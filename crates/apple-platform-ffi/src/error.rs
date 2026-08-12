//! Error classification and the thread-local "last error" slot.
//!
//! Upstream's `AppleCodesignError` has 100+ variants and grows regularly. We
//! map a curated subset onto the small, stable status-code set in `abi.rs`;
//! everything else deliberately falls through to `UNKNOWN` with its full
//! Display message preserved, so upstream additions never break the build.

use std::any::Any;
use std::cell::RefCell;
use std::error::Error as StdError;

use apple_codesign::AppleCodesignError;
use serde::Serialize;

use crate::abi::*;

/// The error payload surfaced to callers via `apple_platform_last_error_json`.
#[derive(Debug, Serialize)]
pub(crate) struct FfiError {
    pub code: i32,
    pub kind: String,
    pub message: String,
    /// Messages from the `std::error::Error::source()` chain, outermost first.
    pub source: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl FfiError {
    pub(crate) fn new(code: i32, kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            kind: kind.into(),
            message: message.into(),
            source: Vec::new(),
            details: None,
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(
            APPLE_PLATFORM_ERR_INVALID_ARGUMENT,
            "InvalidArgument",
            message,
        )
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::new(APPLE_PLATFORM_ERR_UNSUPPORTED, "Unsupported", message)
    }

    #[allow(dead_code)] // used once notarize/smartcard stubs land
    pub(crate) fn feature_not_enabled(feature: &str) -> Self {
        Self::new(
            APPLE_PLATFORM_ERR_FEATURE_NOT_ENABLED,
            "FeatureNotEnabled",
            format!("this build of the library was compiled without the `{feature}` feature"),
        )
    }

    #[allow(dead_code)] // used by the Windows-only certificate guard in ops/sign.rs
    pub(crate) fn no_signing_certificate(message: impl Into<String>) -> Self {
        Self::new(
            APPLE_PLATFORM_ERR_NO_SIGNING_CERTIFICATE,
            "NoSigningCertificate",
            message,
        )
    }

    #[allow(dead_code)] // used by the interactive-prompt guard in ops/sign.rs
    pub(crate) fn interactive_input_required(message: impl Into<String>) -> Self {
        Self::new(
            APPLE_PLATFORM_ERR_INTERACTIVE_INPUT_REQUIRED,
            "InteractiveInputRequired",
            message,
        )
    }

    pub(crate) fn from_panic(panic: &(dyn Any + Send)) -> Self {
        let message = if let Some(s) = panic.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "panic payload of unknown type".to_string()
        };
        Self::new(APPLE_PLATFORM_ERR_PANIC, "Panic", message)
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(err: serde_json::Error) -> Self {
        Self::invalid_argument(err.to_string())
    }
}

impl From<std::io::Error> for FfiError {
    fn from(err: std::io::Error) -> Self {
        Self::new(APPLE_PLATFORM_ERR_IO, "Io", err.to_string())
    }
}

impl From<AppleCodesignError> for FfiError {
    fn from(err: AppleCodesignError) -> Self {
        let (code, kind) = classify(&err);
        let mut source = Vec::new();
        let mut cursor: Option<&dyn StdError> = err.source();
        while let Some(inner) = cursor {
            source.push(inner.to_string());
            cursor = inner.source();
        }
        Self {
            code,
            kind: kind.to_string(),
            message: err.to_string(),
            source,
            details: None,
        }
    }
}

/// Map an upstream error onto (status code, stable kind label).
pub(crate) fn classify(err: &AppleCodesignError) -> (i32, &'static str) {
    use AppleCodesignError as E;

    match err {
        E::Io(_) => (APPLE_PLATFORM_ERR_IO, "Io"),
        E::CliDialoguer(_) => (
            APPLE_PLATFORM_ERR_INTERACTIVE_INPUT_REQUIRED,
            "InteractiveInputRequired",
        ),
        E::SerdeJson(_) => (APPLE_PLATFORM_ERR_INVALID_ARGUMENT, "SerdeJson"),
        E::Unimplemented(_) => (APPLE_PLATFORM_ERR_UNSUPPORTED, "Unimplemented"),
        E::NoSigningCertificate => (
            APPLE_PLATFORM_ERR_NO_SIGNING_CERTIFICATE,
            "NoSigningCertificate",
        ),
        E::PfxBadPassword | E::PfxParseError(_) => (APPLE_PLATFORM_ERR_PRIVATE_KEY, "Pfx"),
        E::SmartcardNoCertificate(_) | E::SmartcardFailedAuthentication => {
            (APPLE_PLATFORM_ERR_PRIVATE_KEY, "Smartcard")
        }
        E::KeychainError(_) | E::CertificateNotFound(_) | E::WindowsStoreError(_) => {
            (APPLE_PLATFORM_ERR_CERTIFICATE, "CertificateStore")
        }
        E::X509(_)
        | E::CertificateGeneric(_)
        | E::CertificateDecode(_)
        | E::CertificatePem(_)
        | E::X509Parse(_)
        | E::CertificateUnsupportedKeyAlgorithm(_)
        | E::CertificateRing(_)
        | E::CertificateCharset(_)
        | E::CertificateBuildError(_)
        | E::UnknownCertificateProfile(_)
        | E::OidIsntCertificateAuthority
        | E::OidIsntExtendedKeyUsage
        | E::OidIsntCodeSigningExtension => (APPLE_PLATFORM_ERR_CERTIFICATE, "Certificate"),
        E::VerificationProblems => (APPLE_PLATFORM_ERR_VERIFICATION, "VerificationProblems"),
        E::NoIdentifier
        | E::PathIdentifier(_)
        | E::SignatureDataTooLarge
        | E::SignatureBuilder(_)
        | E::ForNotarizationInvalidSettings
        | E::ParseSettingsScope(_)
        | E::UnknownPolicy(_)
        | E::PolicyFormulationError(_) => (APPLE_PLATFORM_ERR_SIGNING, "Signing"),
        E::NotarizeUnsupportedPath(_)
        | E::NotarizeNoAuthCredentials
        | E::NotarizeWaitLimitReached
        | E::NotarizeServerError
        | E::NotarizeRejected(..)
        | E::NotarizeIncomplete
        | E::NotarizeInvalid
        | E::NotarizationRecordNotInResponse(_)
        | E::NotarizationRecordNoSignedTicket
        | E::NotarizationRecordSignedTicketNotBytes(_)
        | E::NotarizationLookupFailure(..)
        | E::NotarizationRecordDecodeFailure(_)
        | E::AppStoreConnectApiKey(_)
        | E::AppStoreConnectApiKeyNotFound => (APPLE_PLATFORM_ERR_NOTARIZE, "Notarize"),
        E::StapleUnsupportedBundleType(_)
        | E::StapleMalformedXar
        | E::StapleMainExecutableNotFound
        | E::StapleUnsupportedPath(_) => (APPLE_PLATFORM_ERR_STAPLE, "Staple"),
        E::Goblin(_)
        | E::InvalidBinary(_)
        | E::InvalidMachOIndex(_)
        | E::BinaryNoCodeSignature
        | E::BinaryNoCodeDirectory
        | E::MissingLinkedit
        | E::BadMagic(_)
        | E::LinkeditNotLast
        | E::DataAfterSignature
        | E::LoadCommandNoRoom
        | E::MachOWrite(_)
        | E::UniversalMachO(_) => (APPLE_PLATFORM_ERR_MACHO, "MachO"),
        E::DirectoryBundle(_)
        | E::BundleUnknown(_)
        | E::BundleNoIdentifier(_)
        | E::BundleNoMainExecutable(_)
        | E::BundleUnexpectedResourceRuleResult
        | E::BundleUnknownAppPlatform => (APPLE_PLATFORM_ERR_BUNDLE, "Bundle"),
        E::DmgBadMagic | E::DmgNotarizeNoSignature | E::DmgStapleNoSignature => {
            (APPLE_PLATFORM_ERR_DMG, "Dmg")
        }
        E::Xar(_) | E::FlatPackage(_) | E::XarNoAdhoc => (APPLE_PLATFORM_ERR_PKG, "FlatPackage"),
        E::RemoteSign(_) => (APPLE_PLATFORM_ERR_REMOTE_SIGNING, "RemoteSign"),
        // LOAD-BEARING: never make this match exhaustive. Upstream adds error
        // variants regularly; they must degrade to UNKNOWN (with the Display
        // message preserved by the caller) instead of breaking compilation.
        _ => (APPLE_PLATFORM_ERR_UNKNOWN, "AppleCodesign"),
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<FfiError>> = const { RefCell::new(None) };
}

pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().take());
}

/// Record `err` in the thread-local slot and return its status code.
pub(crate) fn set_last_error(err: FfiError) -> i32 {
    let code = err.code;
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
    code
}

/// JSON for the most recent error on this thread: an `FfiError` object, or
/// `null` when the last guarded call succeeded.
pub(crate) fn last_error_json() -> Vec<u8> {
    LAST_ERROR.with(|slot| serde_json::to_vec(&*slot.borrow()).unwrap_or_else(|_| b"null".to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_io_and_preserves_unknown() {
        let io =
            AppleCodesignError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert_eq!(classify(&io).0, APPLE_PLATFORM_ERR_IO);

        // A variant we intentionally do not map must hit the catch-all.
        let odd = AppleCodesignError::MissingText;
        assert_eq!(classify(&odd).0, APPLE_PLATFORM_ERR_UNKNOWN);

        let ffi: FfiError = odd.into();
        assert!(!ffi.message.is_empty());
    }

    #[test]
    fn last_error_roundtrip() {
        clear_last_error();
        assert_eq!(last_error_json(), b"null");

        let code = set_last_error(FfiError::invalid_argument("bad json"));
        assert_eq!(code, APPLE_PLATFORM_ERR_INVALID_ARGUMENT);
        let parsed: serde_json::Value = serde_json::from_slice(&last_error_json()).unwrap();
        assert_eq!(parsed["code"], APPLE_PLATFORM_ERR_INVALID_ARGUMENT);
        assert_eq!(parsed["message"], "bad json");
    }
}
