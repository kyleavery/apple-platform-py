//! The sign operation: a faithful port of upstream's `Sign::run`
//! (`apple-codesign/src/cli/mod.rs`) over a JSON request.
//!
//! The request embeds upstream's `SignConfig` verbatim, so all signer sources
//! and scoped settings — including ones added upstream after this was written
//! — flow through `resolve_certificates` / `load_into_signing_settings` /
//! `load_into_settings` without wrapper changes. Only the non-scoped CLI
//! arguments are mirrored here; keep this file in sync with `Sign::run` when
//! moving the upstream pin (it is on the MAINTAINING.md watch list).

use apple_codesign::cli::certificate_source::SigningCertificates;
use apple_codesign::cli::config::SignConfig;
use apple_codesign::cli::ScopedSigningSettings;
use apple_codesign::{MachOSigner, SigningSettings, UnifiedSigner};
use serde::Deserialize;

use crate::error::FfiError;
use crate::path::FfiPath;

/// Mirrors the default of upstream's private `APPLE_TIMESTAMP_URL`
/// (`cli/mod.rs`); used when the request does not name a timestamp server.
const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";

/// The `apple_platform_sign` / `apple_platform_sign_macho_data` request.
///
/// `config` is upstream's `SignConfig` (signer + per-path scoped settings),
/// deserialized by upstream's own serde impls. The remaining fields mirror
/// `rcodesign sign`'s non-scoped arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignRequest {
    config: SignConfig,
    /// Required when signing a filesystem path; invalid for in-memory data.
    #[serde(default)]
    input_path: Option<FfiPath>,
    /// Default: sign in place.
    #[serde(default)]
    output_path: Option<FfiPath>,
    #[serde(default)]
    team_name: Option<String>,
    /// RFC 3339; default is the current time.
    #[serde(default)]
    signing_time: Option<String>,
    /// Default: Apple's timestamp server. The string "none" disables
    /// timestamp tokens entirely.
    #[serde(default)]
    timestamp_url: Option<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    shallow: bool,
    #[serde(default)]
    for_notarization: bool,
}

/// Upstream prompts on a terminal when credentials are missing
/// (`get_pkcs12_password`, `prompt_smartcard_pin`). Inside a host process that
/// hangs or crashes, so reject such requests up front with a precise error.
fn guard_no_interactive(config: &SignConfig) -> Result<(), FfiError> {
    if let Some(p12) = &config.signer.p12_key {
        if p12.path.is_some() && p12.password.is_none() && p12.password_path.is_none() {
            return Err(FfiError::interactive_input_required(
                "the p12 signer needs `password` or `password_path`: upstream \
                 would prompt for the password on a terminal",
            ));
        }
    }
    if let Some(smartcard) = &config.signer.smartcard_key {
        if smartcard.slot.is_some() && smartcard.pin.is_none() {
            return Err(FfiError::interactive_input_required(
                "the smartcard signer needs `pin`: upstream would prompt for \
                 the PIN on a terminal",
            ));
        }
    }
    Ok(())
}

/// Upstream silently resolves zero certificates when a requested key source
/// is compiled out or wrong-platform (it only logs). Surface that as a hard
/// error instead of producing an unexpectedly ad-hoc signature.
fn guard_features(config: &SignConfig) -> Result<(), FfiError> {
    let signer = &config.signer;

    #[cfg(not(feature = "smartcard"))]
    if signer
        .smartcard_key
        .as_ref()
        .is_some_and(|key| key.slot.is_some())
    {
        return Err(FfiError::feature_not_enabled("smartcard"));
    }

    #[cfg(not(target_os = "macos"))]
    if signer
        .macos_keychain_key
        .as_ref()
        .is_some_and(|key| !key.domains.is_empty() || key.sha256_fingerprint.is_some())
    {
        return Err(FfiError::unsupported(
            "the macos_keychain signer only works on macOS",
        ));
    }

    #[cfg(not(target_os = "windows"))]
    if signer
        .windows_store_key
        .as_ref()
        .is_some_and(|key| !key.stores.is_empty() || key.sha1_fingerprint.is_some())
    {
        return Err(FfiError::unsupported(
            "the windows_store signer only works on Windows",
        ));
    }

    // On Windows the windows_store source is live, and upstream's own
    // validation never runs (it lives in clap): a bad store name panics in
    // `StoreName::try_from(...).expect(...)`, and a `stores`-only request
    // can never match anything (upstream requires a fingerprint to match).
    #[cfg(target_os = "windows")]
    if let Some(key) = &signer.windows_store_key {
        for store in &key.stores {
            apple_codesign::windows::StoreName::try_from(store.as_str())
                .map_err(FfiError::invalid_argument)?;
        }
        if !key.stores.is_empty() && key.sha1_fingerprint.is_none() {
            return Err(FfiError::invalid_argument(
                "the windows_store signer needs `sha1_fingerprint`: upstream \
                 only matches store certificates by fingerprint",
            ));
        }
    }

    Ok(())
}

fn resolve_certificates(request: &SignRequest) -> Result<SigningCertificates, FfiError> {
    guard_no_interactive(&request.config)?;
    guard_features(&request.config)?;
    let certs = request.config.signer.resolve_certificates(true)?;

    // Upstream resolves zero certificates for an unmatched windows_store
    // fingerprint and only logs; without this the request would fall through
    // to an unexpectedly ad-hoc signature.
    #[cfg(target_os = "windows")]
    if certs.is_empty()
        && request
            .config
            .signer
            .windows_store_key
            .as_ref()
            .is_some_and(|key| !key.stores.is_empty() || key.sha1_fingerprint.is_some())
    {
        return Err(FfiError::no_signing_certificate(
            "the windows_store signer matched no certificate",
        ));
    }

    Ok(certs)
}

/// The settings-assembly section of upstream `Sign::run`, verbatim except that
/// CLI arguments come from the request.
fn build_settings<'certs>(
    request: &SignRequest,
    certs: &'certs SigningCertificates,
) -> Result<SigningSettings<'certs>, FfiError> {
    let mut settings = SigningSettings::default();

    certs.load_into_signing_settings(&mut settings)?;

    // Doesn't make sense to set a time-stamp server URL unless we're
    // generating CMS signatures.
    let timestamp_url = request
        .timestamp_url
        .as_deref()
        .unwrap_or(APPLE_TIMESTAMP_URL);
    if settings.signing_key().is_some() && timestamp_url != "none" {
        settings.set_time_stamp_url(timestamp_url)?;
    }

    if let Some(time) = &request.signing_time {
        let time = chrono::DateTime::parse_from_rfc3339(time).map_err(|e| {
            FfiError::invalid_argument(format!("invalid signing_time (want RFC 3339): {e}"))
        })?;
        settings.set_signing_time(time.with_timezone(&chrono::Utc));
    }

    settings.set_team_id_from_signing_certificate();
    if let Some(team_name) = &request.team_name {
        settings.set_team_id(team_name);
    }

    settings.set_shallow(request.shallow);
    settings.set_for_notarization(request.for_notarization);

    for pattern in &request.exclude {
        settings.add_path_exclusion(pattern)?;
    }

    ScopedSigningSettings(request.config.paths.clone()).load_into_settings(&mut settings)?;

    settings.ensure_for_notarization_settings()?;

    Ok(settings)
}

pub(crate) fn sign(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: SignRequest = serde_json::from_str(request_json)?;
    let input_path = request
        .input_path
        .clone()
        .ok_or_else(|| FfiError::invalid_argument("input_path is required"))?;

    let certs = resolve_certificates(&request)?;
    let settings = build_settings(&request, &certs)?;

    let signer = UnifiedSigner::new(settings);

    if let Some(output_path) = &request.output_path {
        signer.sign_path(&input_path, output_path)?;
    } else {
        signer.sign_path_in_place(&input_path)?;
    }

    if let Some(private) = certs.private_key_optional()? {
        private.finish()?;
    }

    let result = serde_json::json!({
        "input_path": input_path,
        "output_path": request.output_path.as_ref().unwrap_or(&input_path),
    });
    Ok(serde_json::to_vec(&result)?)
}

pub(crate) fn sign_macho_data(data: &[u8], request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: SignRequest = serde_json::from_str(request_json)?;
    if request.input_path.is_some() || request.output_path.is_some() {
        return Err(FfiError::invalid_argument(
            "input_path/output_path do not apply when signing in-memory data",
        ));
    }

    let certs = resolve_certificates(&request)?;
    let settings = build_settings(&request, &certs)?;

    let signer = MachOSigner::new(data)?;
    let mut signed = Vec::with_capacity(data.len());
    signer.write_signed_binary(&settings, &mut signed)?;

    if let Some(private) = certs.private_key_optional()? {
        private.finish()?;
    }

    Ok(signed)
}
