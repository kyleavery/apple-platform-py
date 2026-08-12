//! Runtime reflection of upstream's JSON config schema.
//!
//! Every config type upstream exposes uses `#[serde(deny_unknown_fields)]`, so
//! feeding serde a bogus key makes it enumerate the valid field names in the
//! error message. We parse those names back out. This means the schema
//! reported by `apple_platform_config_schema` always matches the upstream
//! sources this library was compiled against — and the committed snapshot in
//! `tests/repo/data/config_schema.json` turns any upstream field change into a
//! failing diff.

use serde::de::DeserializeOwned;

use apple_codesign::cli::certificate_source::{
    CertificateDerSigningKey, CertificateSource, MacosKeychainSigningKey, P12SigningKey,
    PemSigningKey, RemoteSigningKey, SmartcardSigningKey, WindowsStoreSigningKey,
};
use apple_codesign::cli::config::SignConfig;
use apple_codesign::cli::ScopedSigningSettingsValues;

use crate::error::FfiError;

const PROBE_KEY: &str = "__apple_platform_schema_probe__";

/// Field names serde reports for `T` when rejecting an unknown key.
fn probe_fields<T: DeserializeOwned>() -> Vec<String> {
    let probe = serde_json::json!({ PROBE_KEY: null });
    match serde_json::from_value::<T>(probe) {
        Err(err) => parse_expected_fields(&err.to_string()),
        // A type that accepts unknown fields has nothing to enumerate. Return
        // empty rather than panic; the snapshot test will surface the change.
        Ok(_) => Vec::new(),
    }
}

/// Extract backtick-quoted field names from serde messages like
/// "unknown field `x`, expected one of `a`, `b`" or "expected `a` or `b`".
fn parse_expected_fields(message: &str) -> Vec<String> {
    let Some((_, tail)) = message.split_once("expected") else {
        return Vec::new();
    };
    tail.split('`')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect()
}

pub(crate) fn schema_json() -> Result<Vec<u8>, FfiError> {
    let schema = serde_json::json!({
        "SignConfig": probe_fields::<SignConfig>(),
        "CertificateSource": probe_fields::<CertificateSource>(),
        "ScopedSigningSettingsValues": probe_fields::<ScopedSigningSettingsValues>(),
        "SmartcardSigningKey": probe_fields::<SmartcardSigningKey>(),
        "MacosKeychainSigningKey": probe_fields::<MacosKeychainSigningKey>(),
        "WindowsStoreSigningKey": probe_fields::<WindowsStoreSigningKey>(),
        "P12SigningKey": probe_fields::<P12SigningKey>(),
        "PemSigningKey": probe_fields::<PemSigningKey>(),
        "RemoteSigningKey": probe_fields::<RemoteSigningKey>(),
        "CertificateDerSigningKey": probe_fields::<CertificateDerSigningKey>(),
    });
    Ok(serde_json::to_vec_pretty(&schema)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plural_and_singular_expected_lists() {
        assert_eq!(
            parse_expected_fields("unknown field `x`, expected one of `a`, `b`, `c`"),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            parse_expected_fields("unknown field `x`, expected `only`"),
            vec!["only"]
        );
        assert!(parse_expected_fields("no marker here").is_empty());
    }

    #[test]
    fn schema_covers_known_upstream_fields() {
        let schema: serde_json::Value = serde_json::from_slice(&schema_json().unwrap()).unwrap();

        let names = |key: &str| -> Vec<String> {
            schema[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        };

        // Spot-check anchors that exist at the 0.29.0 pin. If upstream renames
        // any of these the snapshot test fails first; this guards the probe
        // mechanism itself.
        assert!(names("SignConfig").contains(&"signer".to_string()));
        assert!(names("CertificateSource").contains(&"p12".to_string()));
        assert!(names("CertificateSource").contains(&"pem".to_string()));
        assert!(names("P12SigningKey").contains(&"path".to_string()));
        assert!(!names("ScopedSigningSettingsValues").is_empty());
    }
}
