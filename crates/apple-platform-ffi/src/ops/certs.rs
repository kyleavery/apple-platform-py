//! Certificate operations: self-signed generation (mirroring upstream's
//! `generate-certificate-signing-request`/`generate-self-signed-certificate`
//! commands), analysis (JSON twin of upstream's `print_certificate_info`),
//! and PKCS#12 parse/create.

use std::str::FromStr;

use apple_codesign::cryptography::parse_pfx_data;
use apple_codesign::{
    create_self_signed_code_signing_certificate, AppleCertificate, CertificateProfile,
};
use serde::Deserialize;
use x509_certificate::{CapturedX509Certificate, EcdsaCurve, KeyAlgorithm};

use crate::abi::APPLE_PLATFORM_ERR_CERTIFICATE;
use crate::error::FfiError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerateSelfSignedRequest {
    person_name: String,
    /// "rsa" (default), "ecdsa", or "ed25519".
    #[serde(default)]
    algorithm: Option<String>,
    /// A CertificateProfile name, e.g. "apple-development" (default).
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    validity_days: Option<i64>,
}

pub(crate) fn generate_self_signed(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: GenerateSelfSignedRequest = serde_json::from_str(request_json)?;

    let algorithm = match request.algorithm.as_deref().unwrap_or("rsa") {
        "rsa" => KeyAlgorithm::Rsa,
        "ecdsa" => KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1),
        "ed25519" => KeyAlgorithm::Ed25519,
        other => {
            return Err(FfiError::invalid_argument(format!(
                "unknown algorithm {other:?}; expected \"rsa\", \"ecdsa\", or \"ed25519\""
            )))
        }
    };
    let profile =
        CertificateProfile::from_str(request.profile.as_deref().unwrap_or("apple-development"))?;

    let (cert, key_pair) = create_self_signed_code_signing_certificate(
        algorithm,
        profile,
        request.team_id.as_deref().unwrap_or("unset"),
        &request.person_name,
        request.country_name.as_deref().unwrap_or("XX"),
        chrono::Duration::days(request.validity_days.unwrap_or(365)),
    )?;

    let certificate_pem = cert.encode_pem();
    let private_key_pem = pem::encode(&pem::Pem::new(
        "PRIVATE KEY",
        key_pair.to_pkcs8_one_asymmetric_key_der().to_vec(),
    ));

    Ok(serde_json::to_vec(&serde_json::json!({
        "certificate_pem": certificate_pem,
        "private_key_pem": private_key_pem,
        "info": certificate_info(&cert)?,
    }))?)
}

/// JSON twin of upstream's `print_certificate_info`.
fn certificate_info(cert: &CapturedX509Certificate) -> Result<serde_json::Value, FfiError> {
    Ok(serde_json::json!({
        "subject_common_name": cert.subject_common_name(),
        "issuer_common_name": cert.issuer_common_name(),
        "subject_is_issuer": cert.subject_is_issuer(),
        "team_id": cert.apple_team_id(),
        "sha1_fingerprint": hex::encode(cert.sha1_fingerprint()?),
        "sha256_fingerprint": hex::encode(cert.sha256_fingerprint()?),
        "not_valid_before": cert.validity_not_before().to_rfc3339(),
        "not_valid_after": cert.validity_not_after().to_rfc3339(),
        "key_algorithm": cert.key_algorithm().map(|a| a.to_string()),
        "signature_algorithm": cert.signature_algorithm().map(|a| a.to_string()),
        "signed_by_apple": cert.chains_to_apple_root_ca(),
        "guessed_profile": cert.apple_guess_profile().map(|p| format!("{p:?}")),
        "is_apple_root_ca": cert.is_apple_root_ca(),
        "is_apple_intermediate_ca": cert.is_apple_intermediate_ca(),
        "apple_extended_key_usage_purposes": cert
            .apple_extended_key_usage_purposes()
            .into_iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>(),
        "apple_code_signing_extensions": cert
            .apple_code_signing_extensions()
            .into_iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>(),
    }))
}

pub(crate) fn analyze(der: &[u8]) -> Result<Vec<u8>, FfiError> {
    let cert = CapturedX509Certificate::from_der(der.to_vec())
        .map_err(apple_codesign::AppleCodesignError::from)?;
    let mut info = certificate_info(&cert)?;
    info["certificate_pem"] = serde_json::Value::String(cert.encode_pem());
    Ok(serde_json::to_vec(&info)?)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct P12ParseOptions {
    #[serde(default)]
    password: Option<String>,
}

pub(crate) fn p12_parse(data: &[u8], options_json: Option<&str>) -> Result<Vec<u8>, FfiError> {
    let options: P12ParseOptions = match options_json {
        Some(json) => serde_json::from_str(json)?,
        None => P12ParseOptions::default(),
    };

    let (cert, _key) = parse_pfx_data(data, options.password.as_deref().unwrap_or(""))?;

    let mut info = certificate_info(&cert)?;
    info["certificate_pem"] = serde_json::Value::String(cert.encode_pem());
    info["has_private_key"] = serde_json::Value::Bool(true);
    Ok(serde_json::to_vec(&info)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct P12CreateRequest {
    /// PEM `CERTIFICATE` block.
    certificate_pem: String,
    /// PEM `PRIVATE KEY` (PKCS#8) block.
    private_key_pem: String,
    password: String,
    /// Friendly name recorded in the archive; upstream uses "code-signing".
    #[serde(default)]
    name: Option<String>,
}

pub(crate) fn p12_create(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: P12CreateRequest = serde_json::from_str(request_json)?;

    let cert_der = pem_contents(&request.certificate_pem, "CERTIFICATE")?;
    let key_der = pem_contents(&request.private_key_pem, "PRIVATE KEY")?;

    let pfx = p12::PFX::new(
        &cert_der,
        &key_der,
        None,
        &request.password,
        request.name.as_deref().unwrap_or("code-signing"),
    )
    .ok_or_else(|| {
        FfiError::new(
            APPLE_PLATFORM_ERR_CERTIFICATE,
            "Certificate",
            "failed to create PFX structure from the provided key/certificate",
        )
    })?;

    Ok(pfx.to_der())
}

fn pem_contents(pem_text: &str, expected_tag: &str) -> Result<Vec<u8>, FfiError> {
    for block in pem::parse_many(pem_text)
        .map_err(|e| FfiError::invalid_argument(format!("invalid PEM: {e}")))?
    {
        if block.tag() == expected_tag {
            return Ok(block.contents().to_vec());
        }
    }
    Err(FfiError::invalid_argument(format!(
        "no `{expected_tag}` PEM block found"
    )))
}
