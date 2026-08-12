//! Notarization via Apple's notary service. Compiled only with the
//! `notarize` feature; `lib.rs` substitutes FEATURE_NOT_ENABLED bodies
//! otherwise so the symbols always exist.

use std::time::Duration;

use app_store_connect::notary_api::{SubmissionResponse, SubmissionResponseData};
use apple_codesign::{AppleCodesignError, NotarizationUpload, Notarizer};
use serde::Deserialize;

use crate::error::FfiError;
use crate::path::FfiPath;

/// The notary response types are Deserialize-only upstream, so mirror them
/// into JSON by hand. Status strings use upstream's Display: "accepted",
/// "in progress", "invalid", "rejected", "unknown".
fn submission_data_json(data: &SubmissionResponseData) -> serde_json::Value {
    serde_json::json!({
        "id": data.id,
        "type": data.r#type,
        "name": data.attributes.name,
        "created_date": data.attributes.created_date,
        "status": data.attributes.status.to_string(),
    })
}

fn submission_response_json(response: &SubmissionResponse) -> serde_json::Value {
    serde_json::json!({
        "submission_id": response.data.id,
        "response": submission_data_json(&response.data),
        "meta": response.meta,
    })
}

/// Mirrors upstream's `NotaryApi` CLI arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotaryCredentials {
    /// Path to a JSON file containing a unified App Store Connect API key.
    #[serde(default)]
    api_key_path: Option<FfiPath>,
    /// App Store Connect issuer ID; requires `api_key`.
    #[serde(default)]
    api_issuer: Option<String>,
    /// App Store Connect API key ID; requires `api_issuer`.
    #[serde(default)]
    api_key: Option<String>,
}

fn notarizer(credentials: &NotaryCredentials) -> Result<Notarizer, FfiError> {
    if let Some(path) = &credentials.api_key_path {
        Ok(Notarizer::from_api_key(path)?)
    } else if let (Some(issuer), Some(key)) = (&credentials.api_issuer, &credentials.api_key) {
        Ok(Notarizer::from_api_key_id(issuer, key)?)
    } else {
        Err(AppleCodesignError::NotarizeNoAuthCredentials.into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitRequest {
    credentials: NotaryCredentials,
    /// Bundle, DMG, XAR (.pkg), or zip. Mach-O binaries cannot be notarized
    /// directly.
    path: FfiPath,
    /// If set, wait up to this long for Apple to finish processing; if
    /// omitted, return as soon as the upload completes.
    #[serde(default)]
    wait_seconds: Option<u64>,
}

pub(crate) fn submit(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: SubmitRequest = serde_json::from_str(request_json)?;
    let notarizer = notarizer(&request.credentials)?;

    let upload =
        notarizer.notarize_path(&request.path, request.wait_seconds.map(Duration::from_secs))?;

    let payload = match upload {
        NotarizationUpload::UploadId(id) => serde_json::json!({
            "submission_id": id,
            "response": null,
        }),
        NotarizationUpload::NotaryResponse(response) => submission_response_json(&response),
    };
    Ok(serde_json::to_vec(&payload)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WaitRequest {
    credentials: NotaryCredentials,
    submission_id: String,
    /// Default mirrors upstream's `--max-wait-seconds`: 600.
    #[serde(default)]
    wait_seconds: Option<u64>,
}

pub(crate) fn wait(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: WaitRequest = serde_json::from_str(request_json)?;
    let notarizer = notarizer(&request.credentials)?;

    let response = notarizer.wait_on_notarization(
        &request.submission_id,
        Duration::from_secs(request.wait_seconds.unwrap_or(600)),
    )?;
    Ok(serde_json::to_vec(&submission_response_json(&response))?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogRequest {
    credentials: NotaryCredentials,
    submission_id: String,
}

pub(crate) fn log(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: LogRequest = serde_json::from_str(request_json)?;
    let notarizer = notarizer(&request.credentials)?;
    let log = notarizer.fetch_notarization_log(&request.submission_id)?;
    Ok(serde_json::to_vec(&log)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRequest {
    credentials: NotaryCredentials,
}

pub(crate) fn list(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: ListRequest = serde_json::from_str(request_json)?;
    let notarizer = notarizer(&request.credentials)?;
    let response = notarizer.list_submissions()?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "submissions": response
            .data
            .iter()
            .map(submission_data_json)
            .collect::<Vec<_>>(),
        "meta": response.meta,
    }))?)
}
