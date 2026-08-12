//! Flat package (.pkg / XAR installer) inspection and extraction.
//! `Distribution` and `PackageInfo` are serde types upstream, so they pass
//! through to JSON verbatim.

use std::fs::File;
use std::path::Path;

use apple_codesign::AppleCodesignError;
use apple_flat_package::PkgReader;
use serde::Deserialize;

use crate::error::FfiError;
use crate::path::FfiPath;

fn open_pkg(path: &Path) -> Result<PkgReader<File>, FfiError> {
    let file = File::open(path)?;
    Ok(PkgReader::new(file).map_err(AppleCodesignError::from)?)
}

pub(crate) fn pkg_info(path: &Path) -> Result<Vec<u8>, FfiError> {
    let mut reader = open_pkg(path)?;

    let flavor = format!("{:?}", reader.flavor());
    let distribution = reader.distribution().map_err(AppleCodesignError::from)?;

    let components = reader
        .component_packages()
        .map_err(AppleCodesignError::from)?
        .iter()
        .map(|component| {
            serde_json::json!({
                "package_info": component.package_info(),
                "has_bom": component.bom().is_some(),
            })
        })
        .collect::<Vec<_>>();

    let xar_files = reader
        .into_inner()
        .files()
        .map_err(AppleCodesignError::from)?
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();

    Ok(serde_json::to_vec(&serde_json::json!({
        "flavor": flavor,
        "distribution": distribution,
        "components": components,
        "files": xar_files,
    }))?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtractMemberRequest {
    path: FfiPath,
    /// XAR member path, e.g. "Distribution" or "com.example.pkg/Payload"
    /// (see the `files` list from `pkg_info`).
    member: String,
}

pub(crate) fn pkg_extract_member(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: ExtractMemberRequest = serde_json::from_str(request_json)?;

    let file = File::open(&request.path)?;
    let reader = PkgReader::new(file).map_err(AppleCodesignError::from)?;
    let mut xar = reader.into_inner();

    xar.get_file_data_from_path(&request.member)
        .map_err(AppleCodesignError::from)?
        .ok_or_else(|| {
            FfiError::invalid_argument(format!(
                "member {:?} not found in archive; see pkg_info()[\"files\"]",
                request.member
            ))
        })
}
