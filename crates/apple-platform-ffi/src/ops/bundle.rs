//! Bundle inspection. `DirectoryBundle` has no serde support upstream, so
//! this is a hand-written (low-churn) mirror of its accessors. Path fields
//! read off the filesystem go through `PathValue` — `name`/`nested_bundles`/
//! `icon_files` are upstream `String`s (already lossy) and pass through.

use std::path::Path;

use apple_bundles::DirectoryBundle;
use apple_codesign::AppleCodesignError;

use crate::error::FfiError;
use crate::path::PathValue;

fn open_bundle(path: &Path) -> Result<DirectoryBundle, FfiError> {
    Ok(DirectoryBundle::new_from_path(path).map_err(AppleCodesignError::DirectoryBundle)?)
}

pub(crate) fn bundle_info(path: &Path) -> Result<Vec<u8>, FfiError> {
    let bundle = open_bundle(path)?;
    let map_err = AppleCodesignError::DirectoryBundle;

    let nested = bundle
        .nested_bundles(true)
        .map_err(map_err)?
        .into_iter()
        .map(|(rel_path, _)| rel_path)
        .collect::<Vec<_>>();

    Ok(serde_json::to_vec(&serde_json::json!({
        "root_dir": PathValue(bundle.root_dir()),
        "name": bundle.name(),
        "package_type": format!("{:?}", bundle.package_type()),
        "shallow": bundle.shallow(),
        "identifier": bundle.identifier().map_err(map_err)?,
        "display_name": bundle.display_name().map_err(map_err)?,
        "version": bundle.version().map_err(map_err)?,
        "main_executable": bundle.main_executable().map_err(map_err)?,
        "icon_files": bundle.icon_files().map_err(map_err)?,
        "info_plist_path": PathValue(bundle.info_plist_path()),
        "nested_bundles": nested,
    }))?)
}

pub(crate) fn bundle_files(path: &Path) -> Result<Vec<u8>, FfiError> {
    let bundle = open_bundle(path)?;
    let map_err = AppleCodesignError::DirectoryBundle;

    let mut files = Vec::new();
    for file in bundle.files(true).map_err(map_err)? {
        files.push(serde_json::json!({
            "relative_path": PathValue(file.relative_path()),
            "absolute_path": PathValue(file.absolute_path()),
            "is_info_plist": file.is_info_plist(),
            "is_main_executable": file.is_main_executable().map_err(map_err)?,
            "is_in_code_signature_directory": file.is_in_code_signature_directory(),
            "symlink_target": file.symlink_target().map_err(map_err)?.map(PathValue),
            "size": file.metadata().map(|m| m.len()).ok(),
        }));
    }
    Ok(serde_json::to_vec(&files)?)
}
