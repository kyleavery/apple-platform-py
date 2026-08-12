//! Read/verify operations. `read_signature` passes upstream's
//! `SignatureReader` entity serialization through verbatim — its JSON shape
//! tracks upstream automatically and is intentionally not modeled here —
//! except for the two path fields, which are spliced into wire form by
//! `entity_json` (serde refuses to serialize a non-UTF-8 `PathBuf`, and it
//! fails the whole value, so there is nothing to post-process).

use std::path::Path;

use apple_codesign::{FileEntity, PathType, SignatureReader};

use crate::abi::APPLE_PLATFORM_ERR_UNKNOWN;
use crate::error::FfiError;
use crate::path::PathValue;

pub(crate) fn path_type(path: &Path) -> Result<Vec<u8>, FfiError> {
    let kind = match PathType::from_path(path)? {
        PathType::MachO => "macho",
        PathType::Dmg => "dmg",
        PathType::Bundle => "bundle",
        PathType::Xar => "xar",
        PathType::Zip => "zip",
        PathType::Other => "other",
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "path": PathValue(path),
        "path_type": kind,
    }))?)
}

fn drift(message: &str) -> FfiError {
    FfiError::new(APPLE_PLATFORM_ERR_UNKNOWN, "UpstreamDrift", message)
}

/// Serialize a `FileEntity` with its paths blanked, then splice the
/// wire-form paths back in. The `insert` return value is checked so an
/// upstream field rename fails loudly here instead of silently emitting a
/// wrong shape. (On the MAINTAINING.md hand-mirrored list.)
fn entity_json(mut entity: FileEntity) -> Result<serde_json::Value, FfiError> {
    let path = std::mem::take(&mut entity.path);
    let symlink_target = entity.symlink_target.take();

    let mut value = serde_json::to_value(&entity)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| drift("FileEntity no longer serializes as a JSON object"))?;
    if object
        .insert("path".into(), serde_json::to_value(PathValue(&path))?)
        .is_none()
    {
        return Err(drift("FileEntity no longer has a `path` field"));
    }
    // `symlink_target` is skip_serializing_if-None upstream, so re-insert
    // only when set — preserving the verbatim shape exactly.
    if let Some(target) = symlink_target {
        object.insert(
            "symlink_target".into(),
            serde_json::to_value(PathValue(target))?,
        );
    }
    Ok(value)
}

pub(crate) fn read_signature(path: &Path) -> Result<Vec<u8>, FfiError> {
    let reader = SignatureReader::from_path(path)?;
    let entities = reader
        .entities()?
        .into_iter()
        .map(entity_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(serde_json::to_vec(&entities)?)
}

pub(crate) fn verify_macho(path: &Path) -> Result<Vec<u8>, FfiError> {
    let data = std::fs::read(path)?;
    let problems = apple_codesign::verify_macho_data(&data);
    let report = problems
        .iter()
        .map(|problem| {
            serde_json::json!({
                "path": problem.context.path.as_deref().map(PathValue),
                "fat_index": problem.context.fat_index,
                "description": problem.to_string(),
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_vec(&report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apple_codesign::SignatureEntity;
    use std::path::PathBuf;

    fn entity(path: PathBuf, symlink_target: Option<PathBuf>) -> FileEntity {
        FileEntity {
            path,
            file_size: Some(4),
            file_sha256: None,
            symlink_target,
            sub_path: None,
            entity: SignatureEntity::Other,
        }
    }

    #[test]
    fn entity_json_utf8_paths_stay_strings() {
        let value = entity_json(entity(PathBuf::from("a/b"), Some(PathBuf::from("c")))).unwrap();
        assert_eq!(value["path"], "a/b");
        assert_eq!(value["symlink_target"], "c");
        assert_eq!(value["file_size"], 4);
    }

    #[test]
    fn entity_json_omits_unset_symlink_target() {
        let value = entity_json(entity(PathBuf::from("a"), None)).unwrap();
        assert!(!value.as_object().unwrap().contains_key("symlink_target"));
    }

    #[cfg(unix)]
    #[test]
    fn entity_json_splices_non_utf8_paths() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let weird = PathBuf::from(OsStr::from_bytes(b"caf\xe9"));
        let value = entity_json(entity(weird.clone(), Some(weird))).unwrap();
        assert_eq!(value["path"]["__path_bytes__"], "Y2Fm6Q==");
        assert_eq!(value["symlink_target"]["__path_bytes__"], "Y2Fm6Q==");
    }
}
