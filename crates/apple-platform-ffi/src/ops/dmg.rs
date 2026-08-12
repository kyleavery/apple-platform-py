//! DMG inspection, partition extraction, and simple creation.
//!
//! upstream `apple-dmg` panics (`unimplemented!()`) on Adc/Bzlib/Lzfse
//! chunks, so extraction pre-validates chunk types and returns UNSUPPORTED
//! instead; it also `to_str().unwrap()`s every entry name and symlink target
//! under `dmg_create`'s input tree, so `scan_input_tree` rejects non-UTF-8
//! names cleanly up front. `dmg_create` builds a FAT32-backed DMG — a
//! testing/CI utility, not an hdiutil replacement.

use std::path::Path;

use apple_dmg::{ChunkType, DmgReader};
use serde::Deserialize;

use crate::abi::APPLE_PLATFORM_ERR_DMG;
use crate::error::FfiError;
use crate::path::FfiPath;

fn dmg_error(err: anyhow::Error) -> FfiError {
    FfiError::new(APPLE_PLATFORM_ERR_DMG, "Dmg", format!("{err:#}"))
}

pub(crate) fn dmg_info(path: &Path) -> Result<Vec<u8>, FfiError> {
    let reader = DmgReader::open(path).map_err(dmg_error)?;

    let mut partitions = Vec::new();
    for (index, partition) in reader.plist().partitions().iter().enumerate() {
        let table = partition.table().map_err(dmg_error)?;
        let chunk_types = table
            .chunks
            .iter()
            .map(|chunk| match chunk.ty() {
                Some(ty) => format!("{ty:?}"),
                None => format!("unknown(0x{:x})", chunk.r#type),
            })
            .collect::<std::collections::BTreeSet<_>>();
        partitions.push(serde_json::json!({
            "index": index,
            "name": partition.name,
            "chunk_count": table.chunks.len(),
            "chunk_types": chunk_types,
        }));
    }

    let koly = reader.koly();
    let payload = serde_json::json!({
        "version": koly.version,
        "sector_count": koly.sector_count,
        "data_fork_offset": koly.data_fork_offset,
        "data_fork_length": koly.data_fork_length,
        "segment_count": koly.segment_count,
        "has_code_signature": koly.code_signature_size > 0,
        "code_signature_offset": koly.code_signature_offset,
        "code_signature_size": koly.code_signature_size,
        "partitions": partitions,
    });
    Ok(serde_json::to_vec(&payload)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtractPartitionRequest {
    path: FfiPath,
    partition_index: usize,
}

pub(crate) fn dmg_extract_partition(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: ExtractPartitionRequest = serde_json::from_str(request_json)?;
    let mut reader = DmgReader::open(&request.path).map_err(dmg_error)?;

    let partition_count = reader.plist().partitions().len();
    if request.partition_index >= partition_count {
        return Err(FfiError::invalid_argument(format!(
            "partition_index {} out of range (DMG has {} partitions)",
            request.partition_index, partition_count
        )));
    }

    // Pre-validate chunk types: upstream panics on the unimplemented codecs.
    let table = reader
        .partition_table(request.partition_index)
        .map_err(dmg_error)?;
    for chunk in &table.chunks {
        match chunk.ty() {
            Some(ChunkType::Adc) | Some(ChunkType::Bzlib) | Some(ChunkType::Lzfse) => {
                return Err(FfiError::unsupported(format!(
                    "partition uses the {:?} codec, which apple-dmg does not implement",
                    chunk.ty().unwrap()
                )));
            }
            Some(_) => {}
            None => {
                return Err(FfiError::unsupported(format!(
                    "partition contains an unknown chunk type 0x{:x}",
                    chunk.r#type
                )));
            }
        }
    }

    reader
        .partition_data(request.partition_index)
        .map_err(dmg_error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DmgCreateRequest {
    /// Directory whose contents become the volume's root folder.
    input_directory: FfiPath,
    output_path: FfiPath,
    #[serde(default)]
    volume_label: Option<String>,
    /// FAT32 sector count (512-byte sectors); computed from the input size
    /// when omitted.
    #[serde(default)]
    total_sectors: Option<u32>,
}

/// Walk `dir`, returning its total content size while rejecting the names
/// upstream `create_dmg`/`add_dir` would `to_str().unwrap()` on (every entry
/// name and symlink target — a non-UTF-8 one aborts the process there).
fn scan_input_tree(dir: &Path) -> Result<u64, FfiError> {
    let mut total = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_none() {
            return Err(FfiError::invalid_argument(format!(
                "entry {:?} under {} has a non-UTF-8 name; the FAT32 DMG writer \
                 requires UTF-8 names",
                name,
                dir.display()
            )));
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            if target.to_str().is_none() {
                return Err(FfiError::invalid_argument(format!(
                    "symlink {} has a non-UTF-8 target; the FAT32 DMG writer \
                     requires UTF-8 names",
                    entry.path().display()
                )));
            }
            total += entry.metadata()?.len();
        } else if file_type.is_dir() {
            total += scan_input_tree(&entry.path())?;
        } else {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

pub(crate) fn dmg_create(request_json: &str) -> Result<(), FfiError> {
    let request: DmgCreateRequest = serde_json::from_str(request_json)?;

    // Pre-validate what upstream `create_dmg` would unwrap on.
    if !request.input_directory.is_dir() {
        return Err(FfiError::invalid_argument(format!(
            "input_directory {} is not a directory",
            request.input_directory.display()
        )));
    }
    match request.input_directory.file_name().and_then(|n| n.to_str()) {
        Some(_) => {}
        None => {
            return Err(FfiError::invalid_argument(
                "input_directory must have a UTF-8 final path component",
            ))
        }
    }
    let content_bytes = scan_input_tree(&request.input_directory)?;

    let total_sectors = match request.total_sectors {
        Some(sectors) => sectors,
        None => {
            // Content size plus FAT32 overhead headroom: 25% + 4 MiB.
            let padded = content_bytes + content_bytes / 4 + 4 * 1024 * 1024;
            u32::try_from(padded.div_ceil(512)).map_err(|_| {
                FfiError::invalid_argument("input_directory is too large for a FAT32 DMG")
            })?
        }
    };

    apple_dmg::create_dmg(
        &request.input_directory,
        &request.output_path,
        request.volume_label.as_deref().unwrap_or("Untitled"),
        total_sectors,
    )
    .map_err(dmg_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_input_tree_returns_content_size() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"12345").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), b"123").unwrap();
        assert_eq!(scan_input_tree(dir.path()).unwrap(), 8);
    }

    #[cfg(unix)]
    #[test]
    fn scan_input_tree_rejects_non_utf8_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let weird = sub.join(OsStr::from_bytes(b"caf\xe9.txt"));
        // Some filesystems (APFS/HFS+) reject the name at creation; then
        // there is nothing to scan for and the guard is untestable here.
        if std::fs::write(&weird, b"x").is_err() {
            return;
        }
        let err = scan_input_tree(dir.path()).unwrap_err();
        assert!(err.message.contains("non-UTF-8 name"), "{}", err.message);
        assert!(err.message.contains("sub"), "{}", err.message);
    }

    #[cfg(unix)]
    #[test]
    fn scan_input_tree_rejects_non_utf8_symlink_targets() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        // Like non-UTF-8 file names, some filesystems refuse the target.
        if std::os::unix::fs::symlink(OsStr::from_bytes(b"caf\xe9"), &link).is_err() {
            return;
        }
        let err = scan_input_tree(dir.path()).unwrap_err();
        assert!(err.message.contains("non-UTF-8 target"), "{}", err.message);
    }
}
