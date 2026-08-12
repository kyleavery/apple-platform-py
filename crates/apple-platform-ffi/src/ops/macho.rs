//! Mach-O utilities: synthetic binaries (fixture-free testing on any OS) and
//! universal ("fat") binary assembly.

use apple_codesign::macho_builder::MachOBuilder;
use apple_codesign::{AppleCodesignError, UniversalBinaryBuilder};
use serde::Deserialize;

use crate::error::FfiError;
use crate::path::FfiPath;

// Mach-O file type constants (loader.h).
const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateSyntheticRequest {
    /// "aarch64" (default) or "x86_64".
    #[serde(default)]
    architecture: Option<String>,
    /// "executable" (default) or "dylib".
    #[serde(default)]
    file_type: Option<String>,
}

pub(crate) fn create_synthetic(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: CreateSyntheticRequest = serde_json::from_str(request_json)?;

    let file_type = match request.file_type.as_deref().unwrap_or("executable") {
        "executable" => MH_EXECUTE,
        "dylib" => MH_DYLIB,
        other => {
            return Err(FfiError::invalid_argument(format!(
                "unknown file_type {other:?}; expected \"executable\" or \"dylib\""
            )))
        }
    };

    let builder = match request.architecture.as_deref().unwrap_or("aarch64") {
        "aarch64" => MachOBuilder::new_aarch64(file_type),
        "x86_64" => MachOBuilder::new_x86_64(file_type),
        other => {
            return Err(FfiError::invalid_argument(format!(
                "unknown architecture {other:?}; expected \"aarch64\" or \"x86_64\""
            )))
        }
    };

    Ok(builder.write_macho()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UniversalCreateRequest {
    input_paths: Vec<FfiPath>,
    output_path: FfiPath,
}

pub(crate) fn universal_create(request_json: &str) -> Result<Vec<u8>, FfiError> {
    let request: UniversalCreateRequest = serde_json::from_str(request_json)?;
    if request.input_paths.is_empty() {
        return Err(FfiError::invalid_argument("input_paths must not be empty"));
    }

    let mut builder = UniversalBinaryBuilder::default();
    let mut arch_count = 0usize;
    for path in &request.input_paths {
        let data = std::fs::read(path)?;
        arch_count += builder
            .add_binary(&data)
            .map_err(AppleCodesignError::from)?;
    }

    let mut writer = std::io::BufWriter::new(std::fs::File::create(&request.output_path)?);
    builder
        .write(&mut writer)
        .map_err(AppleCodesignError::from)?;
    std::io::Write::flush(&mut writer)?;

    Ok(serde_json::to_vec(&serde_json::json!({
        "output_path": request.output_path,
        "arch_count": arch_count,
    }))?)
}
