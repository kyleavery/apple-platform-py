//! C ABI for apple-platform-rs (code signing, notarization, and packaging).
//!
//! This file contains ONLY `extern "C"` definitions; every body is a one-line
//! dispatch through a panic guard into an inner module. Conventions:
//!
//! - Every fallible function returns an `int32_t` status (`APPLE_PLATFORM_OK`
//!   or an `APPLE_PLATFORM_ERR_*` code) and records details retrievable via
//!   `apple_platform_last_error_json` (thread-local, reset by the next call).
//! - Payloads are returned through `ApplePlatformBuffer` out-params. Rust owns
//!   the memory: release each buffer with `apple_platform_buffer_free`.
//! - `*_json` arguments are borrowed NUL-terminated UTF-8; structured data is
//!   JSON whose shape mirrors upstream's serde config types 1:1.
//! - `path` arguments are borrowed NUL-terminated OS-native path bytes (Unix:
//!   raw bytes; Windows: UTF-8/WTF-8) — what Python's `os.fsencode` emits.
//!   Paths inside JSON are plain strings when valid UTF-8, otherwise
//!   `{"__path_bytes__": "<base64 of OS-native bytes>"}` (both directions).

use std::os::raw::c_char;

mod abi;
mod error;
mod logging;
mod ops;
mod path;
mod schema;
mod versions;
// Compiled (and unit-tested) everywhere so the Windows path logic cannot rot
// on the CI targets; only Windows links it outside of tests.
#[cfg_attr(not(windows), allow(dead_code))]
mod wtf8;

pub use abi::*;

use abi::{guard_buffer, guard_status};
#[cfg(not(feature = "notarize"))]
use error::FfiError;

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

/// The ABI version of this library. Callers must check it before use.
#[no_mangle]
pub extern "C" fn apple_platform_abi_version() -> u32 {
    APPLE_PLATFORM_ABI_VERSION
}

/// JSON report of package/ABI versions, enabled features, build target, and
/// upstream provenance (crate versions, git commit/describe of the submodule).
///
/// # Safety
///
/// `out` must point to writable, properly aligned storage for an
/// [`ApplePlatformBuffer`]. Its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_versions(out: *mut ApplePlatformBuffer) -> i32 {
    guard_buffer(out, versions::versions_json)
}

/// JSON map of upstream config type name -> accepted field names, reflected
/// from the compiled-in upstream sources at runtime.
///
/// # Safety
///
/// `out` must point to writable, properly aligned storage for an
/// [`ApplePlatformBuffer`]. Its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_config_schema(out: *mut ApplePlatformBuffer) -> i32 {
    guard_buffer(out, schema::schema_json)
}

/// JSON details of the most recent failure on this thread (or `null` if the
/// last guarded call succeeded). Read it before making further calls: every
/// guarded call, including this one, resets the slot.
///
/// # Safety
///
/// `out` must point to writable, properly aligned storage for an
/// [`ApplePlatformBuffer`]. Its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_last_error_json(out: *mut ApplePlatformBuffer) -> i32 {
    let payload = error::last_error_json();
    guard_buffer(out, move || Ok(payload))
}

/// Release a buffer returned by this library. Safe to call on NULL or on an
/// already-freed (zeroed) buffer.
///
/// # Safety
///
/// `buf` must be null or point to a writable [`ApplePlatformBuffer`]. A
/// nonempty buffer must be one returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_buffer_free(buf: *mut ApplePlatformBuffer) {
    abi::free_buffer(buf);
}

/// Set the capture level for upstream log output: 0=off, 1=error, 2=warn,
/// 3=info, 4=debug, 5=trace. Records accumulate in a bounded ring buffer.
#[no_mangle]
pub extern "C" fn apple_platform_log_set_level(level: i32) -> i32 {
    guard_status(|| logging::set_level(level))
}

/// Drain captured log records as a JSON array (oldest first).
///
/// # Safety
///
/// `out` must point to writable, properly aligned storage for an
/// [`ApplePlatformBuffer`]. Its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_log_drain(out: *mut ApplePlatformBuffer) -> i32 {
    guard_buffer(out, logging::drain_json)
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign the filesystem path named in `request_json` (Mach-O, bundle, DMG, or
/// XAR). The request embeds upstream's `SignConfig` verbatim plus
/// input/output paths and non-scoped options. Returns a small JSON result.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_result_json` must point to writable, properly
/// aligned storage for an [`ApplePlatformBuffer`]; its previous value is
/// overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_sign(
    request_json: *const c_char,
    out_result_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_result_json, || {
        ops::sign::sign(abi::required_str(request_json, "request_json")?)
    })
}

/// Sign an in-memory Mach-O. `data`/`data_len` is the input binary; the signed
/// binary is returned in `out_macho`.
///
/// # Safety
///
/// `data` must be null when `data_len` is zero or point to `data_len` readable
/// bytes for the duration of the call. `request_json` must point to a readable
/// NUL-terminated string. `out_macho` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_sign_macho_data(
    data: *const u8,
    data_len: usize,
    request_json: *const c_char,
    out_macho: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_macho, || {
        ops::sign::sign_macho_data(
            abi::required_bytes(data, data_len, "data")?,
            abi::required_str(request_json, "request_json")?,
        )
    })
}

// ---------------------------------------------------------------------------
// Reading / verification
// ---------------------------------------------------------------------------

/// Classify a filesystem path as upstream sees it (mach-o, bundle, dmg, xar,
/// zip, other). JSON result. `path` is NUL-terminated OS-native path bytes,
/// not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_path_type(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::read::path_type(&abi::required_path(path, "path")?)
    })
}

/// Read all code-signature entities from a signable path. The JSON is
/// upstream's `SignatureReader` entity serialization, passed through
/// verbatim except for path fields, which use the wire path form. `path` is
/// NUL-terminated OS-native path bytes, not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_read_signature(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::read::read_signature(&abi::required_path(path, "path")?)
    })
}

/// Verify a Mach-O's signature, returning a JSON array of problems (empty =
/// no problems found). Upstream documents this check as advisory, not a full
/// Apple-equivalent verifier. `path` is NUL-terminated OS-native path bytes,
/// not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_verify_macho(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::read::verify_macho(&abi::required_path(path, "path")?)
    })
}

// ---------------------------------------------------------------------------
// Notarization / stapling
// ---------------------------------------------------------------------------

/// Submit a path to Apple's notary service. JSON result includes the
/// submission ID. Requires the `notarize` feature.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_notarize_submit(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        let request = abi::required_str(request_json, "request_json")?;
        #[cfg(feature = "notarize")]
        {
            ops::notarize::submit(request)
        }
        #[cfg(not(feature = "notarize"))]
        {
            let _ = request;
            Err(FfiError::feature_not_enabled("notarize"))
        }
    })
}

/// Wait for a notarization submission to reach a terminal state.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_notarize_wait(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        let request = abi::required_str(request_json, "request_json")?;
        #[cfg(feature = "notarize")]
        {
            ops::notarize::wait(request)
        }
        #[cfg(not(feature = "notarize"))]
        {
            let _ = request;
            Err(FfiError::feature_not_enabled("notarize"))
        }
    })
}

/// Fetch the notarization log for a submission ID.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_notarize_log(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        let request = abi::required_str(request_json, "request_json")?;
        #[cfg(feature = "notarize")]
        {
            ops::notarize::log(request)
        }
        #[cfg(not(feature = "notarize"))]
        {
            let _ = request;
            Err(FfiError::feature_not_enabled("notarize"))
        }
    })
}

/// List recent notarization submissions for the configured credentials.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_notarize_list(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        let request = abi::required_str(request_json, "request_json")?;
        #[cfg(feature = "notarize")]
        {
            ops::notarize::list(request)
        }
        #[cfg(not(feature = "notarize"))]
        {
            let _ = request;
            Err(FfiError::feature_not_enabled("notarize"))
        }
    })
}

/// Staple a notarization ticket to a bundle, DMG, or XAR at `path`. `path` is
/// NUL-terminated OS-native path bytes, not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_staple(path: *const c_char) -> i32 {
    guard_status(|| ops::staple::staple(&abi::required_path(path, "path")?))
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// Generate a self-signed code-signing certificate. JSON result carries the
/// PEM certificate and key material.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_certificate_generate_self_signed(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::certs::generate_self_signed(abi::required_str(request_json, "request_json")?)
    })
}

/// Analyze a DER-encoded X.509 certificate for Apple-specific properties
/// (profile, team ID, extensions). JSON result.
///
/// # Safety
///
/// `der` must be null when `der_len` is zero or point to `der_len` readable
/// bytes for the duration of the call. `out_json` must point to writable,
/// properly aligned storage for an [`ApplePlatformBuffer`]; its previous value
/// is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_certificate_analyze(
    der: *const u8,
    der_len: usize,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::certs::analyze(abi::required_bytes(der, der_len, "der")?)
    })
}

/// Parse a PKCS#12 archive, returning certificates (and key presence) as
/// JSON. `options_json` carries the password.
///
/// # Safety
///
/// `data` must be null when `data_len` is zero or point to `data_len` readable
/// bytes for the duration of the call. `options_json` must be null or point to
/// a readable NUL-terminated string. `out_json` must point to writable,
/// properly aligned storage for an [`ApplePlatformBuffer`]; its previous value
/// is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_p12_parse(
    data: *const u8,
    data_len: usize,
    options_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        let options = if options_json.is_null() {
            None
        } else {
            Some(abi::required_str(options_json, "options_json")?)
        };
        ops::certs::p12_parse(abi::required_bytes(data, data_len, "data")?, options)
    })
}

/// Create a PKCS#12 archive from PEM key/certificates described in
/// `request_json`. The raw p12 bytes are returned in `out_p12`.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_p12` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_p12_create(
    request_json: *const c_char,
    out_p12: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_p12, || {
        ops::certs::p12_create(abi::required_str(request_json, "request_json")?)
    })
}

// ---------------------------------------------------------------------------
// Mach-O utilities
// ---------------------------------------------------------------------------

/// Assemble a universal ("fat") binary from single-arch Mach-O files listed
/// in `request_json`. JSON result.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_json` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_macho_universal_create(
    request_json: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::macho::universal_create(abi::required_str(request_json, "request_json")?)
    })
}

/// Build a minimal synthetic Mach-O (for tests and fixtures) and return its
/// bytes in `out_macho`.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_macho` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_macho_create_synthetic(
    request_json: *const c_char,
    out_macho: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_macho, || {
        ops::macho::create_synthetic(abi::required_str(request_json, "request_json")?)
    })
}

// ---------------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------------

/// Describe an on-disk bundle (identifier, type, main executable, Info.plist
/// highlights). JSON result. `path` is NUL-terminated OS-native path bytes,
/// not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_bundle_info(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::bundle::bundle_info(&abi::required_path(path, "path")?)
    })
}

/// List a bundle's files as upstream classifies them. JSON result. `path` is
/// NUL-terminated OS-native path bytes, not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_bundle_files(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::bundle::bundle_files(&abi::required_path(path, "path")?)
    })
}

// ---------------------------------------------------------------------------
// DMG
// ---------------------------------------------------------------------------

/// Describe a DMG (partitions, checksums, signature presence). JSON result.
/// `path` is NUL-terminated OS-native path bytes, not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_dmg_info(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::dmg::dmg_info(&abi::required_path(path, "path")?)
    })
}

/// Extract a partition's raw data from a DMG per `request_json`.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_data` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_dmg_extract_partition(
    request_json: *const c_char,
    out_data: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_data, || {
        ops::dmg::dmg_extract_partition(abi::required_str(request_json, "request_json")?)
    })
}

/// Create a simple DMG from a directory per `request_json`. Not an hdiutil
/// replacement; see package documentation for limitations.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_dmg_create(request_json: *const c_char) -> i32 {
    guard_status(|| ops::dmg::dmg_create(abi::required_str(request_json, "request_json")?))
}

// ---------------------------------------------------------------------------
// Flat packages (.pkg)
// ---------------------------------------------------------------------------

/// Describe a flat package installer: distribution info, component packages.
/// JSON result (upstream's serde types, verbatim). `path` is NUL-terminated
/// OS-native path bytes, not necessarily UTF-8.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the duration of
/// the call. `out_json` must point to writable, properly aligned storage for
/// an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_pkg_info(
    path: *const c_char,
    out_json: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_json, || {
        ops::pkg::pkg_info(&abi::required_path(path, "path")?)
    })
}

/// Extract a member file from a flat package per `request_json`.
///
/// # Safety
///
/// `request_json` must point to a readable NUL-terminated string for the
/// duration of the call. `out_data` must point to writable, properly aligned
/// storage for an [`ApplePlatformBuffer`]; its previous value is overwritten.
#[no_mangle]
pub unsafe extern "C" fn apple_platform_pkg_extract_member(
    request_json: *const c_char,
    out_data: *mut ApplePlatformBuffer,
) -> i32 {
    guard_buffer(out_data, || {
        ops::pkg::pkg_extract_member(abi::required_str(request_json, "request_json")?)
    })
}
