//! FFI plumbing: the buffer type, status codes, panic guards, and pointer
//! validation helpers shared by every `extern "C"` function in `lib.rs`.
//!
//! Wire format for strings: `*_json` arguments are NUL-terminated UTF-8;
//! `path` arguments are NUL-terminated OS-native path bytes (Unix: raw
//! bytes; Windows: UTF-8 or WTF-8) — exactly what Python's `os.fsencode`
//! produces. Paths *inside* JSON payloads are either plain strings (valid
//! UTF-8) or `{"__path_bytes__": "<base64 of OS-native bytes>"}` objects;
//! see `path.rs`.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use crate::error::{self, FfiError};

/// Incremented only on breaking changes to the C ABI (renamed/removed symbols,
/// changed signatures or struct layout). Adding functions is not a break.
pub const APPLE_PLATFORM_ABI_VERSION: u32 = 1;

// Status codes returned by every fallible function. These values are stable:
// they are never renumbered or reused. New codes may be appended; callers must
// treat unknown codes as a generic error.
pub const APPLE_PLATFORM_OK: i32 = 0;
pub const APPLE_PLATFORM_ERR_UNKNOWN: i32 = 1;
pub const APPLE_PLATFORM_ERR_PANIC: i32 = 2;
pub const APPLE_PLATFORM_ERR_INVALID_ARGUMENT: i32 = 3;
pub const APPLE_PLATFORM_ERR_UNSUPPORTED: i32 = 4;
pub const APPLE_PLATFORM_ERR_FEATURE_NOT_ENABLED: i32 = 5;
pub const APPLE_PLATFORM_ERR_INTERACTIVE_INPUT_REQUIRED: i32 = 6;
pub const APPLE_PLATFORM_ERR_IO: i32 = 7;
pub const APPLE_PLATFORM_ERR_CERTIFICATE: i32 = 8;
pub const APPLE_PLATFORM_ERR_PRIVATE_KEY: i32 = 9;
pub const APPLE_PLATFORM_ERR_NO_SIGNING_CERTIFICATE: i32 = 10;
pub const APPLE_PLATFORM_ERR_SIGNING: i32 = 11;
pub const APPLE_PLATFORM_ERR_VERIFICATION: i32 = 12;
pub const APPLE_PLATFORM_ERR_TIMESTAMP: i32 = 13;
pub const APPLE_PLATFORM_ERR_NOTARIZE: i32 = 14;
pub const APPLE_PLATFORM_ERR_STAPLE: i32 = 15;
pub const APPLE_PLATFORM_ERR_MACHO: i32 = 16;
pub const APPLE_PLATFORM_ERR_BUNDLE: i32 = 17;
pub const APPLE_PLATFORM_ERR_DMG: i32 = 18;
pub const APPLE_PLATFORM_ERR_PKG: i32 = 19;
pub const APPLE_PLATFORM_ERR_REMOTE_SIGNING: i32 = 20;

/// A byte payload allocated by this library. Owned by Rust: callers must
/// release it with `apple_platform_buffer_free` exactly once and must not
/// touch `cap`. A `data == NULL, len == 0` buffer is valid and means "empty".
#[repr(C)]
pub struct ApplePlatformBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl ApplePlatformBuffer {
    pub(crate) const fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Move a Vec's allocation into `out`. Empty vecs become the NULL buffer so
/// `data` is never a dangling pointer.
pub(crate) unsafe fn write_buffer(out: *mut ApplePlatformBuffer, mut bytes: Vec<u8>) {
    let buf = &mut *out;
    if bytes.is_empty() {
        *buf = ApplePlatformBuffer::empty();
        return;
    }
    buf.data = bytes.as_mut_ptr();
    buf.len = bytes.len();
    buf.cap = bytes.capacity();
    std::mem::forget(bytes);
}

/// Reclaim and drop a buffer previously produced by `write_buffer`.
pub(crate) unsafe fn free_buffer(buf: *mut ApplePlatformBuffer) {
    if buf.is_null() {
        return;
    }
    let b = &mut *buf;
    if !b.data.is_null() && b.cap != 0 {
        drop(Vec::from_raw_parts(b.data, b.len, b.cap));
    }
    *b = ApplePlatformBuffer::empty();
}

/// Run a status-only operation with panic containment. Clears the thread-local
/// last error first, records any failure there, and returns the status code.
pub(crate) fn guard_status<F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), FfiError>,
{
    error::clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => APPLE_PLATFORM_OK,
        Ok(Err(err)) => error::set_last_error(err),
        Err(panic) => error::set_last_error(FfiError::from_panic(&panic)),
    }
}

/// Run a payload-producing operation with panic containment, writing the
/// payload into `out` on success. `out` always ends up in a valid state.
pub(crate) fn guard_buffer<F>(out: *mut ApplePlatformBuffer, f: F) -> i32
where
    F: FnOnce() -> Result<Vec<u8>, FfiError>,
{
    if out.is_null() {
        return error::set_last_error(FfiError::invalid_argument(
            "output buffer pointer must not be null",
        ));
    }
    unsafe {
        *out = ApplePlatformBuffer::empty();
    }
    error::clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(bytes)) => {
            unsafe { write_buffer(out, bytes) };
            APPLE_PLATFORM_OK
        }
        Ok(Err(err)) => error::set_last_error(err),
        Err(panic) => error::set_last_error(FfiError::from_panic(&panic)),
    }
}

/// Borrow a required NUL-terminated UTF-8 string argument (JSON payloads and
/// other text; path arguments use `required_path`).
pub(crate) unsafe fn required_str<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument(format!(
            "{what} must not be null"
        )));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| FfiError::invalid_argument(format!("{what} must be valid UTF-8")))
}

/// Read a required NUL-terminated OS-native path argument. Unix: the bytes
/// are the path, verbatim, with no validation. Windows: UTF-8, or WTF-8 for
/// paths containing unpaired surrogates.
pub(crate) unsafe fn required_path(ptr: *const c_char, what: &str) -> Result<PathBuf, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument(format!(
            "{what} must not be null"
        )));
    }
    crate::path::from_os_bytes(CStr::from_ptr(ptr).to_bytes())
        .map_err(|e| FfiError::invalid_argument(format!("{what} is not a valid path: {e}")))
}

/// Borrow a required (pointer, length) byte slice argument. A NULL pointer is
/// only valid together with `len == 0`.
pub(crate) unsafe fn required_bytes<'a>(
    data: *const u8,
    len: usize,
    what: &str,
) -> Result<&'a [u8], FfiError> {
    if data.is_null() {
        if len == 0 {
            Ok(&[])
        } else {
            Err(FfiError::invalid_argument(format!(
                "{what} pointer is null but length is {len}"
            )))
        }
    } else {
        Ok(std::slice::from_raw_parts(data, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn required_path_null_names_the_argument() {
        let err = unsafe { required_path(std::ptr::null(), "path") }.unwrap_err();
        assert!(err.message.contains("path must not be null"));
    }

    #[test]
    fn required_path_utf8() {
        let arg = CString::new("/tmp/café").unwrap();
        let path = unsafe { required_path(arg.as_ptr(), "path") }.unwrap();
        assert_eq!(path, PathBuf::from("/tmp/café"));
    }

    #[cfg(unix)]
    #[test]
    fn required_path_passes_raw_bytes_through() {
        use std::os::unix::ffi::OsStrExt;
        let arg = CString::new(&b"/tmp/caf\xe9"[..]).unwrap();
        let path = unsafe { required_path(arg.as_ptr(), "path") }.unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/tmp/caf\xe9");
    }
}
