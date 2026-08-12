//! Path values at the JSON boundary.
//!
//! The wire form of a path is either a JSON string (used iff the path's
//! OS-native bytes are valid UTF-8 — the universal case) or a tagged object
//! `{"__path_bytes__": "<base64>"}` carrying the OS-native bytes: raw bytes
//! on Unix, WTF-8 on Windows — exactly what Python's `os.fsencode` produces
//! on each platform. The marker key follows the same double-underscore
//! convention as `schema.rs`'s probe key.
//!
//! Serialization is infallible by construction. That matters: serde's own
//! `Path` serializer *errors* on non-UTF-8, and the `json!` macro unwraps
//! serialization errors — so a stray `PathBuf` in a response payload turns
//! one oddly-named file into a library panic. Every path in a response must
//! go through [`PathValue`] or [`FfiPath`].
//!
//! [`FfiPath`]'s `Deserialize` is only usable with self-describing formats
//! (it dispatches through `deserialize_any`); we only ever feed it
//! serde_json.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

pub(crate) const PATH_BYTES_KEY: &str = "__path_bytes__";

#[cfg(not(any(unix, windows)))]
compile_error!("apple-platform-ffi supports unix and windows targets only");

#[cfg(unix)]
fn os_bytes(s: &OsStr) -> Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(s.as_bytes())
}

#[cfg(windows)]
fn os_bytes(s: &OsStr) -> Cow<'_, [u8]> {
    use std::os::windows::ffi::OsStrExt;
    Cow::Owned(crate::wtf8::encode(s.encode_wide()))
}

/// OS-native path bytes -> `PathBuf`. Infallible on Unix; on Windows the
/// bytes must be UTF-8 or WTF-8.
#[cfg(unix)]
pub(crate) fn from_os_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(OsStr::from_bytes(bytes)))
}

#[cfg(windows)]
pub(crate) fn from_os_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(PathBuf::from(text));
    }
    let units = crate::wtf8::decode(bytes)?;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&units)))
}

/// Serialize a path in wire form. Never fails, which is precisely what makes
/// the `json!` macro (which unwraps `to_value` errors) safe on paths.
fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    match path.to_str() {
        Some(text) => serializer.serialize_str(text),
        None => {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(PATH_BYTES_KEY, &BASE64.encode(os_bytes(path.as_os_str())))?;
            map.end()
        }
    }
}

/// A path in a `json!` (or other Serialize) position: `PathValue(&path)`,
/// `PathValue(pathbuf)`, or `option.map(PathValue)` for nullable fields.
pub(crate) struct PathValue<P>(pub(crate) P);

impl<P: AsRef<Path>> Serialize for PathValue<P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_path(self.0.as_ref(), serializer)
    }
}

/// A `PathBuf` request/response field that speaks the wire form in both
/// directions. Derefs to `Path` so upstream `&Path` / `impl AsRef<Path>`
/// APIs take it directly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FfiPath(pub(crate) PathBuf);

impl std::ops::Deref for FfiPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for FfiPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Serialize for FfiPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_path(&self.0, serializer)
    }
}

// Hand-written visitor rather than #[serde(untagged)]: untagged enums buffer
// the input through an internal Content type, degrade error messages to
// "data did not match any variant", and are the construct with known bad
// interactions with deny_unknown_fields/flatten on containing structs.
impl<'de> Deserialize<'de> for FfiPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(FfiPathVisitor)
    }
}

struct FfiPathVisitor;

impl<'de> Visitor<'de> for FfiPathVisitor {
    type Value = FfiPath;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a path string, or an object {{\"{PATH_BYTES_KEY}\": \
             \"<base64 of the path's OS-native bytes>\"}}"
        )
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<FfiPath, E> {
        Ok(FfiPath(PathBuf::from(v)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FfiPath, A::Error> {
        let exactly_one = || {
            de::Error::custom(format!(
                "path object must have exactly one key, `{PATH_BYTES_KEY}`"
            ))
        };
        let key: String = map.next_key()?.ok_or_else(exactly_one)?;
        if key != PATH_BYTES_KEY {
            return Err(de::Error::custom(format!(
                "unknown key `{key}` in path object; expected `{PATH_BYTES_KEY}`"
            )));
        }
        let encoded: String = map.next_value()?;
        if map.next_key::<IgnoredAny>()?.is_some() {
            return Err(exactly_one());
        }
        let bytes = BASE64.decode(encoded.as_bytes()).map_err(|e| {
            de::Error::custom(format!("`{PATH_BYTES_KEY}` is not valid base64: {e}"))
        })?;
        if bytes.contains(&0) {
            return Err(de::Error::custom("path bytes must not contain NUL"));
        }
        from_os_bytes(&bytes)
            .map(FfiPath)
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(value: impl Serialize) -> String {
        serde_json::to_string(&value).unwrap()
    }

    #[test]
    fn serialize_utf8_as_plain_string() {
        assert_eq!(to_json(PathValue(Path::new("/tmp/x"))), r#""/tmp/x""#);
        assert_eq!(to_json(FfiPath(PathBuf::from("café"))), r#""café""#);
        assert_eq!(to_json(PathValue(Path::new(""))), r#""""#);
    }

    #[cfg(unix)]
    #[test]
    fn serialize_non_utf8_as_tagged_object() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"caf\xe9"));
        assert_eq!(to_json(PathValue(path)), r#"{"__path_bytes__":"Y2Fm6Q=="}"#);
        assert_eq!(
            to_json(Some(PathValue(path))),
            r#"{"__path_bytes__":"Y2Fm6Q=="}"#
        );
        assert_eq!(to_json(None::<PathValue<&Path>>), "null");
    }

    #[test]
    fn deserialize_string() {
        let path: FfiPath = serde_json::from_str(r#""/tmp/x""#).unwrap();
        assert_eq!(&*path, Path::new("/tmp/x"));
    }

    #[cfg(unix)]
    #[test]
    fn deserialize_tagged_object_roundtrip() {
        use std::os::unix::ffi::OsStrExt;
        let original = FfiPath(PathBuf::from(OsStr::from_bytes(b"/tmp/caf\xe9")));
        let json = to_json(&original);
        let parsed: FfiPath = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn deserialize_error_messages() {
        for (input, needle) in [
            (r#"{}"#, "exactly one key"),
            (r#"{"other": "x"}"#, "unknown key `other`"),
            (
                r#"{"__path_bytes__": "YQ==", "extra": 1}"#,
                "exactly one key",
            ),
            (r#"{"__path_bytes__": 5}"#, "invalid type"),
            (r#"{"__path_bytes__": "!!!"}"#, "not valid base64"),
            (r#"{"__path_bytes__": "AGE="}"#, "must not contain NUL"),
            ("5", "a path string, or an object"),
            ("[1]", "a path string, or an object"),
            ("null", "a path string, or an object"),
        ] {
            let err = serde_json::from_str::<FfiPath>(input).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "{input}: {err} (wanted {needle:?})"
            );
        }
    }

    #[test]
    fn works_inside_deny_unknown_fields_struct() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            #[serde(default)]
            path: Option<FfiPath>,
        }

        let missing: Request = serde_json::from_str("{}").unwrap();
        assert!(missing.path.is_none());
        let null: Request = serde_json::from_str(r#"{"path": null}"#).unwrap();
        assert!(null.path.is_none());
        let string: Request = serde_json::from_str(r#"{"path": "a"}"#).unwrap();
        assert_eq!(string.path.unwrap().0, PathBuf::from("a"));
        let object: Request =
            serde_json::from_str(r#"{"path": {"__path_bytes__": "YQ=="}}"#).unwrap();
        assert_eq!(object.path.unwrap().0, PathBuf::from("a"));
        assert!(serde_json::from_str::<Request>(r#"{"nope": "a"}"#).is_err());
    }
}
