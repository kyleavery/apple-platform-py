//! Version and provenance report. The `APPLE_PLATFORM_*` environment
//! variables are stamped by `build.rs` from the submodule checkout.

use crate::error::FfiError;

pub(crate) fn versions_json() -> Result<Vec<u8>, FfiError> {
    let payload = serde_json::json!({
        "crate_version": env!("CARGO_PKG_VERSION"),
        "abi_version": crate::abi::APPLE_PLATFORM_ABI_VERSION,
        "target": env!("APPLE_PLATFORM_TARGET"),
        "profile": env!("APPLE_PLATFORM_PROFILE"),
        "features": {
            "notarize": cfg!(feature = "notarize"),
            "smartcard": cfg!(feature = "smartcard"),
        },
        "upstream": {
            "commit": env!("APPLE_PLATFORM_UPSTREAM_COMMIT"),
            "describe": env!("APPLE_PLATFORM_UPSTREAM_DESCRIBE"),
            "crates": {
                "apple-codesign": env!("APPLE_PLATFORM_UPSTREAM_APPLE_CODESIGN"),
                "apple-bundles": env!("APPLE_PLATFORM_UPSTREAM_APPLE_BUNDLES"),
                "apple-dmg": env!("APPLE_PLATFORM_UPSTREAM_APPLE_DMG"),
                "apple-flat-package": env!("APPLE_PLATFORM_UPSTREAM_APPLE_FLAT_PACKAGE"),
            },
        },
    });
    Ok(serde_json::to_vec(&payload)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions_reports_upstream_crates() {
        let payload: serde_json::Value =
            serde_json::from_slice(&super::versions_json().unwrap()).unwrap();
        assert_eq!(
            payload["abi_version"],
            crate::abi::APPLE_PLATFORM_ABI_VERSION
        );
        // Stamped from the submodule's Cargo.toml, not hardcoded anywhere.
        let codesign = payload["upstream"]["crates"]["apple-codesign"]
            .as_str()
            .unwrap();
        assert!(!codesign.is_empty() && codesign != "unknown");
    }
}
