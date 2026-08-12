//! Phase-0 de-risk spikes against the pinned upstream (apple-codesign/0.29.0).
//!
//! These tests prove the three load-bearing design assumptions:
//! 1. Upstream's `SignConfig` deserializes from plain JSON (no figment).
//! 2. `deny_unknown_fields` errors enumerate valid field names (schema probe).
//! 3. `SignatureReader` entities can be bridged to JSON.

use apple_codesign::{
    cli::{certificate_source::CertificateSource, config::SignConfig},
    macho_builder::MachOBuilder,
    SettingsScope, SignatureReader, SigningSettings, UnifiedSigner,
};

#[test]
fn sign_config_deserializes_from_plain_json() {
    let json = r#"{
        "signer": {"p12": {"path": "key.p12", "password": "password"}},
        "path": {"Contents/MacOS/extra": {"binary_identifier": "com.example.x",
                                          "code_signature_flags": ["runtime"]}}
    }"#;

    let config: SignConfig = serde_json::from_str(json).unwrap();

    let p12 = config.signer.p12_key.as_ref().unwrap();
    assert_eq!(p12.password.as_deref(), Some("password"));
    assert_eq!(config.paths.len(), 1);
    assert_eq!(
        config.paths["Contents/MacOS/extra"]
            .binary_identifier
            .as_deref(),
        Some("com.example.x")
    );

    // Unknown fields must be rejected, otherwise typos silently no-op.
    assert!(serde_json::from_str::<SignConfig>(r#"{"bogus": 1}"#).is_err());
}

#[test]
fn deny_unknown_fields_probe_enumerates_fields() {
    let err = serde_json::from_str::<CertificateSource>(r#"{"__probe__": 1}"#)
        .unwrap_err()
        .to_string();

    assert!(err.contains("expected one of"), "{err}");
    for field in [
        "`smartcard`",
        "`macos_keychain`",
        "`windows_store`",
        "`pem`",
        "`p12`",
        "`remote`",
        "`certificate_der`",
    ] {
        assert!(err.contains(field), "missing {field} in: {err}");
    }
}

#[test]
fn signature_reader_entities_bridge_to_json() {
    // Synthesize a Mach-O, ad-hoc sign it, read its signature entities back.
    const MH_EXECUTE: u32 = 0x2;
    let macho = MachOBuilder::new_aarch64(MH_EXECUTE).write_macho().unwrap();

    let dir = std::env::temp_dir().join(format!("apple-platform-spike-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("exe");
    let output = dir.join("exe.signed");
    std::fs::write(&input, &macho).unwrap();

    let mut settings = SigningSettings::default();
    settings.set_binary_identifier(SettingsScope::Main, "com.example.spike");
    UnifiedSigner::new(settings)
        .sign_path(&input, &output)
        .unwrap();

    let entities = SignatureReader::from_path(&output)
        .unwrap()
        .entities()
        .unwrap();
    assert!(!entities.is_empty());

    // Preferred bridge: straight serde_json.
    let direct = serde_json::to_string(&entities);

    // Guaranteed bridge: YAML (the entities' native serialization) -> JSON.
    let yaml = serde_yaml::to_string(&entities).unwrap();
    let value: serde_json::Value = serde_yaml::from_str(&yaml).unwrap();
    let via_yaml = serde_json::to_string(&value).unwrap();
    assert!(via_yaml.contains("com.example.spike"), "{via_yaml}");

    match direct {
        Ok(s) => {
            assert!(s.contains("com.example.spike"));
            eprintln!("spike: direct serde_json serialization works");
        }
        Err(e) => eprintln!("spike: direct serde_json failed ({e}); YAML hop required"),
    }

    std::fs::remove_dir_all(&dir).ok();
}
