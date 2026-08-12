import re

import apple_platform as ap


def test_versions_shape():
    v = ap.versions()
    assert v["abi_version"] == 1
    assert v["package_version"] == ap.__version__
    assert re.match(r"\d+\.\d+\.\d+", v["crate_version"])
    assert set(v["features"]) >= {"notarize", "smartcard"}
    assert v["target"]
    for crate in (
        "apple-codesign",
        "apple-bundles",
        "apple-dmg",
        "apple-flat-package",
    ):
        assert re.match(r"\d+\.\d+\.\d+", v["upstream"]["crates"][crate]), crate


def test_config_schema_reflects_upstream():
    schema = ap.config_schema()
    assert "signer" in schema["SignConfig"]
    assert "p12" in schema["CertificateSource"]
    assert "pem" in schema["CertificateSource"]
    assert schema["ScopedSigningSettingsValues"]
