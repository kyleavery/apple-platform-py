"""Bundle/DMG round-trips built entirely from synthetic artifacts."""

import os
import plistlib

import pytest

import apple_platform as ap
from apple_platform import packaging


def make_app_bundle(root, name="Demo"):
    """A minimal but well-formed .app bundle."""
    bundle = root / f"{name}.app"
    contents = bundle / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "MacOS" / name).write_bytes(ap.macho.create_synthetic())
    (contents / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": f"com.example.{name.lower()}",
                "CFBundleName": name,
                "CFBundleExecutable": name,
                "CFBundleVersion": "1.2.3",
                "CFBundlePackageType": "APPL",
            }
        )
    )
    return bundle


def test_bundle_info_and_files(tmp_path):
    bundle = make_app_bundle(tmp_path)

    info = packaging.bundle_info(bundle)
    assert info["identifier"] == "com.example.demo"
    assert info["main_executable"] == "Demo"
    assert info["version"] == "1.2.3"
    assert ap.path_type(bundle) == "bundle"

    files = packaging.bundle_files(bundle)
    relative = {f["relative_path"] for f in files}
    assert os.path.join("Contents", "Info.plist") in relative
    assert os.path.join("Contents", "MacOS", "Demo") in relative


def test_sign_bundle_and_read_back(tmp_path):
    bundle = make_app_bundle(tmp_path)
    ap.sign(bundle, timestamp_url="none")  # ad-hoc, in place
    entities = ap.read_signature(bundle)
    assert ap.code_directory_identifier(entities) is not None
    relative = {e.get("path") for e in entities}
    # Signing a bundle produces a CodeResources file.
    assert any("CodeResources" in (p or "") for p in relative)


def test_dmg_create_info_extract_roundtrip(tmp_path):
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "hello.txt").write_text("hello dmg")

    dmg = tmp_path / "out.dmg"
    packaging.dmg_create(payload, dmg, volume_label="TEST")

    assert ap.path_type(dmg) == "dmg"
    info = packaging.dmg_info(dmg)
    assert info["partitions"], info
    assert info["has_code_signature"] is False

    data = packaging.dmg_extract_partition(dmg, len(info["partitions"]) - 1)
    assert data  # FAT32 filesystem bytes
    assert b"hello dmg" in data


def test_dmg_create_rejects_missing_directory(tmp_path):
    with pytest.raises(ap.errors.InvalidArgumentError):
        packaging.dmg_create(tmp_path / "nope", tmp_path / "out.dmg")


def test_pkg_info_rejects_non_xar(tmp_path):
    bogus = tmp_path / "bogus.pkg"
    bogus.write_bytes(b"not a xar at all")
    with pytest.raises(ap.errors.ApplePlatformError):
        packaging.pkg_info(bogus)
