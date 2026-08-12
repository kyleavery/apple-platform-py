"""Non-UTF-8 path support across the FFI boundary.

Two tiers: helper/validation tests that run everywhere, and POSIX-gated
end-to-end tests using byte paths a filesystem probe confirms are creatable
(APFS/HFS+ reject invalid-UTF-8 names at the kernel, so the e2e tier
effectively runs on Linux and network mounts).
"""

import os
import sys

import pytest

import apple_platform as ap
from apple_platform import _ffi, packaging
from apple_platform.models import P12Key, PathSettings, PemKey, RemoteKey, Signer

from test_packaging import make_app_bundle

WEIRD = b"caf\xe9"  # latin-1 e-acute: one byte, not valid UTF-8


# ---------------------------------------------------------------------------
# Helpers (all platforms)
# ---------------------------------------------------------------------------


def test_json_path_utf8_is_plain_string(tmp_path):
    assert _ffi.json_path("/tmp/x") == "/tmp/x"
    assert _ffi.json_path(tmp_path) == str(tmp_path)
    assert _ffi.json_path(b"/tmp/x") == "/tmp/x"


def test_json_path_non_utf8_is_tagged_object():
    assert _ffi.json_path(b"/tmp/" + WEIRD) == {_ffi.PATH_BYTES_KEY: "L3RtcC9jYWbp"}


def test_encode_path_accepts_str_bytes_pathlike(tmp_path):
    assert _ffi.encode_path("a") == b"a"
    assert _ffi.encode_path(b"a") == b"a"
    assert _ffi.encode_path(tmp_path) == os.fsencode(tmp_path)


def test_encode_path_rejects_nul():
    with pytest.raises(ap.errors.InvalidArgumentError, match="NUL"):
        _ffi.encode_path(b"a\x00b")


def test_decode_path_object_roundtrips_and_passes_through():
    # Use bytes produced by the host filesystem codec. On POSIX the low
    # surrogate becomes a single non-UTF-8 byte; on Windows it becomes valid
    # WTF-8. An arbitrary byte such as b"\xe9" is not a valid Windows path.
    path = "/tmp/caf\udce9"
    raw = os.fsencode(path)
    tagged = _ffi.json_path(raw)
    assert _ffi._decode_path_object(tagged) == path
    # Not ours: bad base64, extra keys, or wrong value types pass through.
    assert _ffi._decode_path_object({_ffi.PATH_BYTES_KEY: "!!!"}) == {
        _ffi.PATH_BYTES_KEY: "!!!"
    }
    assert _ffi._decode_path_object({_ffi.PATH_BYTES_KEY: "YQ==", "x": 1}) == {
        _ffi.PATH_BYTES_KEY: "YQ==",
        "x": 1,
    }
    assert _ffi._decode_path_object({_ffi.PATH_BYTES_KEY: 5}) == {_ffi.PATH_BYTES_KEY: 5}


# ---------------------------------------------------------------------------
# Upstream-owned config fields stay UTF-8, with field-named errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "build, field_name",
    [
        (lambda: P12Key(path=WEIRD, password="x").to_config(), "p12.path"),
        (
            lambda: P12Key(path="k.p12", password_path=WEIRD).to_config(),
            "p12.password_path",
        ),
        (lambda: PemKey(files=["ok.pem", WEIRD]).to_config(), "pem.files[1]"),
        (
            lambda: Signer(remote=RemoteKey(public_key_pem_path=WEIRD)).to_config(),
            "remote.public_key_pem_path",
        ),
        (
            lambda: PathSettings(entitlements_xml_file=WEIRD).to_config(),
            "entitlements_xml_file",
        ),
    ],
)
def test_upstream_owned_paths_fail_early_naming_the_field(build, field_name):
    with pytest.raises(ap.errors.InvalidArgumentError) as excinfo:
        build()
    assert field_name in str(excinfo.value)
    assert "surrogate" not in str(excinfo.value)


def test_bundle_files_still_emits_plain_strings(tmp_path):
    bundle = make_app_bundle(tmp_path)
    for entry in packaging.bundle_files(bundle):
        assert isinstance(entry["relative_path"], str)
        assert isinstance(entry["absolute_path"], str)


# ---------------------------------------------------------------------------
# End-to-end with byte paths (POSIX + permissive filesystem only)
# ---------------------------------------------------------------------------


@pytest.fixture
def weird_dir(tmp_path):
    """A directory whose name is not valid UTF-8, or skip."""
    if os.name != "posix":
        pytest.skip("byte paths are a POSIX concept")
    path = os.path.join(os.fsencode(tmp_path), WEIRD)
    try:
        os.mkdir(path)
    except (OSError, UnicodeError) as exc:  # APFS/HFS+ enforce UTF-8
        pytest.skip(f"filesystem rejects non-UTF-8 names: {exc}")
    return path


def test_path_type_and_read_signature_on_byte_path(weird_dir):
    exe = os.path.join(weird_dir, b"exe")
    with open(exe, "wb") as fh:
        fh.write(ap.macho.create_synthetic())

    assert ap.path_type(exe) == "macho"
    # The same path as a surrogate-escaped str works too.
    assert ap.path_type(os.fsdecode(exe)) == "macho"

    ap.sign(exe, timestamp_url="none")
    # Response paths decode back to the surrogate-escaped str form.
    entities = ap.read_signature(exe)
    assert entities, "expected at least one signature entity"
    assert entities[0]["path"] == os.fsdecode(exe)
    assert ap.code_directory_identifier(entities) is not None


def test_sign_to_byte_output_path_echoes_it(weird_dir):
    src = os.path.join(weird_dir, b"in")
    dst = os.path.join(weird_dir, b"out" + WEIRD)
    with open(src, "wb") as fh:
        fh.write(ap.macho.create_synthetic())

    result = ap.sign(src, dst, timestamp_url="none")
    assert result["input_path"] == os.fsdecode(src)
    assert result["output_path"] == os.fsdecode(dst)
    assert os.path.exists(dst)


def test_bundle_roundtrip_at_byte_root(weird_dir, tmp_path):
    import pathlib

    root = pathlib.Path(os.fsdecode(weird_dir))
    bundle = make_app_bundle(root)
    link = bundle / "Contents" / "link"
    target_name = os.fsdecode(WEIRD + b"-target")
    (bundle / "Contents" / target_name).write_text("x")
    link.symlink_to(target_name)

    info = packaging.bundle_info(bundle)
    assert info["root_dir"] == str(bundle)
    assert info["info_plist_path"].endswith("Info.plist")

    files = packaging.bundle_files(bundle)
    by_rel = {f["relative_path"]: f for f in files}
    assert by_rel["Contents/link"]["symlink_target"] == target_name
    weird_rel = f"Contents/{target_name}"
    assert weird_rel in by_rel
    assert by_rel[weird_rel]["absolute_path"] == str(bundle / "Contents" / target_name)


def test_dmg_create_rejects_byte_named_content_cleanly(weird_dir, tmp_path):
    # A non-UTF-8 name *inside* the input tree would panic upstream; the
    # wrapper must reject it as InvalidArgument instead.
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "ok.txt").write_text("x")
    weird_child = os.path.join(os.fsencode(payload), WEIRD + b".txt")
    with open(weird_child, "wb") as fh:
        fh.write(b"x")

    with pytest.raises(ap.errors.InvalidArgumentError, match="non-UTF-8"):
        packaging.dmg_create(payload, tmp_path / "out.dmg")


def test_dmg_roundtrip_at_byte_paths(weird_dir, tmp_path):
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "hello.txt").write_text("hello dmg")
    dmg = os.path.join(weird_dir, b"out" + WEIRD + b".dmg")

    packaging.dmg_create(payload, dmg)
    assert ap.path_type(dmg) == "dmg"
    info = packaging.dmg_info(dmg)
    assert info["partitions"]
    data = packaging.dmg_extract_partition(dmg, len(info["partitions"]) - 1)
    assert b"hello dmg" in data


def test_universal_create_to_byte_output(weird_dir, tmp_path):
    a = tmp_path / "a"
    a.write_bytes(ap.macho.create_synthetic("aarch64"))
    b = tmp_path / "b"
    b.write_bytes(ap.macho.create_synthetic("x86_64"))
    out = os.path.join(weird_dir, b"fat")

    result = ap.macho.create_universal([a, b], out)
    assert result["arch_count"] == 2
    assert result["output_path"] == os.fsdecode(out)
    assert os.path.exists(out)


def test_pkg_byte_path_reaches_upstream(weird_dir):
    bogus = os.path.join(weird_dir, b"bogus" + WEIRD + b".pkg")
    with open(bogus, "wb") as fh:
        fh.write(b"not a xar at all")
    # The failure must come from upstream's XAR parser (the path crossed the
    # boundary), not from path validation or a panic.
    with pytest.raises(ap.errors.ApplePlatformError) as excinfo:
        packaging.pkg_info(bogus)
    assert not isinstance(excinfo.value, ap.errors.InternalPanicError)
    assert not isinstance(excinfo.value, ap.errors.InvalidArgumentError)


def test_notarize_submit_deserializes_byte_path(weird_dir):
    # No credentials -> NotarizeError, raised *after* the request (with its
    # tagged byte path) deserialized successfully.
    if not ap.versions()["features"]["notarize"]:
        pytest.skip("notarize feature not enabled in this build")
    with pytest.raises(ap.errors.NotarizeError):
        ap.notarize.submit(
            os.path.join(weird_dir, b"app.zip"),
            ap.notarize.NotaryCredentials(),
        )
