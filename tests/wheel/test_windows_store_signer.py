"""The windows_store signer: the one signer whose behavior is decided at
build time (``#[cfg(target_os = "windows")]`` in ``ops/sign.rs``).

Off Windows the wrapper rejects it as unsupported. On Windows the upstream
code path is live, and the wrapper's guards must turn its two failure modes
— a panic on a bad store name (upstream validates store names in clap, which
never runs here) and a silent ad-hoc signature on an unmatched fingerprint —
into clean errors.
"""

import sys

import pytest

import apple_platform as ap

WINDOWS = sys.platform == "win32"
BOGUS_FINGERPRINT = "00" * 20  # SHA-1 shaped, matches nothing


@pytest.fixture
def exe(tmp_path):
    path = tmp_path / "exe"
    path.write_bytes(ap.macho.create_synthetic())
    return path


def store_signer(stores, sha1_fingerprint=None):
    return ap.Signer(
        windows_store=ap.WindowsStoreKey(stores=stores, sha1_fingerprint=sha1_fingerprint)
    )


@pytest.mark.skipif(WINDOWS, reason="behavior differs on Windows")
def test_windows_store_signer_is_unsupported_off_windows(exe):
    with pytest.raises(ap.errors.UnsupportedError) as excinfo:
        ap.sign(exe, signer=store_signer(["user"]), timestamp_url="none")
    assert excinfo.value.code == 4
    assert "windows_store" in excinfo.value.message


@pytest.mark.skipif(not WINDOWS, reason="Windows-only behavior")
def test_bogus_store_name_is_rejected_not_panicked(exe):
    # Without the wrapper guard this is upstream's
    # `StoreName::try_from(...).expect(...)` panic (InternalPanicError).
    with pytest.raises(ap.errors.InvalidArgumentError) as excinfo:
        ap.sign(
            exe,
            signer=store_signer(["bogus"], BOGUS_FINGERPRINT),
            timestamp_url="none",
        )
    assert "bogus" in excinfo.value.message


@pytest.mark.skipif(not WINDOWS, reason="Windows-only behavior")
def test_stores_without_fingerprint_is_rejected(exe):
    with pytest.raises(ap.errors.InvalidArgumentError) as excinfo:
        ap.sign(exe, signer=store_signer(["user"]), timestamp_url="none")
    assert "sha1_fingerprint" in excinfo.value.message


@pytest.mark.skipif(not WINDOWS, reason="Windows-only behavior")
def test_unmatched_fingerprint_never_signs_ad_hoc(exe):
    original = exe.read_bytes()
    with pytest.raises(ap.errors.ApplePlatformError) as excinfo:
        ap.sign(
            exe,
            signer=store_signer(["user"], BOGUS_FINGERPRINT),
            timestamp_url="none",
        )
    # Clean failure, never a panic; 10 = the wrapper's NoSigningCertificate
    # guard, 8 tolerated in case the host's store enumeration itself errors.
    assert excinfo.value.code != 2
    assert excinfo.value.code in (8, 10)
    assert exe.read_bytes() == original, "input must not be ad-hoc signed"
