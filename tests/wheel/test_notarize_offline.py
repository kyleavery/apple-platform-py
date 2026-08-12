"""Offline error paths for notarization and stapling. Live round-trips need
Apple credentials and run only with ``-m live``."""

import pytest

import apple_platform as ap
from apple_platform import notarize


def _notarize_enabled() -> bool:
    return ap.versions()["features"]["notarize"]


def test_submit_without_credentials_raises_notarize_error(tmp_path):
    if not _notarize_enabled():
        pytest.skip("library built without the notarize feature")
    with pytest.raises(ap.errors.NotarizeError) as exc_info:
        notarize.submit(tmp_path, notarize.NotaryCredentials())
    assert "credentials" in exc_info.value.message.lower()


def test_submit_with_bogus_key_id_fails_cleanly_offline(tmp_path):
    if not _notarize_enabled():
        pytest.skip("library built without the notarize feature")
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic())
    # Upstream resolves credentials before validating the path; a bogus key
    # ID fails the local key-file lookup without any network traffic. The
    # point is a clean exception, not a hang or panic.
    with pytest.raises(ap.errors.ApplePlatformError) as exc_info:
        notarize.submit(
            exe, notarize.NotaryCredentials(api_issuer="bogus", api_key="bogus")
        )
    assert "api key" in exc_info.value.message.lower()


def test_staple_unsigned_macho_fails_cleanly(tmp_path):
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic())
    # A Mach-O is not a stapleable entity; upstream classifies and rejects it
    # before any network traffic.
    with pytest.raises(ap.errors.ApplePlatformError):
        notarize.staple(exe)
