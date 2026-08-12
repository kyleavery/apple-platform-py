"""Notarization via Apple's notary service, and ticket stapling.

All calls need App Store Connect API credentials
(:class:`NotaryCredentials`) except :func:`staple`, which only talks to
Apple's public ticket lookup service.

Requires a native library built with the ``notarize`` feature (the default
for released wheels); otherwise calls raise
:class:`~apple_platform.errors.FeatureNotEnabledError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from . import _ffi
from .models import PathLike, _clean


@dataclass
class NotaryCredentials:
    """App Store Connect API credentials.

    Either ``api_key_path`` (a unified JSON API key file, as produced by
    ``rcodesign encode-app-store-connect-api-key``) or both ``api_issuer``
    and ``api_key``.
    """

    api_key_path: Optional[PathLike] = None
    api_issuer: Optional[str] = None
    api_key: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {
                "api_key_path": _ffi.json_path(self.api_key_path)
                if self.api_key_path is not None
                else None,
                "api_issuer": self.api_issuer,
                "api_key": self.api_key,
            },
            self.extra,
        )


def submit(
    path: PathLike,
    credentials: NotaryCredentials,
    *,
    wait_seconds: Optional[int] = None,
) -> dict:
    """Upload a bundle, DMG, XAR (.pkg), or zip for notarization.

    Returns ``{"submission_id": ..., "response": ...}``; ``response`` is None
    unless ``wait_seconds`` was given and processing finished in time.
    """
    request: Dict[str, Any] = {
        "credentials": credentials.to_config(),
        "path": _ffi.json_path(path),
    }
    if wait_seconds is not None:
        request["wait_seconds"] = int(wait_seconds)
    return _ffi.call_json("apple_platform_notarize_submit", _ffi.encode_json(request))


def wait(
    submission_id: str,
    credentials: NotaryCredentials,
    *,
    wait_seconds: int = 600,
) -> dict:
    """Wait for a submission to reach a terminal state ("accepted",
    "invalid", "rejected"). Raises after ``wait_seconds`` without one."""
    return _ffi.call_json(
        "apple_platform_notarize_wait",
        _ffi.encode_json(
            {
                "credentials": credentials.to_config(),
                "submission_id": submission_id,
                "wait_seconds": int(wait_seconds),
            }
        ),
    )


def fetch_log(submission_id: str, credentials: NotaryCredentials) -> dict:
    """Fetch the notary service's processing log for a submission."""
    return _ffi.call_json(
        "apple_platform_notarize_log",
        _ffi.encode_json(
            {
                "credentials": credentials.to_config(),
                "submission_id": submission_id,
            }
        ),
    )


def list_submissions(credentials: NotaryCredentials) -> dict:
    """List recent submissions for the credential's account."""
    return _ffi.call_json(
        "apple_platform_notarize_list",
        _ffi.encode_json({"credentials": credentials.to_config()}),
    )


def staple(path: PathLike) -> None:
    """Staple a notarization ticket to the bundle, DMG, or XAR at ``path``.

    The ticket is fetched from Apple's public lookup service, so this needs
    network but no credentials.
    """
    _ffi.call_status("apple_platform_staple", _ffi.encode_path(path))
