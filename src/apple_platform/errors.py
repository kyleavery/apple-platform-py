"""Exception hierarchy mirroring the native library's status codes.

Codes are stable: the native side never renumbers them, only appends. Unknown
codes (a newer library than this SDK) degrade to :class:`ApplePlatformError`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    "ApplePlatformError",
    "InternalPanicError",
    "InvalidArgumentError",
    "UnsupportedError",
    "FeatureNotEnabledError",
    "InteractiveInputRequiredError",
    "IoError",
    "CertificateError",
    "PrivateKeyError",
    "NoSigningCertificateError",
    "SigningError",
    "VerificationError",
    "TimestampError",
    "NotarizeError",
    "StapleError",
    "MachOError",
    "BundleError",
    "DmgError",
    "FlatPackageError",
    "RemoteSigningError",
]


class ApplePlatformError(Exception):
    """Base class for all errors raised by the native library.

    Attributes:
        code: native status code (``APPLE_PLATFORM_ERR_*``), if known.
        kind: stable classification label from the native error report.
        source: messages from the underlying Rust error chain, outermost first.
        details: optional structured payload for specific error kinds.
    """

    def __init__(
        self,
        message: str,
        *,
        code: Optional[int] = None,
        kind: Optional[str] = None,
        source: Optional[list] = None,
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.kind = kind
        self.source = list(source or [])
        self.details = details


class InternalPanicError(ApplePlatformError):
    """The native library panicked; this is a bug worth reporting."""


class InvalidArgumentError(ApplePlatformError, ValueError):
    """A request was malformed (bad JSON, unknown field, undecodable path
    bytes, a non-UTF-8 path in an upstream-owned config field, ...)."""


class UnsupportedError(ApplePlatformError):
    """The operation is not supported by this library version or input."""


class FeatureNotEnabledError(ApplePlatformError):
    """The library was compiled without the required cargo feature."""


class InteractiveInputRequiredError(ApplePlatformError):
    """The operation would prompt on a terminal (e.g. a missing p12 password).

    Supply the credential in the request instead.
    """


class IoError(ApplePlatformError):
    """A filesystem or network I/O failure."""


class CertificateError(ApplePlatformError):
    """Loading, parsing, or using an X.509 certificate failed."""


class PrivateKeyError(ApplePlatformError):
    """Loading or using a private key failed (bad password, PKCS#12, smartcard)."""


class NoSigningCertificateError(CertificateError):
    """The request resolved no signing certificate."""


class SigningError(ApplePlatformError):
    """Producing a code signature failed."""


class VerificationError(ApplePlatformError):
    """Signature verification reported problems."""


class TimestampError(ApplePlatformError):
    """Interacting with a timestamp server failed."""


class NotarizeError(ApplePlatformError):
    """Interacting with Apple's notary service failed."""


class StapleError(ApplePlatformError):
    """Stapling a notarization ticket failed."""


class MachOError(ApplePlatformError):
    """Reading or writing a Mach-O binary failed."""


class BundleError(ApplePlatformError):
    """Reading or traversing a bundle failed."""


class DmgError(ApplePlatformError):
    """Reading or writing a DMG failed."""


class FlatPackageError(ApplePlatformError):
    """Reading a flat package (.pkg/XAR) failed."""


class RemoteSigningError(ApplePlatformError):
    """Remote code signing session failed."""


# Native status code -> exception class. Code 0 is success and never raises;
# code 1 (UNKNOWN) intentionally maps to the base class.
CODE_TO_EXCEPTION: Dict[int, type] = {
    1: ApplePlatformError,
    2: InternalPanicError,
    3: InvalidArgumentError,
    4: UnsupportedError,
    5: FeatureNotEnabledError,
    6: InteractiveInputRequiredError,
    7: IoError,
    8: CertificateError,
    9: PrivateKeyError,
    10: NoSigningCertificateError,
    11: SigningError,
    12: VerificationError,
    13: TimestampError,
    14: NotarizeError,
    15: StapleError,
    16: MachOError,
    17: BundleError,
    18: DmgError,
    19: FlatPackageError,
    20: RemoteSigningError,
}


def exception_for(code: int, detail: Optional[dict]) -> ApplePlatformError:
    """Build the exception for a failed native call."""
    detail = detail or {}
    cls = CODE_TO_EXCEPTION.get(code, ApplePlatformError)
    message = detail.get("message") or f"native call failed with status code {code}"
    return cls(
        message,
        code=code,
        kind=detail.get("kind"),
        source=detail.get("source"),
        details=detail.get("details"),
    )
