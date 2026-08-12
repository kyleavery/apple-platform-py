"""Apple code signing, notarization, and packaging for Python.

Powered by `apple-platform-rs <https://github.com/indygreg/apple-platform-rs>`_
(the ``rcodesign`` project) through a bundled native library.
"""

from . import certificates, errors, macho, notarize, packaging, reading
from .errors import ApplePlatformError
from .logs import set_log_level
from .models import (
    CertificateDerKey,
    MacosKeychainKey,
    P12Key,
    PathSettings,
    PemKey,
    RemoteKey,
    Signer,
    SmartcardKey,
    WindowsStoreKey,
)
from .reading import code_directory_identifier, path_type, read_signature, verify_macho
from .signing import sign, sign_macho_bytes, sign_raw
from .versions import config_schema, versions

__version__ = "0.1.0"

__all__ = [
    "ApplePlatformError",
    "CertificateDerKey",
    "MacosKeychainKey",
    "P12Key",
    "PathSettings",
    "PemKey",
    "RemoteKey",
    "Signer",
    "SmartcardKey",
    "WindowsStoreKey",
    "__version__",
    "certificates",
    "code_directory_identifier",
    "config_schema",
    "errors",
    "macho",
    "notarize",
    "packaging",
    "path_type",
    "read_signature",
    "reading",
    "set_log_level",
    "sign",
    "sign_macho_bytes",
    "sign_raw",
    "verify_macho",
    "versions",
]
