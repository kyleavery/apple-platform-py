"""ctypes loader and the single source of truth for the C ABI surface.

``SIGNATURES`` is mechanically diffed against ``include/apple_platform.h`` by
``tests/wheel/test_abi_contract.py``: adding a symbol on the Rust side without
updating this table fails CI, and vice versa. No other module declares ctypes
types.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

# Must match APPLE_PLATFORM_ABI_VERSION in the native library; checked at
# import time below.
ABI_VERSION = 1


class Buffer(ctypes.Structure):
    """Mirrors ``ApplePlatformBuffer``: Rust-owned bytes, freed exactly once
    via ``apple_platform_buffer_free``."""

    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
        ("cap", ctypes.c_size_t),
    ]


_BUF = ctypes.POINTER(Buffer)
_I32 = ctypes.c_int32
_U32 = ctypes.c_uint32
_STR = ctypes.c_char_p  # borrowed NUL-terminated UTF-8
_PATH = ctypes.c_char_p  # borrowed NUL-terminated OS-native path bytes
_BYTES = ctypes.c_char_p  # borrowed binary data, always paired with a length
_LEN = ctypes.c_size_t

SIGNATURES = {
    # Infrastructure
    "apple_platform_abi_version": ([], _U32),
    "apple_platform_versions": ([_BUF], _I32),
    "apple_platform_config_schema": ([_BUF], _I32),
    "apple_platform_last_error_json": ([_BUF], _I32),
    "apple_platform_buffer_free": ([_BUF], None),
    "apple_platform_log_set_level": ([_I32], _I32),
    "apple_platform_log_drain": ([_BUF], _I32),
    # Signing
    "apple_platform_sign": ([_STR, _BUF], _I32),
    "apple_platform_sign_macho_data": ([_BYTES, _LEN, _STR, _BUF], _I32),
    # Reading / verification
    "apple_platform_path_type": ([_PATH, _BUF], _I32),
    "apple_platform_read_signature": ([_PATH, _BUF], _I32),
    "apple_platform_verify_macho": ([_PATH, _BUF], _I32),
    # Notarization / stapling
    "apple_platform_notarize_submit": ([_STR, _BUF], _I32),
    "apple_platform_notarize_wait": ([_STR, _BUF], _I32),
    "apple_platform_notarize_log": ([_STR, _BUF], _I32),
    "apple_platform_notarize_list": ([_STR, _BUF], _I32),
    "apple_platform_staple": ([_PATH], _I32),
    # Certificates
    "apple_platform_certificate_generate_self_signed": ([_STR, _BUF], _I32),
    "apple_platform_certificate_analyze": ([_BYTES, _LEN, _BUF], _I32),
    "apple_platform_p12_parse": ([_BYTES, _LEN, _STR, _BUF], _I32),
    "apple_platform_p12_create": ([_STR, _BUF], _I32),
    # Mach-O utilities
    "apple_platform_macho_universal_create": ([_STR, _BUF], _I32),
    "apple_platform_macho_create_synthetic": ([_STR, _BUF], _I32),
    # Bundles
    "apple_platform_bundle_info": ([_PATH, _BUF], _I32),
    "apple_platform_bundle_files": ([_PATH, _BUF], _I32),
    # DMG
    "apple_platform_dmg_info": ([_PATH, _BUF], _I32),
    "apple_platform_dmg_extract_partition": ([_STR, _BUF], _I32),
    "apple_platform_dmg_create": ([_STR], _I32),
    # Flat packages
    "apple_platform_pkg_info": ([_PATH, _BUF], _I32),
    "apple_platform_pkg_extract_member": ([_STR, _BUF], _I32),
}

_ENV_OVERRIDE = "APPLE_PLATFORM_LIBRARY_PATH"
# _native_lib.*: what setuptools-rust places in the package.
# libapple_platform.* / apple_platform.*: raw cargo artifacts, for developers
# pointing at a target/ directory via a copy or the env override.
_GLOB_PATTERNS = ("_native_lib*", "libapple_platform*", "apple_platform*")
_SUFFIXES = {".so", ".dylib", ".dll"}


def _candidates():
    package_dir = Path(__file__).resolve().parent
    for pattern in _GLOB_PATTERNS:
        for path in sorted(package_dir.glob(pattern)):
            if path.suffix.lower() in _SUFFIXES:
                yield path


def _load():
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        # An explicit override is authoritative: fail loudly, never fall back.
        # The value goes to ctypes.CDLL verbatim — a bare soname resolves via
        # the platform's default library search (LD_LIBRARY_PATH etc.); on
        # Windows that search does not include the current directory, so pass
        # an absolute path there.
        try:
            return ctypes.CDLL(override), Path(override)
        except OSError as exc:
            raise ImportError(
                f"{_ENV_OVERRIDE}={override!r} could not be loaded: {exc}"
            ) from exc

    failures = []
    for path in _candidates():
        try:
            return ctypes.CDLL(str(path)), path
        except OSError as exc:
            failures.append(f"  {path}: {exc}")

    detail = "\n".join(failures) or (
        f"  no native library found in {Path(__file__).resolve().parent}"
    )
    raise ImportError(
        "could not load the apple_platform native library:\n"
        f"{detail}\n"
        f"Set {_ENV_OVERRIDE} to a library path to override discovery."
    )


lib, library_path = _load()

for _name, (_argtypes, _restype) in SIGNATURES.items():
    try:
        _fn = getattr(lib, _name)
    except AttributeError as exc:
        raise ImportError(
            f"native library {library_path} is missing symbol {_name}; "
            "the library and this SDK are from different package versions"
        ) from exc
    _fn.argtypes = _argtypes
    _fn.restype = _restype

_native_abi = lib.apple_platform_abi_version()
if _native_abi != ABI_VERSION:
    raise ImportError(
        f"native library {library_path} implements ABI v{_native_abi} but this "
        f"SDK requires v{ABI_VERSION}; reinstall apple-platform-py"
    )
