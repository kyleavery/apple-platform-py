"""Bundle, DMG, and flat-package (.pkg) inspection and creation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import _ffi
from .models import PathLike


def bundle_info(path: PathLike) -> Dict[str, Any]:
    """Describe an on-disk bundle: identifier, type, version, main
    executable, nested bundles, ..."""
    return _ffi.call_json("apple_platform_bundle_info", _ffi.encode_path(path))


def bundle_files(path: PathLike) -> List[Dict[str, Any]]:
    """List a bundle's files (nested bundles included) as upstream
    classifies them."""
    return _ffi.call_json("apple_platform_bundle_files", _ffi.encode_path(path))


def dmg_info(path: PathLike) -> Dict[str, Any]:
    """Describe a DMG: partitions, chunk codecs, signature presence."""
    return _ffi.call_json("apple_platform_dmg_info", _ffi.encode_path(path))


def dmg_extract_partition(path: PathLike, partition_index: int) -> bytes:
    """Extract a partition's raw data (see ``dmg_info()["partitions"]``)."""
    return _ffi.call_bytes(
        "apple_platform_dmg_extract_partition",
        _ffi.encode_json(
            {"path": _ffi.json_path(path), "partition_index": int(partition_index)}
        ),
    )


def dmg_create(
    input_directory: PathLike,
    output_path: PathLike,
    *,
    volume_label: str = "Untitled",
    total_sectors: Optional[int] = None,
) -> None:
    """Create a FAT32-backed DMG from a directory.

    A testing/CI utility — not an hdiutil replacement (no HFS+/APFS
    volumes). ``total_sectors`` (512-byte units) is sized from the input
    when omitted.
    """
    request: Dict[str, Any] = {
        "input_directory": _ffi.json_path(input_directory),
        "output_path": _ffi.json_path(output_path),
        "volume_label": volume_label,
    }
    if total_sectors is not None:
        request["total_sectors"] = int(total_sectors)
    _ffi.call_status("apple_platform_dmg_create", _ffi.encode_json(request))


def pkg_info(path: PathLike) -> Dict[str, Any]:
    """Describe a flat package installer: flavor, distribution XML (as
    upstream's serde model, verbatim), component packages, XAR members."""
    return _ffi.call_json("apple_platform_pkg_info", _ffi.encode_path(path))


def pkg_extract_member(path: PathLike, member: str) -> bytes:
    """Extract a member file from the package's XAR archive by name
    (see ``pkg_info()["files"]``)."""
    return _ffi.call_bytes(
        "apple_platform_pkg_extract_member",
        _ffi.encode_json({"path": _ffi.json_path(path), "member": member}),
    )
