"""Mach-O utilities."""

from __future__ import annotations

from typing import Sequence

from . import _ffi
from .models import PathLike


def create_synthetic(
    architecture: str = "aarch64", file_type: str = "executable"
) -> bytes:
    """Build a minimal synthetic Mach-O ("aarch64"/"x86_64",
    "executable"/"dylib"). Useful as a signing fixture on any OS."""
    return _ffi.call_bytes(
        "apple_platform_macho_create_synthetic",
        _ffi.encode_json({"architecture": architecture, "file_type": file_type}),
    )


def create_universal(input_paths: Sequence[PathLike], output_path: PathLike) -> dict:
    """Assemble single-arch Mach-O files into a universal ("fat") binary."""
    return _ffi.call_json(
        "apple_platform_macho_universal_create",
        _ffi.encode_json(
            {
                "input_paths": [_ffi.json_path(p) for p in input_paths],
                "output_path": _ffi.json_path(output_path),
            }
        ),
    )
