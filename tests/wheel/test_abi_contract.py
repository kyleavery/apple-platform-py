"""The ABI drift tripwire: the committed C header, the Rust exports, and the
Python signature table must always describe the same set of symbols."""

import ctypes
import re
from pathlib import Path

import pytest

from apple_platform import _native


def _header_path():
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "include" / "apple_platform.h"
        if candidate.exists():
            return candidate
    return None


def test_abi_version_handshake():
    assert _native.lib.apple_platform_abi_version() == _native.ABI_VERSION


def test_all_signatures_resolve():
    for name in _native.SIGNATURES:
        assert getattr(_native.lib, name) is not None


def test_header_and_signature_table_agree():
    header = _header_path()
    if header is None:
        pytest.skip("include/apple_platform.h not present (installed-wheel run)")
    declared = set(
        re.findall(r"\b(apple_platform_[a-z0-9_]+)\s*\(", header.read_text())
    )
    table = set(_native.SIGNATURES)
    assert declared == table, (
        f"symbols only in header: {sorted(declared - table)}; "
        f"symbols only in SIGNATURES: {sorted(table - declared)}"
    )


def test_buffer_layout():
    assert [name for name, _ in _native.Buffer._fields_] == ["data", "len", "cap"]
    assert ctypes.sizeof(_native.Buffer) == 3 * ctypes.sizeof(ctypes.c_size_t)
