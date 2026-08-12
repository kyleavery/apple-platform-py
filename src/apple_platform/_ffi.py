"""Call-convention helpers over the raw ctypes surface in ``_native``.

Public modules never touch ctypes directly; they go through ``call_status`` /
``call_bytes`` / ``call_json`` so buffer lifetimes, error translation, and log
forwarding live in exactly one place.

Paths cross the boundary as OS-native bytes (``os.fsencode``): direct ``path``
arguments carry them raw; paths inside JSON are plain strings when valid
UTF-8, otherwise ``{"__path_bytes__": "<base64>"}`` objects (``json_path``
builds them, ``call_json`` collapses them back to ``str``).
"""

from __future__ import annotations

import base64
import ctypes
import json
import logging
import os
from typing import Any, Optional

from . import errors
from ._native import Buffer, lib

PATH_BYTES_KEY = "__path_bytes__"

rust_logger = logging.getLogger("apple_platform.rust")

_LOG_LEVELS = {
    "ERROR": logging.ERROR,
    "WARN": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "TRACE": logging.DEBUG,
}


def _read_and_free(buf: Buffer) -> bytes:
    try:
        if not buf.data or buf.len == 0:
            return b""
        return ctypes.string_at(buf.data, buf.len)
    finally:
        lib.apple_platform_buffer_free(ctypes.byref(buf))


def _last_error() -> Optional[dict]:
    buf = Buffer()
    code = lib.apple_platform_last_error_json(ctypes.byref(buf))
    payload = _read_and_free(buf)
    if code != 0 or not payload:
        return None
    return json.loads(payload)


def drain_logs() -> None:
    """Forward buffered native log records to the ``apple_platform.rust`` logger."""
    buf = Buffer()
    if lib.apple_platform_log_drain(ctypes.byref(buf)) != 0:
        lib.apple_platform_buffer_free(ctypes.byref(buf))
        return
    payload = _read_and_free(buf)
    if not payload:
        return
    for entry in json.loads(payload):
        rust_logger.log(
            _LOG_LEVELS.get(entry.get("level", ""), logging.INFO),
            "%s: %s",
            entry.get("target", ""),
            entry.get("message", ""),
        )


def check(code: int) -> None:
    """Raise the mapped exception for a nonzero status code.

    The native last-error slot is reset by every guarded call, so it must be
    read before ``drain_logs`` (which is itself a guarded call).
    """
    if code == 0:
        drain_logs()
        return
    detail = _last_error()
    drain_logs()
    raise errors.exception_for(code, detail)


def call_status(name: str, *args) -> None:
    """Invoke a status-only native function."""
    check(getattr(lib, name)(*args))


def call_bytes(name: str, *args) -> bytes:
    """Invoke a native function whose final parameter is an out-buffer."""
    buf = Buffer()
    code = getattr(lib, name)(*args, ctypes.byref(buf))
    payload = _read_and_free(buf)
    check(code)
    return payload


def _decode_path_object(obj: dict) -> Any:
    """``json.loads`` object_hook: collapse tagged path objects to ``str``."""
    if len(obj) == 1:
        raw = obj.get(PATH_BYTES_KEY)
        if isinstance(raw, str):
            try:
                return os.fsdecode(base64.b64decode(raw, validate=True))
            except (ValueError, UnicodeDecodeError):
                return obj  # not ours; pass upstream JSON through untouched
    return obj


def call_json(name: str, *args) -> Any:
    """Invoke an out-buffer function and decode its JSON payload."""
    payload = call_bytes(name, *args)
    return json.loads(payload, object_hook=_decode_path_object) if payload else None


def encode_json(payload: Any) -> bytes:
    try:
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as exc:
        # ensure_ascii=False makes this fail *here* for strings holding
        # unpaired surrogates, instead of deep inside the native JSON parser
        # with "lone leading surrogate in hex escape".
        raise errors.InvalidArgumentError(
            "request contains text that is not encodable as UTF-8 (usually a "
            "path holding unpaired surrogates); pass byte paths for "
            "wrapper-owned path fields"
        ) from exc


def encode_path(path) -> bytes:
    """Encode a path argument as the OS-native bytes the native side expects.

    ``os.fsencode`` is the exact inverse of ``os.fsdecode``: on POSIX it is
    UTF-8 with ``surrogateescape`` (so ``str``s carrying undecodable bytes
    round-trip), on Windows UTF-8 with ``surrogatepass`` (WTF-8). ``bytes``
    pass through unchanged.
    """
    raw = os.fsencode(path)
    if b"\x00" in raw:
        raise errors.InvalidArgumentError(f"path {path!r} contains a NUL byte")
    return raw


def json_path(path) -> Any:
    """A path as a JSON value: ``str`` when its OS bytes are valid UTF-8,
    otherwise ``{"__path_bytes__": "<base64>"}``."""
    raw = encode_path(path)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return {PATH_BYTES_KEY: base64.b64encode(raw).decode("ascii")}
