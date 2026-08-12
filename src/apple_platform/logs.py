"""Control capture of the native library's log output.

Once enabled, records emitted during native calls are forwarded to the
standard :mod:`logging` logger named ``apple_platform.rust`` after each call.
"""

from __future__ import annotations

from typing import Union

from . import _ffi
from ._native import lib

_NAMED_LEVELS = {
    "off": 0,
    "error": 1,
    "warn": 2,
    "warning": 2,
    "info": 3,
    "debug": 4,
    "trace": 5,
}


def set_log_level(level: Union[str, int]) -> None:
    """Set the native capture level: "off", "error", "warn", "info", "debug",
    "trace", or the equivalent integer 0-5."""
    if isinstance(level, str):
        try:
            value = _NAMED_LEVELS[level.lower()]
        except KeyError:
            raise ValueError(
                f"unknown log level {level!r}; expected one of "
                f"{sorted(set(_NAMED_LEVELS))}"
            ) from None
    else:
        value = int(level)
    _ffi.check(lib.apple_platform_log_set_level(value))
