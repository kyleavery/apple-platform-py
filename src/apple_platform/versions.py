"""Version, provenance, and schema introspection."""

from __future__ import annotations

from . import _ffi


def versions() -> dict:
    """Report package/ABI versions, enabled features, build target, and the
    upstream apple-platform-rs provenance (crate versions, git commit) this
    library was built from."""
    payload = _ffi.call_json("apple_platform_versions")
    # The Python distribution version lives only in pyproject.toml/__init__;
    # the native report carries the FFI crate's own version as crate_version.
    from . import __version__

    payload["package_version"] = __version__
    return payload


def config_schema() -> dict:
    """Map of upstream config type name -> accepted JSON field names,
    reflected at runtime from the compiled-in upstream sources.

    Useful for discovering settings this SDK's typed helpers don't model yet;
    any listed field can be passed through the ``extra`` escape hatches.
    """
    return _ffi.call_json("apple_platform_config_schema")
