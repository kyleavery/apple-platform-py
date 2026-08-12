"""Dataclasses mirroring upstream's serde config types 1:1.

Field names match the JSON that upstream's ``SignConfig`` deserializes
(``rcodesign``'s config file format). Every dataclass carries an ``extra``
dict merged verbatim into its JSON — when upstream grows a field this SDK
doesn't model yet, pass it there (discover names via
:func:`apple_platform.config_schema`). ``None``/empty values are dropped
because upstream rejects unknown *and* misshapen fields.

Path fields here are *upstream-owned*: upstream's serde types deserialize
them as JSON strings, so they must be UTF-8-encodable (unlike the
wrapper-owned paths elsewhere in the SDK, which accept arbitrary OS bytes).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from . import errors

PathLike = Union[str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"]


def _fspath(value: PathLike, field_name: str) -> str:
    """Encode a path for an upstream-owned config field.

    Upstream deserializes these as JSON strings — there is no byte-path form
    to hand them. Fail here, naming the field, rather than deep inside the
    native JSON parser.
    """
    raw = os.fsencode(value)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise errors.InvalidArgumentError(
            f"{field_name} must be a UTF-8-encodable path because upstream's "
            f"config format has no byte-path form; got {value!r}"
        ) from None


def _clean(mapping: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Drop unset values, then overlay the escape-hatch dict."""
    result = {key: value for key, value in mapping.items() if value not in (None, [], {})}
    result.update(extra)
    return result


@dataclass
class P12Key:
    """Upstream ``p12``: a PKCS#12/PFX archive.

    ``password`` or ``password_path`` is required — without one, upstream
    would prompt on a terminal and the native layer rejects the request.
    """

    path: PathLike
    password: Optional[str] = None
    password_path: Optional[PathLike] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {
                "path": _fspath(self.path, "p12.path"),
                "password": self.password,
                "password_path": _fspath(self.password_path, "p12.password_path")
                if self.password_path is not None
                else None,
            },
            self.extra,
        )


@dataclass
class PemKey:
    """Upstream ``pem``: PEM files containing certificates and/or keys."""

    files: List[PathLike] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {"files": [_fspath(p, f"pem.files[{i}]") for i, p in enumerate(self.files)]},
            self.extra,
        )


@dataclass
class CertificateDerKey:
    """Upstream ``certificate_der``: DER certificate files (no private key)."""

    paths: List[PathLike] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {
                "paths": [
                    _fspath(p, f"certificate_der.paths[{i}]")
                    for i, p in enumerate(self.paths)
                ]
            },
            self.extra,
        )


@dataclass
class SmartcardKey:
    """Upstream ``smartcard``: a YubiKey/PIV slot.

    Requires a build with the ``smartcard`` feature; ``pin`` is required to
    avoid a terminal prompt.
    """

    slot: str
    pin: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean({"slot": self.slot, "pin": self.pin}, self.extra)


@dataclass
class MacosKeychainKey:
    """Upstream ``macos_keychain`` (macOS only)."""

    domains: List[str] = field(default_factory=list)
    sha256_fingerprint: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {"domains": self.domains, "sha256_fingerprint": self.sha256_fingerprint},
            self.extra,
        )


@dataclass
class WindowsStoreKey:
    """Upstream ``windows_store`` (Windows only)."""

    stores: List[str] = field(default_factory=list)
    sha1_fingerprint: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {"stores": self.stores, "sha1_fingerprint": self.sha1_fingerprint},
            self.extra,
        )


@dataclass
class RemoteKey:
    """Upstream ``remote``: session-based remote code signing."""

    url: Optional[str] = None
    public_key: Optional[str] = None
    public_key_pem_path: Optional[PathLike] = None
    shared_secret: Optional[str] = None
    shared_secret_env: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {
                "url": self.url,
                "public_key": self.public_key,
                "public_key_pem_path": _fspath(
                    self.public_key_pem_path, "remote.public_key_pem_path"
                )
                if self.public_key_pem_path is not None
                else None,
                "shared_secret": self.shared_secret,
                "shared_secret_env": self.shared_secret_env,
            },
            self.extra,
        )


@dataclass
class Signer:
    """Upstream ``CertificateSource``: where the signing key/certs come from.

    Multiple sources may be set; upstream merges what they resolve.
    """

    p12: Optional[P12Key] = None
    pem: Optional[PemKey] = None
    certificate_der: Optional[CertificateDerKey] = None
    smartcard: Optional[SmartcardKey] = None
    macos_keychain: Optional[MacosKeychainKey] = None
    windows_store: Optional[WindowsStoreKey] = None
    remote: Optional[RemoteKey] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        return _clean(
            {
                "p12": self.p12.to_config() if self.p12 else None,
                "pem": self.pem.to_config() if self.pem else None,
                "certificate_der": self.certificate_der.to_config()
                if self.certificate_der
                else None,
                "smartcard": self.smartcard.to_config() if self.smartcard else None,
                "macos_keychain": self.macos_keychain.to_config()
                if self.macos_keychain
                else None,
                "windows_store": self.windows_store.to_config()
                if self.windows_store
                else None,
                "remote": self.remote.to_config() if self.remote else None,
            },
            self.extra,
        )


@dataclass
class PathSettings:
    """Upstream ``ScopedSigningSettingsValues``: per-scope signing settings.

    Scopes are upstream path scope strings: ``@main`` (default target),
    ``path/inside/bundle``, ``*`` wildcards, etc.
    """

    binary_identifier: Optional[str] = None
    code_requirements_file: Optional[PathLike] = None
    code_resources_file: Optional[PathLike] = None
    code_signature_flags: List[str] = field(default_factory=list)
    digests: List[str] = field(default_factory=list)
    entitlements_xml_file: Optional[PathLike] = None
    launch_constraints_self_file: Optional[PathLike] = None
    launch_constraints_parent_file: Optional[PathLike] = None
    launch_constraints_responsible_file: Optional[PathLike] = None
    library_constraints_file: Optional[PathLike] = None
    runtime_version: Optional[str] = None
    info_plist_file: Optional[PathLike] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_config(self) -> Dict[str, Any]:
        def path_or_none(value: Optional[PathLike], field_name: str) -> Optional[str]:
            return _fspath(value, field_name) if value is not None else None

        return _clean(
            {
                "binary_identifier": self.binary_identifier,
                "code_requirements_file": path_or_none(
                    self.code_requirements_file, "code_requirements_file"
                ),
                "code_resources_file": path_or_none(
                    self.code_resources_file, "code_resources_file"
                ),
                "code_signature_flags": self.code_signature_flags,
                "digests": self.digests,
                "entitlements_xml_file": path_or_none(
                    self.entitlements_xml_file, "entitlements_xml_file"
                ),
                "launch_constraints_self_file": path_or_none(
                    self.launch_constraints_self_file, "launch_constraints_self_file"
                ),
                "launch_constraints_parent_file": path_or_none(
                    self.launch_constraints_parent_file, "launch_constraints_parent_file"
                ),
                "launch_constraints_responsible_file": path_or_none(
                    self.launch_constraints_responsible_file,
                    "launch_constraints_responsible_file",
                ),
                "library_constraints_file": path_or_none(
                    self.library_constraints_file, "library_constraints_file"
                ),
                "runtime_version": self.runtime_version,
                "info_plist_file": path_or_none(self.info_plist_file, "info_plist_file"),
            },
            self.extra,
        )
