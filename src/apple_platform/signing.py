"""Code signing: Mach-O binaries, bundles, DMGs, and XAR archives.

Three tiers so nobody is blocked:

1. :func:`sign` — typed arguments plus common ``@main``-scope sugar.
2. ``paths=`` — full per-scope control via :class:`~.models.PathSettings`.
3. :func:`sign_raw` — a verbatim request dict, for anything upstream supports
   that this SDK doesn't model yet.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from . import _ffi
from .models import PathLike, PathSettings, Signer

MAIN_SCOPE = "@main"


def _rfc3339(value: Union[str, datetime.datetime, None]) -> Optional[str]:
    if value is None or isinstance(value, str):
        return value
    if value.tzinfo is None:
        raise ValueError("signing_time datetime must be timezone-aware")
    return value.isoformat()


def _build_request(
    *,
    signer: Optional[Signer],
    paths: Optional[Mapping[str, PathSettings]],
    binary_identifier: Optional[str],
    entitlements_xml_file: Optional[PathLike],
    code_signature_flags: Optional[Sequence[str]],
    digests: Optional[Sequence[str]],
    team_name: Optional[str],
    signing_time: Union[str, datetime.datetime, None],
    timestamp_url: Optional[str],
    exclude: Sequence[str],
    shallow: bool,
    for_notarization: bool,
    extra_config: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    scoped: Dict[str, PathSettings] = {k: v for k, v in (paths or {}).items()}

    # Sugar arguments apply to the main scope.
    if any([binary_identifier, entitlements_xml_file, code_signature_flags, digests]):
        main = scoped.get(MAIN_SCOPE, PathSettings())
        if binary_identifier is not None:
            main.binary_identifier = binary_identifier
        if entitlements_xml_file is not None:
            main.entitlements_xml_file = entitlements_xml_file
        if code_signature_flags is not None:
            main.code_signature_flags = list(code_signature_flags)
        if digests is not None:
            main.digests = list(digests)
        scoped[MAIN_SCOPE] = main

    config: Dict[str, Any] = {
        "signer": signer.to_config() if signer is not None else {},
    }
    if scoped:
        config["path"] = {scope: ps.to_config() for scope, ps in scoped.items()}
    if extra_config:
        config.update(extra_config)

    request: Dict[str, Any] = {"config": config}
    if team_name is not None:
        request["team_name"] = team_name
    if signing_time is not None:
        request["signing_time"] = _rfc3339(signing_time)
    if timestamp_url is not None:
        request["timestamp_url"] = timestamp_url
    if exclude:
        request["exclude"] = list(exclude)
    if shallow:
        request["shallow"] = True
    if for_notarization:
        request["for_notarization"] = True
    return request


def sign(
    input_path: PathLike,
    output_path: Optional[PathLike] = None,
    *,
    signer: Optional[Signer] = None,
    paths: Optional[Mapping[str, PathSettings]] = None,
    binary_identifier: Optional[str] = None,
    entitlements_xml_file: Optional[PathLike] = None,
    code_signature_flags: Optional[Sequence[str]] = None,
    digests: Optional[Sequence[str]] = None,
    team_name: Optional[str] = None,
    signing_time: Union[str, datetime.datetime, None] = None,
    timestamp_url: Optional[str] = None,
    exclude: Sequence[str] = (),
    shallow: bool = False,
    for_notarization: bool = False,
    extra_config: Optional[Mapping[str, Any]] = None,
) -> dict:
    """Sign the entity at ``input_path`` (in place if ``output_path`` is None).

    With no ``signer``, an ad-hoc signature is produced. ``timestamp_url``
    defaults to Apple's server when a signing key is present; pass ``"none"``
    to disable timestamp tokens.
    """
    request = _build_request(
        signer=signer,
        paths=paths,
        binary_identifier=binary_identifier,
        entitlements_xml_file=entitlements_xml_file,
        code_signature_flags=code_signature_flags,
        digests=digests,
        team_name=team_name,
        signing_time=signing_time,
        timestamp_url=timestamp_url,
        exclude=exclude,
        shallow=shallow,
        for_notarization=for_notarization,
        extra_config=extra_config,
    )
    request["input_path"] = _ffi.json_path(input_path)
    if output_path is not None:
        request["output_path"] = _ffi.json_path(output_path)
    return sign_raw(request)


def sign_raw(request: Mapping[str, Any]) -> dict:
    """Submit a raw sign request (the JSON shape of the C ABI, verbatim).

    Path values in the request are JSON strings; a path whose OS bytes are
    not valid UTF-8 is spelled ``{"__path_bytes__": "<base64>"}`` instead
    (:func:`apple_platform._ffi.json_path` builds either form).
    """
    return _ffi.call_json("apple_platform_sign", _ffi.encode_json(dict(request)))


def sign_macho_bytes(
    data: bytes,
    *,
    signer: Optional[Signer] = None,
    paths: Optional[Mapping[str, PathSettings]] = None,
    binary_identifier: Optional[str] = None,
    entitlements_xml_file: Optional[PathLike] = None,
    code_signature_flags: Optional[Sequence[str]] = None,
    digests: Optional[Sequence[str]] = None,
    team_name: Optional[str] = None,
    signing_time: Union[str, datetime.datetime, None] = None,
    timestamp_url: Optional[str] = None,
    for_notarization: bool = False,
    extra_config: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Sign an in-memory Mach-O and return the signed binary."""
    request = _build_request(
        signer=signer,
        paths=paths,
        binary_identifier=binary_identifier,
        entitlements_xml_file=entitlements_xml_file,
        code_signature_flags=code_signature_flags,
        digests=digests,
        team_name=team_name,
        signing_time=signing_time,
        timestamp_url=timestamp_url,
        exclude=(),
        shallow=False,
        for_notarization=for_notarization,
        extra_config=extra_config,
    )
    return _ffi.call_bytes(
        "apple_platform_sign_macho_data",
        data,
        len(data),
        _ffi.encode_json(request),
    )
