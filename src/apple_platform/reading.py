"""Inspect code signatures and classify signable paths.

``read_signature`` returns upstream's ``SignatureReader`` entity list
verbatim: a list of file-entity dicts whose ``entity`` member is a
single-key map naming the entity type (``code-directory``, ``cms``, ...).
The shape tracks upstream and is intentionally not remodeled here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import _ffi
from .models import PathLike


def path_type(path: PathLike) -> str:
    """Classify a path as upstream sees it: "macho", "dmg", "bundle",
    "xar", "zip", or "other"."""
    return _ffi.call_json("apple_platform_path_type", _ffi.encode_path(path))[
        "path_type"
    ]


def read_signature(path: PathLike) -> List[Dict[str, Any]]:
    """Read all code-signature entities from a signable path."""
    return _ffi.call_json("apple_platform_read_signature", _ffi.encode_path(path))


def verify_macho(path: PathLike) -> List[Dict[str, Any]]:
    """Verify a Mach-O, returning a list of problems (empty = none found).

    Upstream documents this as advisory — it is not a full replacement for
    Apple's verification.
    """
    return _ffi.call_json("apple_platform_verify_macho", _ffi.encode_path(path))


def find_entities(entities: List[Dict[str, Any]], entity_type: str) -> List[Any]:
    """All entity payloads of ``entity_type`` (e.g. "mach_o") from a
    :func:`read_signature` result."""
    found = []
    for file_entity in entities:
        entity = file_entity.get("entity")
        if isinstance(entity, dict) and entity_type in entity:
            found.append(entity[entity_type])
        elif entity == entity_type:
            # Payload-less entities serialize as a bare string.
            found.append({})
    return found


def find_values(entities: Any, key: str) -> List[Any]:
    """All non-null values of ``key`` anywhere in a :func:`read_signature`
    result. The entity JSON mirrors upstream and its nesting may change with
    the upstream pin, so prefer this over hardcoding paths."""
    found: List[Any] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                if k == key and v is not None:
                    found.append(v)
                walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(entities)
    return found


def code_directory_identifier(entities: List[Dict[str, Any]]) -> Optional[str]:
    """The first code directory identifier in a :func:`read_signature` result."""
    for payload in find_values(entities, "code_directory"):
        if isinstance(payload, dict) and payload.get("identifier"):
            return payload["identifier"]
    return None


def has_cms_signature(entities: List[Dict[str, Any]]) -> bool:
    """Whether any entity carries a CMS (non-ad-hoc) signature."""
    return bool(find_values(entities, "cms"))
