"""Certificate helpers: self-signed generation (testing only), analysis,
and PKCS#12 archives."""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from . import _ffi
from .models import PathLike

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)


@dataclass
class SelfSignedCertificate:
    """A freshly generated self-signed code-signing certificate.

    Binaries signed with it will not pass Apple's trust checks; it exists for
    testing and development.
    """

    certificate_pem: str
    private_key_pem: str
    info: Dict[str, Any]

    def write_pem_bundle(self, path: PathLike) -> Path:
        """Write key + certificate as one PEM file usable as a ``PemKey``."""
        # fsdecode: PathLike admits bytes, which Path() would reject.
        target = Path(os.fsdecode(path))
        # Key first, certificate second — upstream's --pem-unified-file order.
        target.write_text(self.private_key_pem + self.certificate_pem)
        return target

    def to_p12(self, password: str, name: str = "code-signing") -> bytes:
        return create_p12(
            certificate_pem=self.certificate_pem,
            private_key_pem=self.private_key_pem,
            password=password,
            name=name,
        )


def generate_self_signed(
    person_name: str,
    *,
    algorithm: str = "rsa",
    profile: str = "apple-development",
    team_id: str = "unset",
    country_name: str = "XX",
    validity_days: int = 365,
) -> SelfSignedCertificate:
    """Generate a self-signed code-signing certificate (mirrors upstream's
    ``generate-self-signed-certificate`` command defaults)."""
    result = _ffi.call_json(
        "apple_platform_certificate_generate_self_signed",
        _ffi.encode_json(
            {
                "person_name": person_name,
                "algorithm": algorithm,
                "profile": profile,
                "team_id": team_id,
                "country_name": country_name,
                "validity_days": validity_days,
            }
        ),
    )
    return SelfSignedCertificate(
        certificate_pem=result["certificate_pem"],
        private_key_pem=result["private_key_pem"],
        info=result["info"],
    )


def analyze(certificate: bytes) -> Dict[str, Any]:
    """Analyze a certificate (DER or PEM bytes) for Apple-specific properties:
    profile, team ID, fingerprints, code-signing extensions, ..."""
    match = _PEM_BLOCK.search(certificate)
    if match:
        certificate = base64.b64decode(b"".join(match.group(1).split()))
    return _ffi.call_json(
        "apple_platform_certificate_analyze", certificate, len(certificate)
    )


def parse_p12(data: bytes, password: str = "") -> Dict[str, Any]:
    """Parse a PKCS#12/PFX archive and report on the certificate inside."""
    return _ffi.call_json(
        "apple_platform_p12_parse",
        data,
        len(data),
        _ffi.encode_json({"password": password}),
    )


def create_p12(
    *,
    certificate_pem: str,
    private_key_pem: str,
    password: str,
    name: str = "code-signing",
) -> bytes:
    """Build a PKCS#12/PFX archive from PEM key + certificate."""
    return _ffi.call_bytes(
        "apple_platform_p12_create",
        _ffi.encode_json(
            {
                "certificate_pem": certificate_pem,
                "private_key_pem": private_key_pem,
                "password": password,
                "name": name,
            }
        ),
    )
