"""The end-to-end gate: exercises every load-bearing design decision with no
fixtures and no network — dylib load, buffers both directions, upstream
CertificateSource/SignConfig deserialization, upstream policy functions,
UnifiedSigner/MachOSigner, and the SignatureReader JSON bridge."""

import pathlib

import pytest

import apple_platform as ap

IDENTIFIER = "com.example.apple-platform-py.e2e"


@pytest.fixture(scope="module")
def cert():
    return ap.certificates.generate_self_signed(
        person_name="apple-platform-py CI", team_id="CITEAM"
    )


def test_generated_certificate_reports_apple_properties(cert):
    assert "BEGIN CERTIFICATE" in cert.certificate_pem
    assert "BEGIN PRIVATE KEY" in cert.private_key_pem
    assert cert.info["team_id"] == "CITEAM"
    analyzed = ap.certificates.analyze(cert.certificate_pem.encode())
    assert analyzed["team_id"] == "CITEAM"
    assert analyzed["subject_is_issuer"] is True


def test_sign_file_with_pem_key_and_read_back(cert, tmp_path: pathlib.Path):
    pem = cert.write_pem_bundle(tmp_path / "signer.pem")
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic(architecture="aarch64"))
    assert ap.path_type(exe) == "macho"

    result = ap.sign(
        exe,
        tmp_path / "exe.signed",
        signer=ap.Signer(pem=ap.PemKey(files=[pem])),
        binary_identifier=IDENTIFIER,
        timestamp_url="none",  # keep tests offline
    )
    assert result["output_path"].endswith("exe.signed")

    entities = ap.read_signature(tmp_path / "exe.signed")
    assert ap.code_directory_identifier(entities) == IDENTIFIER
    # A real (non-ad-hoc) signature must carry a CMS blob.
    assert ap.reading.has_cms_signature(entities)


def test_sign_macho_bytes_adhoc_roundtrip(tmp_path: pathlib.Path):
    raw = ap.macho.create_synthetic(architecture="x86_64")
    signed = ap.sign_macho_bytes(raw, binary_identifier=IDENTIFIER)
    assert signed != raw

    out = tmp_path / "adhoc"
    out.write_bytes(signed)
    assert ap.code_directory_identifier(ap.read_signature(out)) == IDENTIFIER
    # Upstream's advisory verifier flags the empty CMS blob of ad-hoc
    # signatures; the digests themselves must be clean.
    problems = ap.verify_macho(out)
    assert all("CMS" in p["description"] for p in problems), problems


def test_p12_roundtrip_and_signing(cert, tmp_path: pathlib.Path):
    p12_bytes = cert.to_p12(password="secret")
    parsed = ap.certificates.parse_p12(p12_bytes, password="secret")
    assert parsed["team_id"] == "CITEAM"
    assert parsed["has_private_key"] is True

    p12_file = tmp_path / "signer.p12"
    p12_file.write_bytes(p12_bytes)
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic())
    ap.sign(
        exe,
        signer=ap.Signer(p12=ap.P12Key(path=p12_file, password="secret")),
        binary_identifier=IDENTIFIER,
        timestamp_url="none",
    )
    entities = ap.read_signature(exe)  # signed in place
    assert ap.code_directory_identifier(entities) == IDENTIFIER


def test_wrong_p12_password_raises_private_key_error(cert, tmp_path: pathlib.Path):
    p12_file = tmp_path / "signer.p12"
    p12_file.write_bytes(cert.to_p12(password="right"))
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic())

    with pytest.raises(ap.errors.PrivateKeyError):
        ap.sign(
            exe,
            signer=ap.Signer(p12=ap.P12Key(path=p12_file, password="wrong")),
            timestamp_url="none",
        )


def test_universal_create_and_classify(tmp_path: pathlib.Path):
    slim_a = tmp_path / "a"
    slim_b = tmp_path / "b"
    slim_a.write_bytes(ap.macho.create_synthetic(architecture="aarch64"))
    slim_b.write_bytes(ap.macho.create_synthetic(architecture="x86_64"))

    fat = tmp_path / "fat"
    result = ap.macho.create_universal([slim_a, slim_b], fat)
    assert result["arch_count"] == 2
    assert ap.path_type(fat) == "macho"
