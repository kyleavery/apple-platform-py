"""The interactive-prompt guard: upstream would prompt on a terminal for a
missing p12 password; embedded in a host process that would hang. The native
layer must reject such requests instead."""

import subprocess
import sys
import textwrap

import pytest

import apple_platform as ap


def test_p12_without_password_is_rejected(tmp_path):
    cert = ap.certificates.generate_self_signed(person_name="Guard Test")
    p12_file = tmp_path / "signer.p12"
    p12_file.write_bytes(cert.to_p12(password="secret"))
    exe = tmp_path / "exe"
    exe.write_bytes(ap.macho.create_synthetic())

    with pytest.raises(ap.errors.InteractiveInputRequiredError) as exc_info:
        ap.sign(
            exe,
            signer=ap.Signer(p12=ap.P12Key(path=p12_file)),
            timestamp_url="none",
        )
    assert "password" in exc_info.value.message


def test_p12_without_password_never_hangs_without_tty(tmp_path):
    """Belt and braces: run the same request in a subprocess with stdin closed
    and require a prompt-free, prompt-fast failure."""
    script = textwrap.dedent(
        """
        import sys
        import apple_platform as ap

        cert = ap.certificates.generate_self_signed(person_name="Guard Test")
        p12_file = sys.argv[1] + "/signer.p12"
        with open(p12_file, "wb") as fh:
            fh.write(cert.to_p12(password="secret"))
        exe = sys.argv[1] + "/exe"
        with open(exe, "wb") as fh:
            fh.write(ap.macho.create_synthetic())

        try:
            ap.sign(exe, signer=ap.Signer(p12=ap.P12Key(path=p12_file)),
                    timestamp_url="none")
        except ap.errors.InteractiveInputRequiredError:
            sys.exit(42)
        sys.exit(1)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 42, proc.stderr.decode()
