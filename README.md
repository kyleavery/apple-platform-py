# apple-platform-py

[![CI](https://github.com/kyleavery/apple-platform-py/actions/workflows/ci.yml/badge.svg)](https://github.com/kyleavery/apple-platform-py/actions/workflows/ci.yml)

Apple code signing, notarization, and packaging for Python — anywhere, no
Xcode required. A ctypes SDK over a purpose-built C ABI for
[apple-platform-rs](https://github.com/indygreg/apple-platform-rs) (the
`rcodesign` project), shipped as self-contained wheels.

- **Zero Python dependencies** (stdlib ctypes; one `py3-none-<platform>`
  wheel covers every CPython ≥ 3.9)
- **Sign** Mach-O binaries (files or in-memory bytes), bundles, DMGs, and
  XAR installers with p12/PEM/keychain/Windows-store/smartcard/remote keys
- **Notarize & staple** via Apple's notary service
- **Inspect** code signatures, bundles, DMGs, and .pkg installers
- Works on macOS, Linux, and Windows

```bash
pip install apple-platform-py
```

## Quick start

```python
import apple_platform as ap

# Sign an app bundle with a PKCS#12 certificate
ap.sign(
    "MyApp.app",
    signer=ap.Signer(p12=ap.P12Key(path="signer.p12", password="secret")),
    binary_identifier="com.example.myapp",
    for_notarization=True,
)

# Inspect the result
entities = ap.read_signature("MyApp.app")
print(ap.code_directory_identifier(entities))

# Notarize and staple
from apple_platform import notarize
creds = notarize.NotaryCredentials(api_key_path="appstoreconnect-key.json")
submission = notarize.submit("MyApp.app", creds, wait_seconds=600)
notarize.staple("MyApp.app")
```

More:

```python
# Ad-hoc sign raw Mach-O bytes, no files involved
signed = ap.sign_macho_bytes(macho_bytes, binary_identifier="com.example.tool")

# Per-scope settings (mirrors rcodesign's config file 1:1)
ap.sign(
    "MyApp.app",
    signer=signer,
    paths={
        "@main": ap.PathSettings(entitlements_xml_file="app.entitlements"),
        "Contents/MacOS/helper": ap.PathSettings(binary_identifier="com.example.helper"),
    },
)

# Anything upstream supports that these dataclasses don't model yet:
print(ap.config_schema())          # field names straight from upstream
ap.sign_raw({...})                 # verbatim request escape hatch

# Certificates and packaging
cert = ap.certificates.generate_self_signed(person_name="CI")  # testing only
info = ap.packaging.pkg_info("Installer.pkg")
ap.packaging.dmg_create("dist/", "MyApp.dmg", volume_label="MyApp")
```

Errors raise typed exceptions (`apple_platform.errors.*`) carrying the
native status code, a stable kind label, and the upstream error chain.
Upstream log output is forwarded to the `apple_platform.rust` logger —
enable with `ap.set_log_level("info")`.

## Limitations

| Area | Status |
| --- | --- |
| `.pkg` creation | Not supported upstream — inspect/extract/sign only |
| `dmg_create` | FAT32-backed DMGs (CI/testing utility, not an hdiutil replacement) |
| DMG extraction | Adc/Bzlib/Lzfse chunk codecs unsupported |
| `verify_macho` | Advisory, per upstream — not Apple's verifier |
| Smartcard signing | Compiled out of released wheels; build sdist with `--features smartcard` |
| Windows | `win_amd64` wheels (no ARM64); `windows_store` signing is Windows-only, `macos_keychain` macOS-only |
| Paths | Arbitrary OS bytes for the paths you operate on; signer/settings file paths inside the config must be UTF-8 (upstream's format), and names *inside* bundles are handled lossily by upstream |

## Provenance

`apple_platform.versions()` reports the exact upstream commit, tag, and
crate versions the native library was built from. The sdist vendors the
complete apple-platform-rs source (MPL-2.0 compliance); see `NOTICE`.

Wrapper code is Apache-2.0. See [MAINTAINING.md](MAINTAINING.md) for the
upstream-update playbook (schema tripwires make pin bumps a
one-command-then-review affair).
