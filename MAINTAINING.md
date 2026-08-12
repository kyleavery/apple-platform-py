# Maintaining apple-platform-py

This package is designed so that tracking upstream
[apple-platform-rs](https://github.com/indygreg/apple-platform-rs) is cheap.
This document is the whole playbook.

## How the wrapper stays thin

The load-bearing design decision: the sign request embeds upstream's own
serde config types (`cli::config::SignConfig` — signer sources + per-path
scoped settings) and the implementation reuses upstream's policy functions
(`resolve_certificates`, `load_into_signing_settings`, `load_into_settings`).
Consequences:

- **New upstream settings and key sources flow through with zero wrapper
  changes.** Python users can pass any field upstream accepts via the
  `extra` dict on every dataclass before this SDK models it; discover names
  with `apple_platform.config_schema()`.
- **Output-side JSON is verbatim**: `read_signature` serializes upstream's
  `SignatureReader` entities directly; `pkg_info`'s distribution uses
  upstream's serde model. Their shapes track upstream automatically (which
  is why `reading.find_values` walks instead of hardcoding paths).
- Upstream error variants map through `error.rs::classify()`, whose `_ =>`
  catch-all is **load-bearing** — never make that match exhaustive.

Hand-mirrored surfaces (the only recurring maintenance):

| Wrapper file | Mirrors |
| --- | --- |
| `crates/apple-platform-ffi/src/ops/sign.rs` | `Sign::run` in `apple-codesign/src/cli/mod.rs` (non-scoped args + call order) |
| `src/apple_platform/models.py` | serde field names of `CertificateSource`, key sources, `ScopedSigningSettingsValues` |
| `crates/apple-platform-ffi/src/ops/bundle.rs` | `DirectoryBundle` accessors (no serde upstream) |
| `crates/apple-platform-ffi/src/ops/certs.rs` | `print_certificate_info` field list |
| `crates/apple-platform-ffi/src/ops/read.rs` (`entity_json`) | `FileEntity`'s `path`/`symlink_target` fields (spliced into wire path form; a rename fails loudly as `UpstreamDrift`) |

## Updating the upstream pin

Pin policy: the submodule points at upstream **release tags**
(`apple-codesign/X.Y.Z`). SHA pins work too when cherry-picking a fix.

```bash
just update-upstream apple-codesign/0.30.0
# equivalently: python scripts/update_upstream.py apple-codesign/0.30.0
```

The script: checks out the ref → prints the **watch-list diff** (upstream
commits touching `cli/certificate_source.rs`, `cli/config.rs`, `cli/mod.rs`,
`signing_settings.rs`, `reader.rs`) → `cargo build` + `cargo test` →
regenerates `include/apple_platform.h` → reinstalls and runs the full pytest
suite → prints a changelog stanza.

What failures mean:

- **Schema snapshot test fails** — upstream added/renamed a config field.
  The failure names it exactly. Add one field to the matching dataclass in
  `models.py` (users were never blocked: `extra` already passes it), then
  `just snapshot-update`.
- **Rust compile error** — usually a renamed upstream API or a major-version
  bump of a shared dependency (`x509-certificate`, `serde_yaml`, ...). Align
  the version in `crates/apple-platform-ffi/Cargo.toml`; this failing loudly
  at compile time is intended.
- **Watch-list shows `Sign::run` changes** — re-read it next to
  `ops/sign.rs` (the port is commented step by step) and mirror any new
  non-scoped argument: one serde field + one settings call + one Python
  keyword argument.
- **MSRV bump** — update `rust-toolchain.toml` and, if needed,
  `workspace.package.rust-version`.

## Versioning

- Package: independent SemVer. **MINOR** when the upstream pin moves,
  **PATCH** for wrapper-only fixes, **MAJOR** for Python API breaks.
  Version lives in `pyproject.toml` + `src/apple_platform/__init__.py`.
- C ABI: `APPLE_PLATFORM_ABI_VERSION` bumps only on breaking ABI changes
  (renamed/removed symbols, signature/layout changes). Adding functions or
  error codes is not a break. The Python loader asserts it at import.
- Status codes and their meanings are append-only; never renumber.

## Drift tripwires (all enforced in CI)

1. **Schema snapshot** (`tests/repo/test_schema_snapshot.py`) — upstream
   config-field changes fail with a field-level diff.
2. **Header drift** — CI regenerates `include/apple_platform.h` with
   cbindgen and diffs against the committed copy.
3. **ABI contract** (`tests/wheel/test_abi_contract.py`) — the header's
   symbol set must equal `_native.SIGNATURES`, and every symbol must
   resolve in the loaded library.
4. **Symbol count** — CI checks that `strip = "debuginfo"` kept all 30
   exports, on all three OSes (`nm` on macOS/Linux, `llvm-readobj
   --coff-exports` on Windows — the artifact there is `apple_platform.dll`,
   no `lib` prefix).

## Release checklist

1. `just test && just lint`
2. Bump versions (see above) + CHANGELOG entry.
3. Tag `vX.Y.Z`, push. `wheels.yml` builds macOS arm64/x86_64 +
   manylinux x86_64/aarch64 + Windows x86_64 wheels (tagged
   `py3-none-<plat>` — one wheel covers every CPython) + an sdist vendoring
   the full upstream source (MPL requirement), then publishes via PyPI
   Trusted Publishing. The Windows wheel builds with
   `RUSTFLAGS=-C target-feature=+crt-static`, so it has no
   `vcruntime140.dll` dependency (verify with
   `llvm-readobj --coff-imports` when in doubt).

Note: the `Justfile` hardcodes `.venv/bin/python`, so on Windows run the
underlying commands directly (`.venv\Scripts\python.exe`).

## Licensing

Wrapper code: Apache-2.0. Statically linked upstream crates: MPL-2.0
(apple-codesign and friends) and Apache/MIT (apple-dmg, app-store-connect).
The wheel ships `apple_platform/licenses/`; `NOTICE` records where complete
MPL source lives (pinned submodule + sdist). When adding a new upstream
crate dependency, extend `NOTICE` and `licenses/`.

## Known limitations (documented, not bugs)

- No `.pkg` *builder* upstream — flat packages are inspect/extract/sign-only.
- `dmg_create` produces FAT32-backed DMGs (a CI/testing utility, not an
  hdiutil replacement); DMG extraction returns UNSUPPORTED for
  Adc/Bzlib/Lzfse chunks (upstream would panic).
- `verify_macho` is advisory (upstream's own characterization) — it flags
  ad-hoc signatures' empty CMS blob, for example.
- `smartcard` feature is compiled out of released wheels (build from sdist
  with `--features smartcard` if needed); `macos_keychain` / `windows_store`
  signers error cleanly on other platforms. On Windows, `windows_store`
  requests are pre-validated (store name, fingerprint presence) and an
  unmatched fingerprint errors instead of silently ad-hoc signing.
- Windows wheels are x86_64 only — setuptools-rust has no win-arm64 target
  mapping.
- Paths cross the boundary as OS-native bytes (`os.fsencode`); non-UTF-8
  paths appear in JSON as `{"__path_bytes__": "<base64>"}` in both
  directions. Two residual UTF-8 ceilings, both upstream's: paths inside
  the signer/settings config are serde `String`s (the wrapper rejects
  non-UTF-8 there early, naming the field), and file names *inside* bundles
  go through upstream's lossy `to_string_lossy` handling (`dmg_create`
  rejects non-UTF-8 names in its input tree because upstream would panic).
