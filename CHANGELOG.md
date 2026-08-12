# Changelog

## 0.1.0 (August 11, 2026)

Initial release.

- C ABI (`apple_platform_*`, ABI v1, 30 symbols) over apple-platform-rs,
  pinned at upstream tag `apple-codesign/0.29.0`
- Python ctypes SDK (`apple_platform`), stdlib-only:
  - signing: files, bundles, DMGs, XAR; in-memory Mach-O; ad-hoc through
    p12/PEM/DER/keychain/remote key sources; scoped per-path settings
  - reading: `path_type`, verbatim `SignatureReader` entities, advisory
    Mach-O verification
  - notarization: submit/wait/log/list + stapling
  - certificates: self-signed generation, analysis, PKCS#12 parse/create
  - packaging: bundle info/files, DMG info/extract/create, pkg info/extract
  - Mach-O utilities: synthetic binaries, universal (fat) assembly
- Non-UTF-8 path support: path arguments accept `str`/`bytes`/`os.PathLike`
  and cross the boundary as OS-native bytes (`{"__path_bytes__": ...}` in
  JSON); response paths that are not UTF-8 no longer panic the native
  library. Upstream-owned config paths (signer files, settings files) remain
  UTF-8 and fail early with field-named errors
- Windows: `windows_store` signer requests are validated up front (bad store
  names and unmatched fingerprints error instead of panicking or silently
  ad-hoc signing)
- Wheels tagged `py3-none-<platform>` (macOS arm64/x86_64, manylinux
  x86_64/aarch64, Windows x86_64); sdist vendors complete upstream source
  (MPL-2.0)
