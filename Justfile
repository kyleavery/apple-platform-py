# Development workflow. `just --list` for a summary.

python := ".venv/bin/python"

# Build the release cdylib
build:
    cargo build --release

# Run Rust unit + spike tests
test-rust:
    cargo test --release -p apple-platform-ffi

# Reinstall the package in editable mode (rebuilds the cdylib)
install:
    {{python}} -m pip install --force-reinstall -e .

# Full Python test suite (wheel + repo tiers)
test-py:
    {{python}} -m pytest tests/ -q

# Everything CI runs locally
test: test-rust install test-py header-check

# Regenerate the committed C header
header:
    cbindgen --config crates/apple-platform-ffi/cbindgen.toml \
        --crate apple-platform-ffi \
        --output include/apple_platform.h crates/apple-platform-ffi

# Fail if the committed header is stale
header-check: header
    git diff --exit-code include/apple_platform.h

# Lint
lint:
    cargo fmt --check -p apple-platform-ffi
    cargo clippy --release -p apple-platform-ffi --no-deps -- -D warnings

# Accept an intended upstream config-schema change
snapshot-update:
    {{python}} -m pytest tests/repo/test_schema_snapshot.py --snapshot-update -q

# Move the upstream pin (e.g. `just update-upstream apple-codesign/0.30.0`)
update-upstream ref:
    {{python}} scripts/update_upstream.py {{ref}}

# Build a wheel into dist/
wheel:
    {{python}} -m pip wheel --no-deps -w dist .
