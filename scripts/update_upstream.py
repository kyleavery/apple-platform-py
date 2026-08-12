#!/usr/bin/env python3
"""Move the apple-platform-rs submodule to a new upstream release and verify
the wrapper end to end.

Usage:
    python scripts/update_upstream.py apple-codesign/0.30.0
    python scripts/update_upstream.py <commit-sha>
    python scripts/update_upstream.py --dry-run apple-codesign/0.29.0

Steps (stops at the first failure):
  1. Fetch upstream and check out the requested tag/commit in the submodule.
  2. Print the "watch list" diff: upstream commits touching the files whose
     shapes this wrapper mirrors by hand.
  3. cargo build --release && cargo test (workspace).
  4. Regenerate include/apple_platform.h with cbindgen and show any drift.
  5. pip install -e . and run the full pytest suite. A schema-snapshot
     failure names exactly the upstream config fields that changed.
  6. Print a changelog stanza template.

Requires: git, cargo, cbindgen on PATH, and a virtualenv python (pass with
--python; defaults to .venv/bin/python).
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SUBMODULE = REPO / "crates" / "apple-platform-rs"

# Files whose JSON-visible shapes or behavior this wrapper mirrors by hand.
# A change here is not automatically an incompatibility, but it must be
# reviewed against crates/apple-platform-ffi/src/ops/*.rs and models.py.
WATCH_LIST = [
    "apple-codesign/src/cli/certificate_source.rs",
    "apple-codesign/src/cli/config.rs",
    "apple-codesign/src/cli/mod.rs",
    "apple-codesign/src/signing_settings.rs",
    "apple-codesign/src/reader.rs",
]


def run(cmd, cwd=REPO, check=True, capture=False):
    print(f"$ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(
        [str(c) for c in cmd],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=capture,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref", help="upstream tag (apple-codesign/X.Y.Z) or commit SHA")
    parser.add_argument("--python", default=str(REPO / ".venv" / "bin" / "python"))
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="verify against the requested ref without expecting changes",
    )
    args = parser.parse_args()

    old = run(
        ["git", "-C", SUBMODULE, "rev-parse", "HEAD"], capture=True
    ).stdout.strip()

    print(f"\n=== 1. Checking out {args.ref} (currently {old[:12]}) ===")
    run(["git", "-C", SUBMODULE, "fetch", "--tags", "origin"])
    run(["git", "-C", SUBMODULE, "checkout", args.ref])
    new = run(
        ["git", "-C", SUBMODULE, "rev-parse", "HEAD"], capture=True
    ).stdout.strip()

    if old == new:
        print("submodule already at the requested ref")
    else:
        print(f"\n=== 2. Watch-list changes {old[:12]}..{new[:12]} ===")
        log = run(
            ["git", "-C", SUBMODULE, "log", "--oneline", f"{old}..{new}", "--"]
            + WATCH_LIST,
            capture=True,
        ).stdout.strip()
        if log:
            print(log)
            print(
                "\n^ REVIEW REQUIRED: these commits touch hand-mirrored "
                "surfaces (ops/sign.rs port, models.py, entity helpers)."
            )
        else:
            print("no watch-list files changed; expect a clean ride")

    print("\n=== 3. Rust build + tests ===")
    run(["cargo", "build", "--release"])
    run(["cargo", "test", "--release", "-p", "apple-platform-ffi"])

    print("\n=== 4. Header drift ===")
    run(
        [
            "cbindgen",
            "--config",
            "crates/apple-platform-ffi/cbindgen.toml",
            "--crate",
            "apple-platform-ffi",
            "--output",
            "include/apple_platform.h",
            "crates/apple-platform-ffi",
        ]
    )
    drift = run(
        ["git", "diff", "--stat", "include/apple_platform.h"], capture=True
    ).stdout.strip()
    print(drift or "header unchanged")

    print("\n=== 5. Python install + full test suite ===")
    run([args.python, "-m", "pip", "install", "--quiet", "--force-reinstall", "-e", "."])
    result = run([args.python, "-m", "pytest", "tests/", "-q"], check=False)
    if result.returncode != 0:
        print(
            "\ntests failed. If only the schema snapshot failed, review the "
            "named fields, extend models.py, then run:\n"
            "  pytest tests/repo/test_schema_snapshot.py --snapshot-update"
        )
        return result.returncode

    if args.dry_run:
        print("\n=== dry run OK ===")
        if old != new:
            print("NOTE: submodule was moved; `git -C crates/apple-platform-rs "
                  f"checkout {old}` to restore")
        return 0

    describe = run(
        ["git", "-C", SUBMODULE, "describe", "--tags", "--always"], capture=True
    ).stdout.strip()
    print(
        "\n=== 6. All green. Finish up: ===\n"
        f"  1. Review `git diff` (Cargo.lock, header, snapshot).\n"
        f"  2. Bump `version` in pyproject.toml + __init__.py (MINOR for a pin move).\n"
        f"  3. Add a CHANGELOG stanza:\n\n"
        f"     ### Changed\n"
        f"     - upstream apple-platform-rs pin: {describe} ({new[:12]})\n\n"
        f"  4. git add -A && git commit"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
