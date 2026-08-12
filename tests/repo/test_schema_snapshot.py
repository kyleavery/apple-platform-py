"""THE upstream-drift tripwire.

``config_schema()`` reflects the field names of upstream's serde config types
out of the compiled library (via their ``deny_unknown_fields`` errors). This
test diffs that against a committed snapshot: when moving the submodule pin,
any added/renamed/removed upstream setting fails here with the exact field
names — each one is usually a one-line dataclass addition in models.py.

To accept intended changes, regenerate the snapshot:

    python -m pytest tests/repo/test_schema_snapshot.py --snapshot-update
"""

import json
from pathlib import Path

import apple_platform as ap

SNAPSHOT = Path(__file__).parent / "data" / "config_schema.json"


def test_config_schema_matches_snapshot(request):
    actual = ap.config_schema()

    if request.config.getoption("--snapshot-update"):
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        return

    assert SNAPSHOT.exists(), (
        f"missing snapshot {SNAPSHOT}; run with --snapshot-update to create it"
    )
    expected = json.loads(SNAPSHOT.read_text())

    if actual != expected:
        lines = ["upstream config schema drifted from the committed snapshot:"]
        for type_name in sorted(set(expected) | set(actual)):
            before = set(expected.get(type_name, []))
            after = set(actual.get(type_name, []))
            for field in sorted(after - before):
                lines.append(f"  {type_name}: NEW field {field!r}")
            for field in sorted(before - after):
                lines.append(f"  {type_name}: REMOVED field {field!r}")
        lines.append(
            "Update models.py/docs accordingly, then refresh with "
            "`pytest tests/repo/test_schema_snapshot.py --snapshot-update`."
        )
        raise AssertionError("\n".join(lines))
