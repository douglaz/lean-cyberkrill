#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Assert the accepted implementation scope and unchanged unrelated issue records."""
import json
import hashlib
from pathlib import Path
import re
import subprocess

from cases import APP, ROOT

BASE = "fc8ded46acc899c6b94a88bc27fa824f0b61dd13"
ISSUE = "lck-phase-7a-app-skeleton-yx7"
# Fixed observations for fixtures first introduced by this phase. Never derive
# these expected values from HEAD, the index, or the current fixture bytes.
HISTORICAL_DIGESTS = {
    "regression-record.json": "679f3cb08ecb804ea9b46572254c56a22e766599fc8c650b780eb7e125bdf336",
    "output-regression-record.json": "c0fa1d361be244360425341420975fab01e8f013198dfa59f48b41f5db7a930f",
    "attached-output-regression-record.json": "451f10beafae7da7bce1c83d3e09f7181567dbc6389e409e79a1229b723483ca",
    "reference.json": "1e7958dae384cc6811f6ab42d2b7b1a8549a0abee4ae441017b104e89d2004b0",
    "provenance.json": "a1632beec123567b9af6f4835038e8e20598055bfa27f0fdbb167e2f0524dcc3",
    "capture-digests.json": "df828cadece40a7a6a028863660384548de4efa488198373e3076c343e431bf6",
    "fixture-digests.json": "789f783531c438c3934468497016c1e930e699c162e1851ede23561b1377dbbb",
}


def git(*args):
    p = subprocess.run(["git", *args], cwd=ROOT, stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=30)
    assert p.returncode == 0, "scope git command failed: " + " ".join(args)
    return p.stdout


def main():
    allowed = {"README.md", "plan.md", ".beads/issues.jsonl", "flake.nix", "flake.lock", ".github/workflows/ci.yml"}
    changed = set(git("diff", BASE, "--name-only", "-z").decode().strip("\0").split("\0"))
    new = set(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    for path in changed | new:
        assert path in allowed or path.startswith("packages/cyberkrill/"), "unrelated changed path: " + path
    # Equality against the base for each unrelated issue includes every field.
    def issues(data):
        rows = [json.loads(line) for line in data.splitlines()]
        result = {row["id"]: row for row in rows}
        assert len(rows) == len(result) == 59, "issue inventory"
        return result
    original = issues(git("show", BASE + ":.beads/issues.jsonl"))
    current = issues((ROOT / ".beads/issues.jsonl").read_bytes())
    assert original.keys() == current.keys(), "issue identity set"
    assert all(original[k] == current[k] for k in original if k != ISSUE), "unrelated issue changed"
    claim_changes = {k for k in original[ISSUE].keys() | current[ISSUE].keys()
                     if original[ISSUE].get(k) != current[ISSUE].get(k)}
    assert claim_changes <= {"status", "updated_at", "closed_at", "close_reason"}, "only claim/closure fields may change"
    assert original[ISSUE]["status"] == "open" and current[ISSUE]["status"] in ["open", "in_progress", "closed"]
    if current[ISSUE]["status"] == "closed":
        assert current[ISSUE].get("closed_at") and current[ISSUE].get("close_reason"), "closure evidence missing"
    # These files must retain the original observations, not refreshed hashes.
    base_paths = set(git("ls-tree", "-r", "--name-only", BASE).decode().splitlines())
    for path, expected in HISTORICAL_DIGESTS.items():
        relative = "packages/cyberkrill/test/golden/" + path
        data = (ROOT / relative).read_bytes()
        if relative in base_paths:
            assert data == git("show", BASE + ":" + relative), "historical fixture changed: " + path
        else:
            assert hashlib.sha256(data).hexdigest() == expected, "historical fixture digest changed: " + path
    flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
    assert 'lakePackages = [ "sha256" "secp256k1" "bitcoin" "lightning" "fedimint-invite" "http-curl" "cyberkrill" ];' in flake
    assert 'lake build && lake test' in flake and 'bash scripts/check-link-spike.sh' in flake
    assert git("diff", BASE, "--", "scripts/check-link-spike.sh", "scripts/check-one-openssl.sh") == b""
    assert git("diff", "--check", BASE) == b""
    assert git("diff", "--cached", "--check") == b""
    public_paths = (changed | new) - {".beads/issues.jsonl"}
    prohibited = re.compile(r"/(?:home|tmp)/|/run/(?:user)/")
    header = "Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the"
    for relative in public_paths:
        text = (ROOT / relative).read_text(encoding="utf-8")
        # README retains earlier historical text: audit its additions only.
        if relative == "README.md":
            text = "\n".join(line[1:] for line in git("diff", BASE, "--", relative).decode().splitlines()
                             if line.startswith("+") and not line.startswith("+++"))
        assert not prohibited.search(text), "private path in: " + relative
        if Path(relative).suffix in [".lean", ".py", ".c"]:
            assert any(header in line for line in text.splitlines()[:4]), "authored file licence header: " + relative
    print(f"scope: {len(changed | new)} allowed paths; 58/58 unrelated issues unchanged; claim/closure valid")
    print("historical captures/records unchanged; seven packages/link gates retained; whitespace/public-text checks passed")


if __name__ == "__main__":
    main()
