#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Assert the accepted implementation scope and unchanged unrelated issue records."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime

from cases import APP, ROOT

BASE = "01879167f2f6b7ace2a286987a14a2104a48f912"
ISSUE = "lck-phase-8c-move-utxos-xxl"
# Fixed reference fixtures. Never derive
# these expected values from HEAD, the index, or the current fixture bytes.
FIXTURE_DIGESTS = {
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


def check_lifecycle(original, current):
    changed = {k for k in original.keys() | current.keys() if original.get(k) != current.get(k)}
    assert changed <= {"status", "updated_at", "closed_at", "close_reason"}, "only claim/closure fields may change"
    assert original["status"] == "open" and current["status"] in ["in_progress", "closed"], "claim/closure status"

    def date(value):
        assert isinstance(value, str), "lifecycle timestamp type"
        try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError: raise AssertionError("lifecycle timestamp format") from None
        assert parsed.tzinfo is not None, "lifecycle timestamp zone"
        return parsed

    updated = date(current["updated_at"])
    assert updated >= date(original["updated_at"]), "lifecycle update order"
    if current["status"] == "closed":
        assert current.get("closed_at") and isinstance(current.get("close_reason"), str), "populated closure"
        closed = date(current["closed_at"])
        assert date(original["updated_at"]) <= closed <= updated, "closure timestamp order"
        assert current["close_reason"].strip(), "nonempty closure reason"
    else:
        assert not current.get("closed_at") and not current.get("close_reason"), "in-progress closure fields"


def main():
    allowed = {"README.md", "AGENTS.md", ".beads/issues.jsonl"}
    # Move integration and latest-only evidence maintenance.
    allowed |= {"packages/cyberkrill/" + p for p in [
        "Cyberkrill/App.lean",  # Move registration, ordered parser and ordinary writer dispatch.
        "Cyberkrill/MoveUtxos.lean",  # Exact lookup, stable selection, local fee, validation.
        "Cyberkrill/PsbtCommands.lean",  # Export existing fiat grammar; creation behavior unchanged.
        "CyberkrillTests.lean", "CyberkrillTests/MoveUtxos.lean",  # Registered move checks and client injection.
        "test/move-utxos.py", "test/move-utxos-mutations.py",  # Handler replay and compiled detecting edits.
        "test/move-utxos-provenance.json",  # Pinned source and actual reference capture bindings.
        "test/scope.py", "test/validate.py", "test/verify.py",  # Phase scope, registration, source count.
        "test/rpc-client.py",  # Replay new real Core responses alongside the original 90.
        "test/rpc-recording-cases.json",  # Named new overshoot request only.
        "test/generate-rpc-recordings.py",  # Additional exact request in the new case only.
        "test/rpc-recordings.py",  # Independent new-case shape and inventory.
        "test/recordings/move-unclamped.json",  # New real Core no-clamp success; old cases untouched.
        "test/list-utxos-mutations.py", "test/list-utxos-lexical-mutations.py",
        "test/rpc-client-mutations.py",  # Finite full-suite allowance for the added move replay.
        "test/offline-mutate.py",  # Measured full-suite allowance and retained timeout diagnostics.
        "test/evidence.py",  # Atomic replacement with latest-run content only.
        "test/evidence_history.py",  # Remove the obsolete nested-history writer.
        "test/list-utxos-lifecycle.py",  # Remove old-run snapshot preservation.
        "test/mutate.py",  # Publish refreshed App/test bindings with latest-run records.
        "test/lightning-mutate.py",  # Publish refreshed App/test bindings with latest-run records.
        "test/revision-mutate.py",  # Publish refreshed parser/scope bindings with latest-run records.
        "test/refresh-regressions.py",  # Replace the regression record on each refresh.
        "test/output-regressions.py",  # Replace the output record on each refresh.
        "test/refresh-attached-output.py",  # Replace the attached-output record on each refresh.
        "test/psbt-commands-mutations.py",  # Replace the creation record on each completed campaign.

    ]}
    allowed |= {"packages/cyberkrill/test/golden/" + p for p in [
        "move-utxos-reference.json", "move-utxos-mutation-record.json",  # Actual new captures and compiled reds.
        "psbt-commands-mutation-record.json",  # Actual App/test-registration/client-source refresh.
        "mutation-record.json", "lightning-mutation-record.json", "revision-mutation-record.json",
        "offline-mutation-record.json", "rpc-client-mutation-record.json",
        "list-utxos-mutation-record.json", "list-utxos-lexical-mutation-record.json",
        "list-utxos-lifecycle-record.json",  # Actual amended-source lifecycle replay.
        "regression-refresh.json", "output-regression-refresh.json", "attached-output-refresh.json",
        "offline-history-recapture.json",  # Actual App/test/phase-boundary refreshes.
        "offline-validation.json",  # Remove obsolete prior-attempt notes only.
    ]}
    changed = set(filter(None, git("diff", BASE, "--name-only", "-z").decode().split("\0")))
    new = set(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    base_paths = set(git("ls-tree", "-r", "--name-only", BASE).decode().splitlines())
    assert changed | new <= allowed, "path outside move command scope: " + repr(sorted((changed | new) - allowed))
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
    def raw_issues(data):
        return {json.loads(line)["id"]: line for line in data.splitlines(keepends=True)}
    original_raw = raw_issues(git("show", BASE + ":.beads/issues.jsonl"))
    # Check original export bytes independently of parsed lifecycle fields.
    with (ROOT / ".beads/issues.jsonl").open("rb") as exported:
        current_raw = raw_issues(exported.read())
    assert all(original_raw[k] == current_raw[k] for k in original_raw if k != ISSUE), "unrelated raw issue bytes changed"
    amended = current[ISSUE]
    check_lifecycle(original[ISSUE], amended)
    # Reference captures and fixture provenance remain fixed.
    for path, expected in FIXTURE_DIGESTS.items():
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
    original_flake = git("show", BASE + ":flake.nix").decode()
    assert flake == original_flake, "landed flake and network isolation contract unchanged"
    for relative in base_paths:
        if relative in allowed:
            continue
        path = ROOT / relative
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        assert data == git("show", BASE + ":" + relative), "forbidden path changed: " + relative
    assert git("diff", "--check", BASE) == b""
    assert git("diff", "--cached", "--check") == b""
    public_paths = (changed | new) - {".beads/issues.jsonl"}
    prohibited = re.compile(r"/(?:home|Users|root|tmp|var/tmp|nix/store)/|/run/(?:user)/|(?<![A-Za-z])[A-Za-z]:[\\/]")
    attribution = re.compile(r"\bco[d]ex\b|\bclau[d]e\b|\bg[p]t-[0-9]|\bchat[g]pt\b|\bgr[o]k\b|\bfa[b]le\b|\bop[u]s\b|\bas[t]ra\b|Co-auth[o]red-by:", re.I)
    header = "Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the"
    for relative in public_paths:
        if not (ROOT / relative).exists(): continue
        text = (ROOT / relative).read_text(encoding="utf-8")
        # README retains earlier historical text: audit its additions only.
        if relative == "README.md":
            text = "\n".join(line[1:] for line in git("diff", BASE, "--", relative).decode().splitlines()
                             if line.startswith("+") and not line.startswith("+++"))
        assert not prohibited.search(text), "private path in: " + relative
        assert not attribution.search(text), "tool attribution in: " + relative
        if Path(relative).suffix in [".lean", ".py", ".c"]:
            assert any(header in line for line in text.splitlines()[:4]), "authored file licence header: " + relative
    print(f"scope: {len(changed | new)} allowed paths; 58/58 unrelated issues unchanged; claim/closure valid")
    print("reference captures/fixtures unchanged; seven packages/link gates retained; whitespace/public-text checks passed")


if __name__ == "__main__":
    main()
