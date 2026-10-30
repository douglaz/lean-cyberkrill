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

BASE = "1d104f4e2cddc5632b50431aef48998e3966521b"
ISSUE = "lck-phase-8a-core-rpc-client-yt0"
# Fixed observations for fixtures first introduced by this phase. Never derive
# these expected values from HEAD, the index, or the current fixture bytes.
HISTORICAL_DIGESTS = {
    "revision-regression-record.json": "60c8074b198e76e211b17deb1cfcec57fc644b0aa1f184356dd846698d135379",
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
    allowed = {"README.md", ".beads/issues.jsonl", "flake.nix"}
    # Exact paths, grouped by their concrete integration responsibility.
    allowed |= {"packages/cyberkrill/" + p for p in [
        "Cyberkrill.lean", "CyberkrillTests.lean", "Cyberkrill/CoreRpc.lean",
        "Cyberkrill/RpcFlags.lean", "CyberkrillTests/Rpc.lean",
        "test/network.py", "test/network-safety.py", "test/rpc-client.py",
        "test/rpc-client-mutations.py", "test/generate-rpc-recordings.py",
        "test/rpc-recordings.py", "test/scope.py", "test/validate.py", "test/revision-mutate.py"]}
    # These current observations are refreshed by their executable mutation suites.
    allowed |= {"packages/cyberkrill/test/golden/" + p for p in [
        "regression-refresh.json", "output-regression-refresh.json", "attached-output-refresh.json",
        "mutation-record.json", "lightning-mutation-record.json", "revision-mutation-record.json",
        "offline-mutation-record.json", "rpc-client-mutation-record.json"]}
    changed = set(filter(None, git("diff", BASE, "--name-only", "-z").decode().split("\0")))
    new = set(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    base_paths = set(git("ls-tree", "-r", "--name-only", BASE).decode().splitlines())
    assert changed | new <= allowed, "path outside Core RPC scope: " + repr(sorted((changed | new) - allowed))
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
    amended = current[ISSUE]
    check_lifecycle(original[ISSUE], amended)
    # These files must retain the original observations, not refreshed hashes.
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
    original_flake = git("show", BASE + ":flake.nix").decode()
    marker = '          export LCK_RPC_SANDBOX=1\n          readlink /proc/self/ns/net > "$NIX_BUILD_TOP/rpc-network-namespace"\n'
    shell_packages = "packages = [ lean pkgs.glibc.bin pkgs.binutils pkgs.python3 pkgs.openssl pkgs.util-linux pkgs.iproute2 ];"
    original_packages = "packages = [ lean pkgs.glibc.bin pkgs.binutils pkgs.python3 pkgs.openssl ];"
    assert flake.count(marker) == 1 and flake.count(shell_packages) == 1, "sandbox-only marker and namespace tools"
    assert flake.replace(marker, "").replace(shell_packages, original_packages) == original_flake, "only network check/dev-shell flake delta"
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
    print("historical captures/records unchanged; seven packages/link gates retained; whitespace/public-text checks passed")


if __name__ == "__main__":
    main()
