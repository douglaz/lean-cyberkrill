#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Assert the accepted implementation scope and unchanged unrelated issue records."""
import json
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime
from contextlib import redirect_stdout
from unittest.mock import patch

from cases import APP, ROOT

BASE = "6e3bbefbbb954ac391cd04000eca61b0a6b41c04"
ISSUE = "lck-phase-9b-ln-generate-invoice-edn"
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
    allowed = {"README.md", ".beads/issues.jsonl"}
    # LNURL command, pure callback serialization and necessary verification refreshes.
    allowed |= {"packages/lightning/Lightning/Lnurl/Url.lean",
                "packages/lightning/LightningTests/Lnurl.lean"}
    allowed |= {"packages/cyberkrill/" + p for p in [
        "Cyberkrill/App.lean", "Cyberkrill/GenerateInvoice.lean", "Cyberkrill/TestEntry.lean",
        "CyberkrillTests/GenerateInvoice.lean", "CyberkrillTests.lean",
        "test/generate-invoice.py", "test/generate-invoice-mutations.py",
        "test/http/ln-generate.json", "test/http/ln-generate-expected.json",
        "test/http/ln-generate.provenance.json", "test/golden/ln-generate-mutation-record.json",
        "test/scope.py", "test/validate.py", "test/verify.py", "test/network.py", "test/network-safety.py",
        "test/http/mutation-record.json",
    ]}
    allowed |= {"packages/cyberkrill/test/golden/" + p for p in [
        "fiat-onchain-mutation-record.json", "move-utxos-mutation-record.json", "psbt-commands-mutation-record.json",
        "mutation-record.json", "lightning-mutation-record.json", "revision-mutation-record.json",
        "offline-mutation-record.json", "rpc-client-mutation-record.json",
        "list-utxos-mutation-record.json", "list-utxos-lexical-mutation-record.json",
        "list-utxos-lifecycle-record.json",
        "regression-refresh.json", "output-regression-refresh.json",
        "attached-output-refresh.json",
    ]}
    changed = set(filter(None, git("diff", BASE, "--name-only", "-z").decode().split("\0")))
    new = set(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")))
    base_paths = set(git("ls-tree", "-r", "--name-only", BASE).decode().splitlines())
    assert changed | new <= allowed, "path outside invoice generation scope: " + repr(sorted((changed | new) - allowed))
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


def check_admission():
    """Exercise the real gate in read-only views of unrelated source/evidence edits."""
    protected = [
        "Cyberkrill/PriceFeed.lean", "Cyberkrill/Fiat.lean", "Cyberkrill/CoreRpc.lean",
        "Cyberkrill/PsbtCommands.lean", "Cyberkrill/MoveUtxos.lean",
        "CyberkrillTests/PriceFeed.lean", "test/capture-price-reference.py",
        "test/driver.py", "test/http/exact-deltas.json", "test/http/reference.json",
        "test/http/success.json", "test/http/success.json.provenance",
        "test/lightning-mutate.py", "test/list-utxos-lifecycle.py",
        "test/move-utxos.py", "test/mutate.py", "test/price-cases.py",
        "test/price-feeds.py", "test/price-parity.py", "test/recordings/fiat-create.json", "test/recordings/fiat-funded.json",
    ]
    assert len(protected) == len(set(protected)) == 21, "scope protected path inventory"
    real_git, real_bytes, real_text = git, Path.read_bytes, Path.read_text
    checks = 0
    for relative in protected:
        relative = "packages/cyberkrill/" + relative
        target = ROOT / relative
        marker = "\n-- synthetic scope admission edit\n"

        def read_bytes(path):
            return real_bytes(path) + (marker.encode() if path == target else b"")

        def read_text(path, *args, **kwargs):
            return real_text(path, *args, **kwargs) + (marker if path == target else "")

        for reported in [True, False]:
            def virtual_git(*args):
                result = real_git(*args)
                if reported and args == ("diff", BASE, "--name-only", "-z"):
                    return result + relative.encode() + b"\0"
                return result

            expected = ("path outside invoice generation scope: " if reported
                        else "forbidden path changed: ")
            with patch(__name__ + ".git", virtual_git), \
                    patch.object(Path, "read_bytes", read_bytes), \
                    patch.object(Path, "read_text", read_text), redirect_stdout(io.StringIO()):
                try:
                    main()
                except AssertionError as error:
                    assert str(error).startswith(expected) and relative in str(error), \
                        "scope admission wrong rejection: " + str(error)
                else:
                    raise AssertionError("scope admission accepted unrelated edit: " + relative)
            checks += 1
    assert checks == 42, "scope admission check inventory"
    print("scope admission: 42/42 unrelated edits rejected at path/baseline assertions; read-only views")


if __name__ == "__main__":
    main()
    check_admission()
