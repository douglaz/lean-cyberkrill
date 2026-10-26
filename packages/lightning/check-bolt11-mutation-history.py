# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Simulate a committed proof-era record without moving HEAD or changing history."""
import json
from pathlib import Path
import runpy
import subprocess
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parent
BASE = "730c23ae4481e4f66e05b633a70d510e1594d96b"
RECORD = "packages/lightning/test-data/bolt11-mutations.json"


def main():
    original = subprocess.run(
        ["git", "show", f"{BASE}:{RECORD}"], cwd=PACKAGE, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    expected = {entry["mutation"]: entry for entry in json.loads(original)}
    assert len(expected) == 21
    current = (PACKAGE / "test-data/bolt11-mutations.json").read_bytes()
    post_acceptance = json.loads(current)
    assert len(post_acceptance) > 21
    assert all(entry.get("historical_runtime") == expected.get(entry["mutation"])
               for entry in post_acceptance), "fixture must retain original runtime objects"
    harness = runpy.run_path(str(PACKAGE / "check-bolt11-mutations.py"))

    def simulated_show(command, **_kwargs):
        assert command[:2] == ["git", "show"], command
        # HEAD has the current proof-era record after acceptance. The pinned base
        # still has the original runtime objects. Neither is written by this test.
        revisions = {f"HEAD:{RECORD}": current, f"{BASE}:{RECORD}": original}
        return subprocess.CompletedProcess(command, 0, revisions[command[2]], b"")

    with patch.object(subprocess, "run", side_effect=simulated_show):
        prior = harness["historical_runtime"]()
    assert prior == expected, "post-acceptance history must preserve exactly 21 original runtime objects"
    assert all(prior.get(entry["mutation"]) == entry.get("historical_runtime")
               for entry in post_acceptance), "new labels must have no historical runtime evidence"
    print("BOLT11 historical runtime: 21/21 exact original objects; new labels: no history")


if __name__ == "__main__":
    main()
