# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Require the library scan to reject an otherwise unused private theorem's axiom."""
import json
from pathlib import Path
import signal
import subprocess
import time

PACKAGE = Path(__file__).resolve().parent
SOURCE = PACKAGE / "FedimintInvite/ConsensusProofs.lean"
LOGS = PACKAGE / ".lake/invite-axiom-check"
RECORD = PACKAGE / "test-data/axiom-gate.json"


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def run(label):
    command = ["lake", "test"]
    start = time.monotonic()
    with (LOGS / (label + ".stdout")).open("w") as out, (LOGS / (label + ".stderr")).open("w") as err:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    return dict(command=command, exit=result.returncode, wall_seconds=round(time.monotonic()-start, 3)), \
        (LOGS / (label + ".stdout")).read_text(), (LOGS / (label + ".stderr")).read_text()


def main():
    for signum in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
        signal.signal(signum, stop)
    LOGS.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_bytes()
    old = "end FedimintInvite"
    new = "axiom libraryGateProbe : False\nprivate theorem rejectedPrivateHelper : False := libraryGateProbe\n\nend FedimintInvite"
    text = original.decode()
    assert text.count(old) == 1
    try:
        SOURCE.write_text(text.replace(old, new))
        red, stdout, stderr = run("red")
        assert red["exit"] == 1
        failures = [(stream, line) for stream, text in [("stdout", stdout), ("stderr", stderr)]
                    for line in text.splitlines() if "reaches disallowed axiom" in line]
        assert len(failures) == 1 and "rejectedPrivateHelper" in failures[0][1] and \
            "FedimintInvite.libraryGateProbe" in failures[0][1], (stdout, stderr)
        red["diagnostic_stream"], red["diagnostic"] = failures[0]
    finally:
        SOURCE.write_bytes(original)
        assert SOURCE.read_bytes() == original
    green, stdout, stderr = run("restored")
    assert green["exit"] == 0, (stdout, stderr)
    assert SOURCE.read_bytes() == original
    assert RECORD.resolve() != Path(__file__).resolve()
    RECORD.write_text(json.dumps(dict(count=1, source="FedimintInvite/ConsensusProofs.lean",
        production_edit=dict(old=old, new=new), red=red, restored=green), indent=2) + "\n")
    print("private-library axiom rejection: 1/1; red EXIT=1; restored lake test EXIT=0")
    print(red["diagnostic"])


if __name__ == "__main__":
    main()
