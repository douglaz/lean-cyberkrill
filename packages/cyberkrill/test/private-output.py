#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Published-entropy dispatch checks for private creation and named refusals."""
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tempfile

from cases import APP, ROOT
from compare import Comparator

TEST = APP / ".lake/build/bin/CyberkrillTests"
EXISTS = "outputPathExists: Refusing an existing output path\n"
FAILURE = "outputFailure: Cannot write output\n"


def run(path, *, mask=0o022, limited=False, nul=False):
    def prepare():
        os.umask(mask)
        if limited:
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1))
    proc = subprocess.run([str(TEST), "--private-output-nul" if nul else "--private-output", str(path)],
                          cwd=APP, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=30, preexec_fn=prepare)
    assert proc.returncode == 0 and proc.stderr == b"", "private output dispatch completed"
    result = json.loads(proc.stdout)
    assert set(result) == {"status", "stdout_empty", "stderr"}, "private output result fields"
    assert result["stdout_empty"], "private output stdout remains empty"
    return dict(status=result["status"], stdout="", stderr=result["stderr"])


def main(only="all"):
    with tempfile.TemporaryDirectory(prefix="private-output-", dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)
        if only in ["all", "mode"]:
            row = json.loads((ROOT / "packages/bitcoin/test-data/bip39-english-vectors.json").read_bytes())[0]
            for mask in [0, 0o022]:
                target = root / f"new-{mask}.json"
                result = run(target, mask=mask)
                assert result == dict(status=0, stdout="", stderr=""), "private output new file success"
                assert stat.S_IMODE(target.stat().st_mode) == 0o600, "private output mode 0600"
                assert target.stat().st_uid == os.geteuid(), "private output file owner"
                assert json.loads(target.read_bytes()) == dict(mnemonic=row["mnemonic"], words=12, entropy_bits=128), "private output published JSON"
            print("private output new files: 2/2; mode 0600, owner and exact published JSON")
        if only in ["all", "exclusive"]:
            target = root / "existing.json"
            target.write_bytes(b"public-sentinel")
            result = run(target)
            assert result == dict(status=1, stdout="", stderr=EXISTS), "private output exclusive create"
            assert target.read_bytes() == b"public-sentinel", "private output existing contents preserved"
            print("private output exclusive creation: 1/1")
        if only in ["all", "write-errors"]:
            target = root / "limited.json"
            result = run(target, limited=True)
            assert result == dict(status=1, stdout="", stderr=FAILURE), "private output write failure"
            assert target.stat().st_size == 1 and stat.S_IMODE(target.stat().st_mode) == 0o600, "private output partial file remains private"
            print("private output write failures: 1/1; partial file stays private")
        if only in ["all", "trailing-existing"]:
            target = root / "existing-directory"
            target.mkdir()
            assert run(str(target) + "/") == dict(status=1, stdout="", stderr=EXISTS), "private output existing trailing slash"
            assert list(target.iterdir()) == [], "private output trailing directory untouched"
            print("private output existing trailing slash: 1/1")
        if only in ["all", "trailing-missing"]:
            target = root / "missing-directory"
            assert run(str(target) + "/") == dict(status=1, stdout="", stderr=FAILURE), "private output missing trailing slash"
            assert not target.exists(), "private output missing trailing path untouched"
            print("private output missing trailing slash: 1/1")
        if only == "all":
            refs = json.loads((APP / "test/golden/private-output-reference.json").read_bytes())
            kinds = [row["kind"] for row in refs["cases"]]
            assert kinds == ["regular", "symlink", "dangling-symlink", "hardlink", "device"], "private output golden inventory"
            for row in refs["cases"]:
                kind = row["kind"]
                target = root / kind
                backing = root / (kind + "-backing")
                if kind == "regular":
                    target.write_bytes(b"public-sentinel")
                elif kind in ["symlink", "hardlink"]:
                    backing.write_bytes(b"public-sentinel")
                    if kind == "symlink": target.symlink_to(backing)
                    else: os.link(backing, target)
                elif kind == "dangling-symlink": target.symlink_to(backing)
                else: target = Path("/dev/null")
                comparator = Comparator(refusals=[dict(case=row["id"], reference_status=0,
                    reference_stdout="", reference_stderr="", port_status=1, port_stderr=EXISTS, error="outputPathExists")])
                comparator.compare(dict(id=row["id"], mode="failure"), row["reference"], run(target))
                comparator.finish()
                if kind == "regular": assert target.read_bytes() == b"public-sentinel", "private output regular untouched"
                if kind in ["symlink", "hardlink"]: assert backing.read_bytes() == b"public-sentinel", "private output link target untouched"
                if kind == "dangling-symlink": assert target.is_symlink() and not backing.exists(), "private output dangling link untouched"
            for kind in ["directory", "fifo"]:
                target = root / kind
                if kind == "directory": target.mkdir()
                else: os.mkfifo(target)
                assert run(target) == dict(status=1, stdout="", stderr=EXISTS), "private output special path refused"
            target = root / "nul-prefix"
            assert run(target, nul=True) == dict(status=1, stdout="", stderr=FAILURE), "private output NUL refused"
            assert not target.exists(), "private output NUL prefix untouched"
            print("private output named-refusal goldens: 5/5; directory/fifo/NUL boundaries: 3/3")


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) == 2 else "all"
    assert name in ["all", "mode", "exclusive", "write-errors", "trailing-existing", "trailing-missing"] and len(sys.argv) <= 2
    main(name)
