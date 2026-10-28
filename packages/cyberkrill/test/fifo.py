#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""One FIFO consumer must receive the complete decoder output before EOF."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cases import APP
from compare import differences, exact_json


def main(commands=None):
    commands = commands or ["ln-decode-invoice", "ln-decode-lnurl"]
    assert commands and all(c in ["ln-decode-invoice", "ln-decode-lnurl"] for c in commands)
    rows = {r["id"]: r for r in json.loads((APP / "test/golden/lightning-reference.json").read_bytes())}
    cases = {"ln-decode-invoice": rows["valid/L410"],
             "ln-decode-lnurl": rows["lnurl-positive/limit-1022"]}
    with tempfile.TemporaryDirectory(prefix="lightning-fifo-", dir=os.environ["TMPDIR"]) as directory:
        path = Path(directory) / "output.fifo"
        for command in commands:
            os.mkfifo(path)
            children = []
            try:
                reader = subprocess.Popen([sys.executable, "-I", "-c",
                    "import sys; f=open(sys.argv[1], 'rb'); sys.stdout.buffer.write(f.read()); f.close()",
                    str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                children.append(reader)
                row = cases[command]
                writer = subprocess.Popen([str(APP / ".lake/build/bin/cyberkrill"), *row["args"], "-o", str(path)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                children.append(writer)
                try:
                    data, error = reader.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    raise AssertionError("FIFO reader completion: " + command) from None
                assert reader.returncode == 0 and not error, "FIFO reader status: " + command
                assert data, "FIFO output bytes before EOF: " + command
                assert not differences(exact_json(row["result"]["stdout"]), exact_json(data)), "FIFO JSON value: " + command
                assert not data.endswith(b"\n"), "FIFO output newline: " + command
                try:
                    out, err = writer.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    raise AssertionError("FIFO writer completion: " + command) from None
                assert writer.returncode == 0 and out == err == b"", "FIFO writer status/streams: " + command
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)
                path.unlink()
    print(f"decoder FIFO consumers: {len(commands)}/{len(commands)}; complete JSON before EOF")


if __name__ == "__main__":
    main(sys.argv[1:] or None)
