# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Capture or verify the three pinned, published invite examples offline."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

PIN = "27cad1faba86260b06665a89f0af5134d23525c2"
BUILD = ["nix", "build", "--no-link", "--print-out-paths", "--max-jobs", "2",
         "--cores", "4", f"github:douglaz/cyberkrill/{PIN}"]
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "test-data"
PUBLISHED = "fed11qgqzxgthwden5te0v9cxjtnzd96xxmmfdckhqunfde3kjurvv4ejucm0d5hsqqfqkggx3jz0tvfv5n7lj0e7gs7nh47z06ry95x4963wfh8xlka7a80su3952t"
EXAMPLES = [
    {"federation_id": "b21068c84f5b12ca4fdf93f3e443d3bd7c27e8642d0d52ea2e4dce6fdbbee9df",
     "guardians": [{"peer_id": 0, "url": "wss://api.bitcoin-principles.com/"}], "api_secret": None},
    {"federation_id": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
     "guardians": [{"peer_id": i, "url": f"wss://guardian{i+1}.example.com/"} for i in range(2)],
     "api_secret": "super_secret_api_key"},
    {"federation_id": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
     "guardians": [{"peer_id": i, "url": f"wss://{name}.example.com/"}
                   for i, name in enumerate(["alpha", "beta", "gamma"])], "api_secret": None},
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    result = subprocess.run(BUILD, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    print(f"reference build exit: {result.returncode}")
    if result.returncode:
        raise SystemExit(result.returncode)
    paths = result.stdout.splitlines()
    assert len(paths) == 1
    executable = str(Path(paths[0]) / "bin" / "cyberkrill")
    rows = []
    commands = []
    with tempfile.TemporaryDirectory(prefix="invite-capture-", dir=os.environ["TMPDIR"]) as scratch:
        home = Path(scratch) / "home"
        home.mkdir()
        env = os.environ.copy()
        env["HOME"] = str(home)

        def offline(*command):
            start = time.monotonic()
            p = subprocess.run(["unshare", "-rn", "sh", "-c",
                                'ip link set lo up && exec "$@"', "sh", executable, *command],
                               env=env, capture_output=True, text=True)
            assert p.returncode == 0, (command[0], p.returncode, p.stderr)
            commands.append(dict(command=[command[0], "$INPUT_JSON" if command[0] == "fm-encode-invite"
                                          else "$INVITE"], exit=p.returncode,
                                 wall_seconds=round(time.monotonic() - start, 3),
                                 stdout=p.stdout.splitlines(), stderr=p.stderr.splitlines()))
            return p.stdout

        for index, expected in enumerate(EXAMPLES):
            source = Path(scratch) / f"input-{index}.json"
            source.write_text(json.dumps(expected) + "\n")
            encoded = offline("fm-encode-invite", str(source)).strip()
            if index == 0:
                assert encoded == PUBLISHED
            decoded = json.loads(offline("fm-decode-invite", PUBLISHED if index == 0 else encoded))
            assert decoded == expected, (index, decoded)
            rows.append({"encoded": encoded, "decoded": decoded})
    assert len(rows) == 3
    if args.capture:
        DATA.mkdir(exist_ok=True)
        for index in [1, 2]:
            (DATA / f"input-{index + 1}.json").write_text(json.dumps(EXAMPLES[index], indent=2) + "\n")
        (DATA / "primary.json").write_text(json.dumps(rows, indent=2) + "\n")
    else:
        assert json.loads((DATA / "primary.json").read_text()) == rows
        for index in [1, 2]:
            assert json.loads((DATA / f"input-{index + 1}.json").read_text()) == EXAMPLES[index]
    (DATA / "capture-record.json").write_text(json.dumps(dict(build_command=BUILD, build_exit=0,
        primary_count=3, namespace="unshare -rn; loopback up; isolated HOME", commands=commands), indent=2) + "\n")
    print("primary vectors: 3/3; exact strings and parsed JSON fields; isolated offline execution")


if __name__ == "__main__":
    main()
