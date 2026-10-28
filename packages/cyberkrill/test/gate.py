#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Run a foreground gate with the repository's complete supervisor."""
import pathlib
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]


def main():
    instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    start = instructions.index("POSIXLY_CORRECT=y\n")
    end = instructions.index("\n```", start)
    wrapper = instructions[start:end]
    assert wrapper.count("<gate>") == 1
    command = shlex.join(sys.argv[1:])
    assert command
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc"],
        input=wrapper.replace("<gate>", command), text=True, cwd=ROOT,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
