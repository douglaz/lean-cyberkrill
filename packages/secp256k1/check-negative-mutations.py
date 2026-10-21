#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Run one production mutation per negative property; always restore the adapter.

Run from this package inside nix develop. Logs stay under the ignored .lake tree.
The recid mutations deliberately expose libsecp256k1's abort; disable core dumps.
"""
import json
from pathlib import Path
import resource
import subprocess


def cases():
    yield "tampered signature", "verify"
    for kind in ["wrong-length", "off-curve"]:
        for operation in ["parse", "verify"]:
            yield f"{kind} key {operation}", operation
    for recid in [4, 255]:
        yield f"recid {recid}", "recid"
    for length in [0, 31, 33]:
        for operation in ["verify", "recover", "sign"]:
            yield f"{operation} hash length {length}", operation
        yield f"sign secret length {length}", "sign"
    for length in [0, 63, 65]:
        for operation in ["verify", "recover"]:
            yield f"{operation} signature length {length}", operation
    for scalar in ["zero", "order", "overflow"]:
        for operation in ["verify", "recover"]:
            for component in ["r", "s"]:
                yield f"{operation} {component} {scalar}", operation
        yield f"sign secret {scalar}", "sign"
    for operation in ["parse", "verify"]:
        yield f"invalid prefix {operation}", operation


def mutate(original, operation):
    if operation == "recid":
        old = " || recid > 3"
        assert original.count(old) == 1
        return original.replace(old, "")
    name = "pubkey_parse" if operation == "parse" else operation
    start = original.index(f"lck_secp_{name}(")
    position = original.index("{", start) + 1
    # Deliberately accept bad input in this operation only. The test and its
    # expected value are untouched; selecting one test isolates the property.
    broken = "\n    return 1;" if operation in ["parse", "verify"] else (
        "\n    return some_bytes((const unsigned char *)\"\", 0);")
    return original[:position] + broken + original[position:]


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    adapter = Path("link_shim.c")
    original = adapter.read_text()
    logs = Path(".lake/mutation-checks")
    logs.mkdir(parents=True, exist_ok=True)
    records = []
    try:
        for index, (name, operation) in enumerate(cases(), 1):
            mutated = mutate(original, operation)
            assert mutated != original
            adapter.write_text(mutated)
            assert adapter.read_text() == mutated
            command = ["lake", "test", "--", "--negative", name]
            stdout = logs / f"{index:02}.stdout"
            stderr = logs / f"{index:02}.stderr"
            with stdout.open("wb") as out, stderr.open("wb") as err:
                result = subprocess.run(command, stdout=out, stderr=err)
            output = stdout.read_text() + stderr.read_text()
            expected = ("illegal argument: recid >= 0 && recid <= 3" if operation == "recid"
                        else f"assertion failed: {name}")
            assert result.returncode != 0, (name, "mutation survived", output)
            assert expected in output, (name, "wrong failure", output)
            records.append({"property": name, "mutation": operation,
                            "command": command, "exit": result.returncode,
                            "failure": expected})
            print(f"{name}: EXIT={result.returncode}; {expected}", flush=True)
            adapter.write_text(original)
            assert adapter.read_text() == original
    finally:
        adapter.write_text(original)
        assert adapter.read_text() == original
    (logs / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"negative mutations: {len(records)}/{len(list(cases()))} detected; adapter restored")


if __name__ == "__main__":
    main()
