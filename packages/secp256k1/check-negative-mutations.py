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
import sys


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
    yield "x-only off-curve", "xonly_pubkey_parse"
    yield "DER empty", "der_signature_parse"


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
    broken = "\n    return 1;" if operation in ["parse", "verify", "xonly_pubkey_parse", "der_signature_parse"] else (
        "\n    return some_bytes((const unsigned char *)\"\", 0);")
    return original[:position] + broken + original[position:]


def compression_cases():
    for name in ["uncompressed", "compressed identity"]:
        yield name, "uncompressed-result"
    yield "matching hybrid", "strict-prefix"
    for name in ["mismatched hybrid", "33 prefix 4", "33 prefix 6", "33 prefix 7",
                 "65 prefix 2", "65 prefix 3", "length 0", "length 32", "length 34",
                 "length 64", "length 66", "off-curve compressed", "off-curve uncompressed"]:
        yield name, "early-some"
    for name in ["strict matching hybrid", "strict mismatched hybrid"]:
        yield name, "strict-accept"


def mutate_compression(original, operation):
    start = original.index("lck_secp_compress_pubkey(")
    end = original.index("\n}\n", start) + 3
    body = original[start:end]
    if operation == "strict-accept":
        return mutate(original, "parse")
    if operation == "early-some":
        pos = body.index("{") + 1
        body = body[:pos] + '\n    return some_bytes((const unsigned char *)"", 0);' + body[pos:]
    elif operation == "strict-prefix":
        old = "    secp256k1_pubkey parsed;"
        assert body.count(old) == 1
        body = body.replace(old, "    if (input_len == 65 && lean_sarray_cptr(key)[0] != 4) return lean_box(0);\n" + old)
    elif operation == "uncompressed-result":
        # Supply the larger buffer required by that serialization mode, so the
        # failure is the tested result, never libsecp256k1's buffer assertion.
        assert body.count("unsigned char bytes[33];") == 1
        assert body.count("SECP256K1_EC_COMPRESSED") == 1
        body = body.replace("unsigned char bytes[33];", "unsigned char bytes[65];")
        body = body.replace("SECP256K1_EC_COMPRESSED", "SECP256K1_EC_UNCOMPRESSED")
    elif operation == "no-length-guard":
        old = "    if (input_len != 33 && input_len != 65) return lean_box(0);\n"
        assert body.count(old) == 1
        body = body.replace(old, "")
    else:
        raise AssertionError(operation)
    return original[:start] + body + original[end:]


def compression_mutations(adapter, original):
    logs = Path(".lake/compression-mutation-checks")
    logs.mkdir(parents=True, exist_ok=True)
    records = []
    try:
        for index, (name, operation) in enumerate(compression_cases(), 1):
            assert adapter.read_text() == original
            changed = mutate_compression(original, operation)
            adapter.write_text(changed)
            assert adapter.read_text() == changed
            command = ["lake", "test", "--", "--compression", name]
            stdout, stderr = logs / f"{index:02}.stdout", logs / f"{index:02}.stderr"
            with stdout.open("wb") as out, stderr.open("wb") as err:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            output = stdout.read_text() + stderr.read_text()
            expected = "assertion failed: compression " + name
            assert result.returncode == 1 and expected in output, (name, output)
            records.append(dict(property=name, mutation=operation, command=command,
                                exit=result.returncode, failure=expected))
            print(f"compression {name}: EXIT={result.returncode}; {expected}", flush=True)
            adapter.write_text(original)
            assert adapter.read_text() == original
        # libsecp256k1 already checks these lengths. Measure the redundant guard
        # removal without counting a surviving mutation as a detected property.
        changed = mutate_compression(original, "no-length-guard")
        adapter.write_text(changed)
        command = ["lake", "test"]
        with (logs / "no-length-guard.stdout").open("wb") as out, \
                (logs / "no-length-guard.stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        assert result.returncode == 0
        records.append(dict(property="length guard redundancy", mutation="no-length-guard",
                            command=command, exit=result.returncode, detected=False))
    finally:
        adapter.write_text(original)
        assert adapter.read_text() == original
    (logs / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print("compression mutations: 18/18 detected; removing length guard: EXIT=0; adapter restored")


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    adapter = Path("link_shim.c")
    original = adapter.read_text()
    if sys.argv[1:] == ["--compression-only"]:
        compression_mutations(adapter, original)
        return
    assert not sys.argv[1:]
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
    compression_mutations(adapter, original)


if __name__ == "__main__":
    main()
