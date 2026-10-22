# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent inventory of published PSBT wire transactions and preimages.

python3 -I audit-psbt-vectors.py [--write]
Reads only the copied BIP vector lists, uses hashlib for txids, records every
malformed transaction or unavailable map boundary explicitly. No network access.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

PACKAGE = Path(__file__).resolve().parent


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n > len(self.data) - self.pos:
            raise ValueError("truncated")
        b = self.data[self.pos:self.pos+n]
        self.pos += n
        return b

    def compact(self):
        tag = self.take(1)[0]
        if tag < 253:
            return tag
        n = int.from_bytes(self.take({253: 2, 254: 4, 255: 8}[tag]), "little")
        if n < {253: 253, 254: 65536, 255: 4294967296}[tag]:
            raise ValueError("noncanonical CompactSize")
        return n

    def vector(self):
        return self.take(self.compact())

    def map(self):
        records = []
        while True:
            key = self.vector()
            if not key:
                return records
            records.append((key, self.vector()))


def transaction(data, witness, inventory_only_superfluous=False):
    r = Reader(data)
    version = r.take(4)
    n = r.compact()
    flags = 0
    if not n and witness:
        flags = r.take(1)[0]
        n = r.compact() if flags else 0
    inputs = []
    start = r.pos
    for _ in range(n):
        prev = r.take(32)
        r.take(4)
        r.vector()
        r.take(4)
        inputs.append(prev)
    input_bytes = r.data[start:r.pos]
    out_start = r.pos
    outputs = r.compact() if not (witness and not n and not flags) else 0
    for _ in range(outputs):
        r.take(8)
        r.vector()
    output_bytes = r.data[out_start:r.pos]
    if flags % 2:
        stacks = [[r.vector() for _ in range(r.compact())] for _ in range(n)]
        if all(not s for s in stacks) and not inventory_only_superfluous:
            raise ValueError("superfluous witness")
    if flags // 2:
        raise ValueError("unknown flags")
    locktime = r.take(4)
    if r.pos != len(data):
        raise ValueError("trailing data")
    # Published transactions here have counts below 253; check before encoding.
    assert n < 253
    if flags:
        stripped = version + bytes([n]) + input_bytes + output_bytes + locktime
    else:
        stripped = data
    return inputs, hashlib.sha256(hashlib.sha256(stripped).digest()).digest()


def vectors():
    source = (PACKAGE / "Bitcoin/PsbtVectors.lean").read_text()
    for match in re.finditer(r"^def (\w+).*?:= \[\n(.*?)\n\]", source, re.M | re.S):
        name, body = match.groups()
        for i, line in enumerate(body.splitlines()):
            strings = re.findall(r'"(?:[^"\\]|\\.)*"', line)
            if strings:
                assert len(strings) == 3, (name, i)
                title, raw, _ = map(json.loads, strings)
                yield name, i, title, bytes.fromhex(raw)


def inventory():
    rows, problems, frames = [], [], []
    preimages = {"10": 0, "12": 0}
    all_map_preimages = {"10": 0, "12": 0}
    raw_records = 0
    scan_errors = []
    vector_count = 0
    txids = 0
    for name, index, _title, raw in vectors():
        vector_count += 1
        label = f"{name}[{index}]"
        if not raw.startswith(b"psbt\xff"):
            transaction(raw, True)
            rows.append(dict(vector=name, index=index, scope="network", map=0, record=0, allowWitness=True))
            continue
        # Also scan without map-count or field validation, including maps in
        # vectors whose missing global fields prevent assigning a scope. A
        # zero count over this superset proves zero input preimage records.
        scanner = Reader(raw)
        scanner.take(5)
        try:
            while scanner.pos < len(raw):
                key = scanner.vector()
                if not key:
                    continue
                raw_records += 1
                kind = Reader(key).compact()
                if kind in [10, 12]:
                    all_map_preimages[str(kind)] += 1
                scanner.vector()
        except ValueError as error:
            scan_errors.append(dict(vector=label, error=str(error), offset=scanner.pos))
        r = Reader(raw)
        r.take(5)
        try:
            global_map = r.map()
        except ValueError as error:
            frames.append(dict(vector=label, error=str(error), stage="global"))
            continue
        unsigned, prevouts = None, None
        counts = None
        for j, (key, value) in enumerate(global_map):
            if key[0] == 0:
                try:
                    prevouts, _ = transaction(value, False)
                    unsigned = value
                    # Read output count independently after the input vector.
                    t = Reader(value)
                    t.take(4)
                    for _ in range(t.compact()):
                        t.take(36); t.vector(); t.take(4)
                    counts = (len(prevouts), t.compact())
                    rows.append(dict(vector=name, index=index, scope="global", map=0, record=j, allowWitness=False))
                except ValueError as error:
                    problems.append(dict(vector=label, scope="global", record=j, error=str(error)))
        if counts is None:
            fields = dict(global_map)
            if b"\x04" in fields and b"\x05" in fields:
                counts = (Reader(fields[b"\x04"]).compact(), Reader(fields[b"\x05"]).compact())
        if counts is None:
            frames.append(dict(vector=label, error="no transaction/map counts", stage="counts"))
            # Published invalid examples still contain transaction bytes. Their
            # missing/forbidden globals cannot supply normal map counts. Record
            # the exceptional boundary source explicitly instead of dropping
            # their input records. BIP174 invalid[3] has one non-witness input
            # map after its empty global map; [18] has a witness unsigned tx.
            if (name, index) == ("bip174Invalid", 3):
                counts = (1, 0)
            elif (name, index) == ("bip174Invalid", 18):
                witness_value = next(v for k, v in global_map if k == b"\x00")
                # This deliberately invalid unsigned tx also has superfluous
                # witness encoding. Only the inventory's prevout extraction
                # permits it; it is never counted as a parseable transaction.
                prevouts, _ = transaction(witness_value, True, inventory_only_superfluous=True)
                unsigned = witness_value
                counts = (1, 2)
            elif (name, index) in [("bip370Invalid", 14), ("bip370Invalid", 15)]:
                counts = (1, 2)
            else:
                continue
        input_maps = []
        try:
            for i in range(counts[0]):
                input_maps.append(r.map())
            for _ in range(counts[1]):
                r.map()
        except ValueError as error:
            frames.append(dict(vector=label, error=str(error), stage="maps"))
        for i, m in enumerate(input_maps):
            for j, (key, value) in enumerate(m):
                kind = Reader(key).compact()
                if kind in [10, 12]:
                    preimages[str(kind)] += 1
                if kind != 0:
                    continue
                try:
                    _, digest = transaction(value, True)
                    expected = prevouts[i] if unsigned is not None else dict(m).get(b"\x0e")
                    equal = digest == expected
                    if not equal:
                        problems.append(dict(vector=label, scope="input", map=i, record=j,
                                             error="previous txid unavailable" if expected is None else "txid mismatch"))
                    rows.append(dict(vector=name, index=index, scope="input", map=i, record=j,
                                     allowWitness=True, txidMatches=equal))
                    txids += 1
                except ValueError as error:
                    problems.append(dict(vector=label, scope="input", map=i, record=j, error=str(error)))
    return dict(vectorCount=vector_count, transactionCount=len(rows), txidCount=txids,
                preimageRecords=preimages, allMapPreimageRecords=all_map_preimages,
                rawRecordCount=raw_records, rawScanErrors=scan_errors, transactionProblems=problems,
                unavailableFrames=frames, transactions=rows)


def main():
    result = inventory()
    path = PACKAGE / "test-data/psbt-inventory.json"
    data = json.dumps(result, indent=2) + "\n"
    if sys.argv[1:] == ["--write"]:
        path.write_text(data)
    else:
        assert not sys.argv[1:]
        assert path.read_text() == data
    summary = {k: v for k, v in result.items() if k != "transactions"}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
