# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Derive 39 published PSBT inputs and capture the pinned CLI offline.

python3 -I packages/bitcoin/capture-cyberkrill-psbt.py [--check]
--check checks the committed record against freshly derived bytes and captures.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PACKAGE = Path(__file__).resolve().parent
REV = "27cad1faba86260b06665a89f0af5134d23525c2"
REF = "github:douglaz/cyberkrill/" + REV
DEST = PACKAGE / "test-data/cyberkrill-psbt-capture.json"


def compact(n):
    if n < 253:
        return bytes([n])
    size, tag = (2, 253) if n <= 65535 else (4, 254)
    return bytes([tag]) + n.to_bytes(size, "little")


def maps(raw):
    assert raw[:5] == b"psbt\xff"
    pos = 5

    def number():
        nonlocal pos
        tag = raw[pos]
        pos += 1
        if tag < 253:
            return tag
        size = {253: 2, 254: 4, 255: 8}[tag]
        n = int.from_bytes(raw[pos:pos + size], "little")
        pos += size
        return n

    def vector(n):
        nonlocal pos
        value = raw[pos:pos + n]
        assert len(value) == n
        pos += n
        return value

    result = []
    while pos < len(raw):
        records = []
        while True:
            n = number()
            if n == 0:
                break
            key = vector(n)
            value = vector(number())
            records.append((key, value))
        result.append(records)
    assert pos == len(raw)
    return result


def encode(groups):
    return b"psbt\xff" + b"".join(
        b"".join(compact(len(k)) + k + compact(len(v)) + v for k, v in group) + b"\0"
        for group in groups)


def vectors():
    source = (PACKAGE / "Bitcoin/PsbtVectors.lean").read_text()
    sets = {}
    for name in ["bip174Valid", "bip371Valid", "bip370Invalid"]:
        body = source.split("def " + name + " :", 1)[1].split("\n]", 1)[0]
        rows = re.findall(r'^  \(("(?:[^"\\]|\\.)*"), "([0-9a-f]+)", "([^"]+)"\)', body, re.M)
        sets[name] = []
        for label, raw, text in rows:
            assert bytes.fromhex(raw) == base64.b64decode(text, validate=True)
            sets[name].append((json.loads(label), bytes.fromhex(raw)))
    return sets


def derive():
    sets = vectors()
    labels = {
        "xpub": ("bip174Valid", "PSBT with `PSBT_GLOBAL_XPUB`."),
        "partial": ("bip174Valid", "PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature."),
        "key": ("bip371Valid", "PSBT with one P2TR key only input with internal key, its derivation path, and signature"),
        "script": ("bip371Valid", "PSBT with one P2TR script path only input with dummy internal key, scripts, script key derivation paths, merkle root, and script path signatures"),
        "tree": ("bip371Valid", "PSBT with one P2TR script path only output with dummy internal key, taproot tree, and script key derivation paths"),
    }
    rows = []

    def add(name, cls, base, edit="unchanged", group=None, kind=None, change=None, extra=None):
        vector_set, label = labels[base]
        matches = [raw for title, raw in sets[vector_set] if title == label]
        assert len(matches) == 1, label
        raw = matches[0]
        before = maps(raw)
        after = copy.deepcopy(before)
        if extra is not None:
            assert all(k != extra[0] for k, _ in after[1])
            after[1].append(extra)
            assert after[1][:-1] == before[1] and len(after[1]) == len(before[1]) + 1
            assert after[:1] == before[:1] and after[2:] == before[2:]
        elif change is not None:
            indices = [i for i, (k, _) in enumerate(after[group]) if k[0] == kind]
            assert indices
            index = indices[0]
            after[group][index] = change(*after[group][index])
            differences = [(g, i) for g in range(len(before)) for i in range(len(before[g]))
                           if before[g][i] != after[g][i]]
            assert differences == [(group, index)], differences
        else:
            assert after == before
        encoded = encode(after)
        assert encode(before) == raw and maps(encoded) == after
        assert (encoded != raw) == (change is not None or extra is not None)
        rows.append(dict(name=name, **{"class": cls}, vector_set=vector_set,
                         base=label, edit=edit, input_base64=base64.b64encode(encoded).decode()))

    reject, accept, stricter = "must-reject", "must-accept", "port-stricter"
    def value_last(n):
        return lambda k, v: (k, v[:-1] + bytes([n]))
    def version(n):
        return lambda k, v: (k[:1] + bytes.fromhex(n) + k[5:], v)
    def control(n):
        return lambda k, v: (k[:1] + bytes([n | (k[1] & 1)]) + k[2:], v)
    def tree(n):
        return lambda k, v: (k, v[:1] + bytes([n]) + v[2:])
    def prop(n):
        return (bytes.fromhex("fc014100") + bytes(n), b"\0")

    add("xpub-version", reject, "xpub", "global xpub version -> 04b24746", 0, 1, version("04b24746"))
    add("partial-sig-sighash", reject, "partial", "input 0 partial signature last byte -> 04", 1, 2, value_last(4))
    add("partial-sig-empty", reject, "partial", "input 0 partial signature -> empty", 1, 2, lambda k, v: (k, b""))
    for name, base, kind in [("tap-key-sig-sighash", "key", 19), ("tap-script-sig-sighash", "script", 20)]:
        add(name, reject, base, "input 0 first signature -> first 64 bytes + 04", 1, kind,
            lambda k, v: (k, v[:64] + b"\x04"))
    for name, n in [("leaf-script-odd", 193), ("leaf-script-annex", 80)]:
        add(name, reject, "script", f"input 0 first leaf-script last byte -> {n:02x}", 1, 21, value_last(n))
    add("control-block-annex", reject, "script", "input 0 first control byte -> 50 OR parity", 1, 21, control(80))
    add("out-tap-tree-annex", reject, "tree", "output 0 first tree leaf version -> 50", 2, 6, tree(80))
    add("proprietary-1025", reject, "partial", "input 0 add fc014100 + 1025 zeros, value 00", extra=prop(1025))
    for base in labels:
        add("base-" + base, accept, base)
    add("partial-sig-83", accept, "partial", "input 0 partial signature last byte -> 83", 1, 2, value_last(131))
    for n in [0, 131]:
        add(f"tap-key-sig-{n:02x}", accept, "key", f"input 0 key signature + {n:02x}", 1, 19,
            lambda k, v, n=n: (k, v + bytes([n])))
    add("leaf-script-c2", accept, "script", "input 0 first leaf-script last byte -> c2", 1, 21, value_last(194))
    add("out-tap-tree-c2", accept, "tree", "output 0 first tree leaf version -> c2", 2, 6, tree(194))
    add("control-block-c2", accept, "script", "input 0 first control byte -> c2 OR parity", 1, 21, control(194))
    add("tpub", accept, "xpub", "global xpub version -> 043587cf", 0, 1, version("043587cf"))
    add("proprietary-1024", accept, "partial", "input 0 add fc014100 + 1024 zeros, value 00", extra=prop(1024))
    for name, key in [("key-type-fd01", "fd01"), ("key-type-fd0500", "fd0500"),
                      ("proprietary-subtype-fd01", "fc0141fd01")]:
        add(name, stricter, "partial", f"input 0 add key {key}, value 00", extra=(bytes.fromhex(key), b"\0"))
    add("xpub-depth", stricter, "xpub", "global xpub depth XOR 1", 0, 1,
        lambda k, v: (k[:5] + bytes([k[5] ^ 1]) + k[6:], v))
    for index in range(1, 13):
        title, raw = sets["bip370Invalid"][index]
        assert title.startswith("PSBTv0 but with PSBT_")
        labels["v2-field"] = ("bip370Invalid", title)
        add(f"bip370-invalid-{index}", stricter, "v2-field")
    assert len(rows) == 39 and len({r["name"] for r in rows}) == 39
    assert [sum(r["class"] == c for r in rows) for c in [reject, accept, stricter]] == [10, 13, 16]
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows = derive()
    # Resolve with the caller's HOME and fetcher cache, before network isolation.
    binary = Path(subprocess.check_output(["nix", "build", "--no-link", "--print-out-paths",
                  "--max-jobs", "2", "--cores", "4", REF], text=True).strip()) / "bin/cyberkrill"
    unshare, sh, ip = [shutil.which(name) for name in ["unshare", "sh", "ip"]]
    assert unshare and sh and ip and binary.is_file()
    with tempfile.TemporaryDirectory(prefix="cyberkrill-psbt-") as workspace:
        for row in rows:
            home = Path(workspace) / row["name"]
            home.mkdir()
            env = dict(HOME=str(home), TMPDIR=str(home), PATH=os.defpath, LANG="C", LC_ALL="C", TZ="UTC")
            result = subprocess.run([unshare, "-rn", sh, "-c",
                '"$1" link set lo up && exec "$2" onchain-decode-psbt', "capture", ip, str(binary)],
                input=row["input_base64"] + "\n", text=True, capture_output=True,
                cwd=home, env=env, timeout=60)
            row.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
            assert str(home) not in result.stdout + result.stderr
            assert str(binary.parent.parent) not in result.stdout + result.stderr
            print(f'{row["name"]}: {row["class"]}; EXIT={result.returncode}', flush=True)
    assert not Path(workspace).exists()
    record = dict(reference=REF, revision=REV, rows=rows)
    if args.check:
        assert json.loads(DEST.read_text()) == record, "capture differs"
    else:
        DEST.write_text(json.dumps(record, indent=2) + "\n")
    print("PSBT capture: 39/39; temporary workspace removed")


if __name__ == "__main__":
    main()
