# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
# Synthetic constructions; parser expectations are hand-derived from cyberkrill
# 27cad1faba86260b06665a89f0af5134d23525c2, fedimint-lite/src/lib.rs:99-284.
"""Build deterministic synthetic bytes and independently checksummed strings."""
import argparse
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / "test-data"
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
ZERO = "00" * 32
ONE = "11" * 32


def big(n):
    if n < 253:
        return bytes([n])
    width, tag = (2, 253) if n < 65536 else (4, 254) if n < 2**32 else (8, 255)
    return bytes([tag]) + n.to_bytes(width, "big")


def text(s):
    b = s.encode("utf-8")
    return big(len(b)) + b


def guardian(peer=0, url="hi"):
    b = text(url) + big(peer)
    return b"\x00" + big(len(b)) + b


def federation(s=ZERO):
    return b"\x01\x20" + bytes.fromhex(s)


def secret(s):
    return b"\x02" + text(s)


def parts(*ps, count=None):
    return big(len(ps) if count is None else count) + b"".join(ps)


def invite(gs=None, fid=ZERO, api=None):
    return dict(federation_id=fid, guardians=[dict(peer_id=p, url=u) for p, u in (gs or [(0, "hi")])],
                api_secret=api)


def consensus(inv):
    ps = [guardian(g["peer_id"], g["url"]) for g in inv["guardians"]]
    if inv["federation_id"]:
        ps.append(federation(inv["federation_id"]))
    if inv["api_secret"] is not None:
        ps.append(secret(inv["api_secret"]))
    return parts(*ps)


def symbols(b):
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return [int(bits[i:i+5], 2) for i in range(0, len(bits), 5)]


def wrap(b=None, *, ds=None, hrp="fed1", variant=0x2bc830a3):
    ds = symbols(b) if ds is None else ds
    chk = 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for v in expanded + ds + [0] * 6:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i, gen in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> i) & 1:
                chk ^= gen
    chk ^= variant
    return hrp + "1" + "".join(ALPHABET[x] for x in ds + [(chk >> (5 * i)) & 31 for i in range(5, -1, -1)])


def make():
    rows = []

    def add(group, name, op, source, expected):
        rows.append(dict(group=group, name=name, op=op, input=source, expected=expected))

    def dec(group, name, b, inv):
        add(group, name, "consensus", b.hex(), dict(ok=inv))

    def err(group, name, b, kind, *details):
        add(group, name, "consensus", b.hex(), dict(error=kind, details=list(details)))

    basic = parts(guardian(), federation())
    model = invite()
    values = [0, 1, 252, 253, 254, 255, 256, 65535, 65536, 4294967295, 4294967296, 2**64-1]
    expected = ["00", "01", "fc", "fd00fd", "fd00fe", "fd00ff", "fd0100", "fdffff", "fe00010000",
                "feffffffff", "ff0000000100000000", "ffffffffffffffffff"]
    assert len(values) == len(expected) == 12
    for n, hx in zip(values, expected):
        assert big(n).hex() == hx
        add("bigsize", str(n), "bigsize", n, dict(hex=hx, consumed=len(bytes.fromhex(hx))))
    for tag, width in [(253, 2), (254, 4), (255, 8)]:
        for available in range(width):
            err("bigsize-truncated", f"{width}-{available}", bytes([tag]) + bytes(available),
                "truncatedBigSize", width, available)
        add("bigsize-lax", str(width), "read-bigsize", (bytes([tag]) + (1).to_bytes(width, "big")).hex(),
            dict(value=1, consumed=width+1))
    dec("lax", "nonminimal", bytes.fromhex("fd0002") + basic[1:], model)
    dec("lax", "peer-truncation", parts(guardian(65536), federation()), model)
    dec("lax", "unknown-stop", parts(guardian(), federation(), b"\x09\xff"), model)
    dec("lax", "trailing", basic + b"\xff\xff", model)
    dec("parts", "stable-duplicates", parts(guardian(1, "a"), guardian(0, "x"), guardian(1, "b"), federation()),
        invite([(0, "x"), (1, "a"), (1, "b")]))
    dec("parts", "unsorted", parts(guardian(2, "a"), guardian(0, "b"), guardian(1, "c"), federation()),
        invite([(0, "b"), (1, "c"), (2, "a")]))
    dec("parts", "last-federation", parts(guardian(), federation(), federation(ONE)), invite(fid=ONE))
    dec("parts", "last-secret", parts(guardian(), federation(), secret("old"), secret("new")), invite(api="new"))
    dec("parts", "nonminimal-url-length", parts(b"\x00\x06\xfd\x00\x02hi\x00", federation()), model)
    dec("parts", "nonminimal-peer", parts(b"\x00\x06\x02hi\xfd\x00\x00", federation()), model)
    err("parts", "unknown-first", parts(b"\x09", guardian(), federation()), "missingFederation")
    err("parts", "unknown-before-id", parts(guardian(), b"\x09", federation()), "missingFederation")
    err("errors", "missing-id", parts(guardian()), "missingFederation")
    err("errors", "no-guardian", parts(federation()), "noGuardian")
    err("errors", "premature-count", parts(guardian(), count=2), "unexpectedPart", 1)
    err("errors", "empty", b"", "truncatedBigSize", 1, 0)
    err("errors", "tag", b"\xfd", "truncatedBigSize", 2, 0)
    err("errors", "id-length", parts(b"\x01\x1f" + bytes(31)), "federationLength", 31)
    err("errors", "id-truncated", parts(b"\x01\x20" + bytes(31)), "overrun", "federation", 32, 31)
    err("errors", "url-utf8", parts(b"\x00\x03\x01\xff\x00", federation()), "invalidUtf8", "url")
    err("errors", "secret-utf8", parts(guardian(), federation(), b"\x02\x01\xff"), "invalidUtf8", "secret")
    err("errors", "url-overrun", parts(b"\x00\x02\x05a"), "overrun", "url", 5, 1)
    err("errors", "secret-overrun", parts(b"\x02\x05a"), "overrun", "secret", 5, 1)
    err("errors", "guardian-length", parts(b"\x00\x03\x00\x00", federation()), "guardianLength", 3, 2)
    err("errors", "whole-buffer", parts(b"\x00\x00\x02hi\x00", federation()), "guardianLength", 0, 4)
    for name, inv in [("absent-secret", model), ("empty-secret", invite(api="")),
                      ("empty-url", invite([(0, "")])), ("opaque", invite([(0, "opaque value")])),
                      ("unicode", invite([(253, "λ☃")], api="雪🦀")),
                      ("encode-order", invite([(2, "a"), (0, "b")])),
                      ("empty-id", invite(fid=""))]:
        decoded = dict(inv, federation_id=inv["federation_id"].lower(),
                       guardians=sorted(inv["guardians"], key=lambda g: g["peer_id"]))
        result = dict(ok=decoded) if inv["federation_id"] else dict(error="missingFederation", details=[])
        add("encoding", name, "encode", inv,
            dict(hex=consensus(inv).hex(), string=wrap(consensus(inv)), decoded=result))
    no_guardian = dict(federation_id=ZERO, guardians=[], api_secret=None)
    add("encoding", "no-guardian", "encode", no_guardian,
        dict(hex=consensus(no_guardian).hex(), string=wrap(consensus(no_guardian)),
             decoded=dict(error="noGuardian", details=[])))
    for name, fid, kind, details in [("bad-hex", "z"*64, "invalidHex", []),
                                      ("odd-hex", "a", "invalidHex", []),
                                      ("short-id", "ab", "federationLength", [1])]:
        add("encoding", name, "encode-error", invite(fid=fid), dict(error=kind, details=details))
    for name, fid in [("upper-hex", "AB"*32), ("mixed-hex", "aB"*32)]:
        inv = invite(fid=fid)
        add("encoding", name, "encode", inv,
            dict(hex=consensus(inv).hex(), string=wrap(consensus(inv)),
                 decoded=dict(ok=invite(fid=fid.lower()))))
        dec("normalization", name, consensus(inv), invite(fid=fid.lower()))
    valid = wrap(basic)
    for name, s in [("ascii-space", " \t\r\n" + valid + "\n "),
                    ("unicode-space", "\u0085\u00a0\u1680\u2007" + valid + "\u2028\u2029\u202f\u205f\u3000"),
                    ("plain", valid)]:
        add("wrapper", name, "decode", s, dict(ok=model))
    for name, s, kind, details in [
        ("uppercase", valid.upper(), "prefix", []),
        ("mixed-case", valid[:10] + valid[10].upper() + valid[11:], "bech32.mixedCase", []),
        ("wrong-hrp", wrap(basic, hrp="fed1x"), "wrongHrp", ["fed1x"]),
        ("wrong-variant", wrap(basic, variant=1), "wrongVariant", []),
        ("bad-checksum", valid[:-1] + ("q" if valid[-1] != "q" else "p"), "bech32.checksumMismatch", []),
        ("consensus-truncation", wrap(b"\x02\x00"), "truncatedBigSize", [1, 0])]:
        add("wrapper", name, "decode", s, dict(error=kind, details=details))
    ds = symbols(basic)
    assert len(basic) == 41 and len(ds)*5-len(basic)*8 == 2
    nonzero = ds[:-1] + [ds[-1] | 1]
    for name, data in [("nonzero-padding", nonzero), ("extra-symbol", ds + [31])]:
        add("padding", name, "decode", wrap(ds=data), dict(ok=model))
    for size, url_size in [(632, 589), (633, 590)]:
        inv = invite([(0, "x"*url_size)])
        b = consensus(inv)
        s = wrap(b)  # Deliberately bypasses the production wrapper's cap.
        assert len(b) == size and len(s) == size + 391
        add("boundaries", str(size), "boundary", inv,
            dict(hex=b.hex(), string=s, byte_length=size, string_length=len(s)))
    counts = {g: sum(r["group"] == g for r in rows) for g in dict.fromkeys(r["group"] for r in rows)}
    pinned = {"bigsize": 12, "bigsize-truncated": 14, "bigsize-lax": 3, "lax": 4, "parts": 8,
              "errors": 13, "encoding": 13, "normalization": 2, "wrapper": 9, "padding": 2, "boundaries": 2}
    assert counts == pinned, counts
    assert len(rows) == 82
    return dict(counts=pinned, rows=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = make()
    path = DATA / "synthetic.json"
    if args.write:
        path.write_text(json.dumps(expected, indent=2, ensure_ascii=False) + "\n")
    else:
        assert json.loads(path.read_text()) == expected
    print("synthetic vectors: 82/82; " + "; ".join(f"{g}: {n}/{n}" for g, n in expected["counts"].items()))


if __name__ == "__main__":
    main()
