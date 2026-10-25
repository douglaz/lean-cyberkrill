# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Reproduce the pinned BOLT11 corpus; signing is restricted to the published example key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

from coincurve import PrivateKey, PublicKey, ecdsa

PACKAGE = Path(__file__).resolve().parent
REVISION = "191462825ae341f0a27098765c075f01ca9bc6c2"
URL = f"https://raw.githubusercontent.com/lightning/bolts/{REVISION}/11-payment-encoding.md"
SPEC_HASH = "c659da1bc08091f7fe691cd4ce661e578dfbe1f77a0b9cd9c53d1839010ae029"
VALID = [382, 410, 438, 466, 491, 516, 554, 579, 602, 625, 648, 682, 704, 707, 735, 762]
INVALID = [792, 814, 821, 824, 827, 830, 833, 836, 839, 842, 845, 848, 851, 854, 858]
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PAYEE = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
HIGH_PAYEE = "02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d"
KEYS = [PAYEE,
        "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
        "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
        "03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pack(words, pad=True):
    bits = "".join(f"{word:05b}" for word in words)
    if pad:
        bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def unpack(data):
    bits = "".join(f"{byte:08b}" for byte in data)
    bits += "0" * (-len(bits) % 5)
    return [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]


def integer(value):
    words = []
    while value:
        words.insert(0, value % 32)
        value //= 32
    return words


def number(words):
    value = 0
    for word in words:
        value = value * 32 + word
    return value


def polymod(words):
    chk = 1
    for word in words:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ word
        for i, gen in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def render(hrp, signed, signature, residue=1):
    data = signed + unpack(signature)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = polymod(expanded + data + [0] * 6) ^ residue
    checksum = [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    result = hrp + "1" + "".join(ALPHABET[w] for w in data + checksum)
    assert polymod(expanded + data + checksum) == residue
    return result


def split(invoice):
    hrp, data = invoice.lower().rsplit("1", 1)
    words = [ALPHABET.index(c) for c in data]
    return hrp, words[:-110], pack(words[-110:-6], False)


def fields(signed):
    result = []
    pos = 7
    while pos < len(signed):
        assert pos + 3 <= len(signed)
        tag, hi, lo = signed[pos:pos + 3]
        length = hi * 32 + lo
        assert pos + 3 + length <= len(signed)
        result.append((tag, signed[pos + 3:pos + 3 + length]))
        pos += 3 + length
    return result


def frame(timestamp, tagged):
    result = list(timestamp)
    for tag, data in tagged:
        assert 0 <= tag < 32 and len(data) <= 1023 and all(0 <= w < 32 for w in data)
        result += [tag, len(data) // 32, len(data) % 32] + data
    return result


def canonical(hrp, signed):
    assert not re.search(r"\D0\d", hrp), hrp
    for tag, data in fields(signed):
        if tag in [5, 6, 24]:
            assert not data or data[0] != 0, (tag, data)
        byte_data = None
        if tag in [13, 27, 3] or (tag in [1, 16, 23] and len(data) == 52) or (tag == 19 and len(data) == 53):
            byte_data = data
        elif tag == 9 and data and data[0] <= 18:
            byte_data = data[1:]
        if byte_data is not None:
            assert unpack(pack(byte_data, False)) == byte_data, (tag, byte_data)


def digest(hrp, signed):
    return sha(hrp.lower().encode("ascii") + pack(signed))


def row(name, invoice, **extras):
    result = dict(name=name, invoice=invoice, **extras)
    if name not in ["L836", "L845"]:
        hrp, signed, signature = split(invoice)
        result.update(hash=digest(hrp, signed), signature=signature.hex())
    return result


def verify(hash_hex, signature, payee=PAYEE):
    der = ecdsa.cdata_to_der(ecdsa.deserialize_compact(signature[:64]))
    return PublicKey(bytes.fromhex(payee)).verify(der, bytes.fromhex(hash_hex), hasher=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without writing fixtures")
    args = parser.parse_args()
    assert Path(os.environ["TMPDIR"]).is_dir(), "TMPDIR must name an existing private directory"
    with urllib.request.urlopen(URL) as response:
        source = response.read()
    assert sha(source) == SPEC_HASH
    lines = source.decode().splitlines()
    assert len(lines) == 868
    key_hex = re.search(r"[0-9a-f]{64}", lines[377])[0]
    key = PrivateKey(bytes.fromhex(key_hex))
    assert key.public_key.format().hex() == PAYEE
    invoices = {line: lines[line].removeprefix("> ").strip().strip("`") for line in VALID + INVALID}
    valid = [row(f"L{line}", invoices[line], line=line, heading=lines[line - 1],
                 pubkey=HIGH_PAYEE if line == 762 else PAYEE) for line in VALID]
    for entry in valid:
        hrp, signed, signature = split(entry["invoice"])
        canonical(hrp, signed)
        assert len(signature) == 65 and signature[64] <= 3
        assert int.from_bytes(signature[:32], "big") < ORDER
        assert int.from_bytes(signature[32:64], "big") < ORDER
        recovered = PublicKey.from_signature_and_message(signature, bytes.fromhex(entry["hash"]), hasher=None)
        assert recovered.format().hex() == entry["pubkey"]
    print("canonical valid examples: 16/16")
    existing = json.loads((PACKAGE.parent / "secp256k1/bolt11.json").read_text())
    assert len(existing) == 16
    for entry, reference in zip(valid, existing, strict=True):
        signature = bytes.fromhex(entry["signature"])
        assert (entry["line"], entry["hash"], signature[:64].hex(), signature[64]) == (
            reference["line"], reference["digest"], reference["signature"], reference["recid"])
    print("existing digest cross-checks: 16/16")
    for line, example in zip([408, 436, 464, 489, 514, 552, 577, 600, 623, 646, 788],
                             VALID[:10] + [762], strict=True):
        assert re.search(r"`([0-9a-f]{64})`", lines[line - 1])[1] == digest(*split(invoices[example])[:2])
    print("published preimage cross-checks: 11/11")
    errors = ["unknownRequiredFeatures", "accepted", "noPaymentHash", "multiplePaymentHashes",
              "multiplePaymentHashes", "multiplePaymentSecrets", "badChecksum", "missingSeparator",
              "mixedCase", "recoveryFailed", "tooShortDataPart", "unknownSiPrefix", "impreciseAmount",
              "noPaymentSecret", "multiplePaymentSecrets"]
    invalid = [row(f"L{line}", invoices[line], line=line, error=error)
               for line, error in zip(INVALID, errors, strict=True)]

    def resign(hrp, signed):
        hash_hex = digest(hrp, signed)
        signature = key.sign_recoverable(bytes.fromhex(hash_hex), hasher=None)
        assert int.from_bytes(signature[32:64], "big") <= ORDER // 2
        assert PublicKey.from_signature_and_message(signature, bytes.fromhex(hash_hex), hasher=None).format().hex() == PAYEE
        assert verify(hash_hex, signature)
        return render(hrp, signed, signature)

    hrp, signed, old_signature = split(invoices[858])
    tagged = fields(signed)
    starts = []
    pos = 7
    for tag, data in tagged:
        if tag == 16:
            starts.append(pos)
        pos += len(data) + 3
    assert len(invoices[858]) == 418 and starts == [184, 245]
    assert tagged[-1] == tagged[-3] and tagged[-2] == (5, [16, 8, 0])
    low_signed = frame(signed[:7], tagged[:-1])
    low_invoice = resign(hrp, low_signed)
    low = row("n-low", low_invoice, pubkey=PAYEE, change="second s field removed")
    assert low["hash"] == "cee5b63bb9ffa1c0c6c2ac2ff0bce99aa88db825cf8e3d813a69ebe6cddc3d11"
    low_signature = bytes.fromhex(low["signature"])
    assert len(low_invoice) == 363 and low_signature[64] == 0
    assert sha(low_invoice.encode()) == "c896332eaa43e422631c6799e268a159430bbc64a8d8269b53de59b65d4178d5"
    twin_signature = low_signature[:32] + (ORDER - int.from_bytes(low_signature[32:64], "big")).to_bytes(32, "big") + bytes([low_signature[64] ^ 1])
    twin_invoice = render(hrp, low_signed, twin_signature)
    assert twin_signature[64] == 1 and not verify(low["hash"], twin_signature)
    assert PublicKey.from_signature_and_message(twin_signature, bytes.fromhex(low["hash"]), hasher=None).format().hex() == PAYEE
    assert sha(twin_invoice.encode()) == "3a956e9bd196452f5df592062b27458b8a14ddb2bc88be6cb7249324c4bceaa0"
    nfields = [low, row("n-high", twin_invoice, error="verifyFailed", change="low-S twin with s replaced by n - s")]
    print("n-field curve probes: 2/2")

    negative = []

    def edit(name, error, tag=None, source_line=382, change=None, transform=None, new_hrp=None):
        invoice = low_invoice if source_line == "n-low" else invoices[source_line]
        source_hrp, source_signed, signature = split(invoice)
        parts = fields(source_signed)
        if transform:
            parts = transform(parts)
        result = render(new_hrp or source_hrp, frame(source_signed[:7], parts), signature)
        entry = row(name, result, error=error, source=source_line, change=change)
        if tag is not None:
            entry["tag"] = tag
        negative.append(entry)

    def replace_tag(tag, data):
        def change(parts):
            assert sum(t == tag for t, _ in parts) == 1
            return [(t, list(data) if t == tag else d) for t, d in parts]
        return change

    edit("no-features", "invalidFeatures", transform=lambda fs: [(t, d) for t, d in fs if t != 5], change="9 removed")
    edit("no-payment-secret-bit", "invalidFeatures", transform=replace_tag(5, integer(1 << 8)), change="9 without bit 14 or 15")
    assert number(integer((1 << 24) | (1 << 14))) & (1 << 24)
    edit("unknown-even-feature", "unknownRequiredFeatures", transform=replace_tag(5, integer((1 << 24) | (1 << 14))), change="9 sets bit 24")
    edit("no-description", "noDescription", transform=lambda fs: [(t, d) for t, d in fs if t not in [13, 23]], change="d and h removed")
    edit("two-descriptions", "multipleDescriptions", transform=lambda fs: fs + [(23, unpack(bytes(32)))], change="h added alongside d")
    edit("description-utf8", "malformedField", 13, transform=replace_tag(13, unpack(b"\xff")), change="d is invalid UTF-8")
    overflow_x = integer(1 << 64)
    assert len(overflow_x) == 13 and overflow_x[0] and number(overflow_x) >= 1 << 64
    edit("expiry-overflow", "malformedField", 6, source_line=410, transform=replace_tag(6, overflow_x), change="x exceeds u64")
    edit("fallback-short", "malformedField", 9, source_line=491, transform=replace_tag(9, [0] + unpack(b"\x01")), change="version 0 f with a 1-byte program")
    edit("route-length", "malformedField", 3, source_line=516, transform=replace_tag(3, unpack(bytes(50))), change="r with 50 bytes")
    off_curve = b"\x02" + b"\xff" * 32
    try:
        PublicKey(off_curve)
    except ValueError:
        pass
    else:
        raise AssertionError("off-curve point parsed")
    route = next(d for t, d in fields(split(invoices[516])[1]) if t == 3)
    bad_route = off_curve + pack(route, False)[33:]
    edit("route-point", "malformedField", 3, source_line=516, transform=replace_tag(3, unpack(bad_route)), change="r hop node id off curve")
    edit("payee-point", "malformedField", 19, transform=lambda fs: fs + [(19, unpack(off_curve))], change="53-symbol n off curve")
    edit("amount-overflow", "invalidAmount", new_hrp="lnbc20000000000m", change="amount multiplier overflows pico u64")
    bad_recid = low_signature[:64] + b"\x04"
    assert bad_recid[64] == 4 and verify(low["hash"], bad_recid)
    negative.append(row("recovery-byte", render(hrp, low_signed, bad_recid), error="malformedSignature", source="n-low", change="recovery byte set to 4"))
    p = next(d for t, d in fields(split(invoices[382])[1]) if t == 1)
    assert len(p) == 52 and p[-1] & 15 == 0
    bad_p = p[:-1] + [p[-1] | 1]
    assert bad_p[-1] & 15
    edit("payment-hash-padding", "nonCanonicalPadding", 1, transform=replace_tag(1, bad_p), change="p padding bits non-zero")
    description_source = next(line for line in VALID if any(t == 13 and len(d) * 5 % 8 <= 2 for t, d in fields(split(invoices[line])[1])))
    d = next(d for t, d in fields(split(invoices[description_source])[1]) if t == 13)
    assert len(d + [0]) * 5 % 8 >= 5 and pack(d + [0], False) == pack(d, False)
    edit("description-padding", "nonCanonicalPadding", 13, source_line=description_source, transform=replace_tag(13, d + [0]), change="whole extra zero padding symbol appended to d")
    for tag, line, name in [(6, 410, "expiry-leading-zero"), (24, 648, "cltv-leading-zero"), (5, 382, "features-leading-zero")]:
        data = next(d for t, d in fields(split(invoices[line])[1]) if t == tag)
        assert data and data[0] != 0 and number([0] + data) == number(data)
        edit(name, "leadingZero", tag, source_line=line, transform=replace_tag(tag, [0] + data), change=f"leading zero symbol prepended to {ALPHABET[tag]}")
    low_p = next(d for t, d in fields(low_signed) if t == 1)
    edit("n-payment-hash-padding", "nonCanonicalPadding", 1, source_line="n-low", transform=replace_tag(1, low_p[:-1] + [low_p[-1] | 1]), change="n-field invoice p padding bits non-zero")
    h, s, sig = split(invoices[382])
    negative.append(row("bech32m", render(h, s, sig, 0x2bc830a3), error="badChecksum", source=382, change="checksum recomputed under bech32m"))
    assert len(negative) == 20

    positive = []

    def positive_edit(name, line, change, transform=None, new_hrp=None):
        source_hrp, source_signed, _ = split(low_invoice if line == "n-low" else invoices[line])
        data = frame(source_signed[:7], transform(fields(source_signed))) if transform else source_signed
        positive.append(row(name, resign(new_hrp or source_hrp, data), pubkey=PAYEE, source=line, change=change))

    positive_edit("fallback-25", 491, "version 0 fallback with 25-byte program", replace_tag(9, [0] + unpack(bytes(25))))
    positive_edit("amount-none", 382, "no-multiplier pico overflow", new_hrp="lnbc20000000")
    positive_edit("amount-leading-zero", 410, "leading zero hrp amount without n", new_hrp="lnbc02500u")
    positive_edit("n-amount-leading-zero", "n-low", "leading zero hrp amount with n", new_hrp="lnbc025m")
    assert len(positive) == 4

    h, s, signature = split(invoices[410])
    long_hrp = "lnbc" + "0" * (84 - len(h)) + h[4:]
    long_invoice = resign(long_hrp, s)
    assert len(long_hrp) == 84 and len(long_invoice) <= 7089
    h0, s0, sig0 = split(invoices[382])
    extra = 7090 - len(invoices[382])
    fs = fields(s0)
    while extra:
        length = min(extra - 3, 1023)
        assert length >= 0
        fs.append((2, [0] * length))
        extra -= length + 3
    long_data = frame(s0[:7], fs)
    long_string = resign(h0, long_data)
    assert len(long_string) == 7090 and len(h0) <= 83
    tampered = bytes([sig0[0] ^ 1]) + sig0[1:]
    assert int.from_bytes(tampered[:32], "big") < ORDER and tampered[64] <= 3
    outside = [row("hrp-over-83", long_invoice, error="hrpTooLong", source=410, change="hrp extended to 84 characters with leading zeros"),
               row("length-7090", long_string, error="tooLong", source=382, change="unknown fields added to reach 7090 characters"),
               row("tampered-signature", render(h0, s0, tampered), error="recoveryFailed", source=382, change="one signature byte changed")]
    extra_cases = [row("malformed-hrp", render("xxbc", s0, sig0), error="malformedHrp", source=382, change="ln prefix replaced by xx"),
                   row("unknown-currency", render("lnzz", s0, sig0), error="unknownCurrency", source=382, change="currency replaced by zz"),
                   row("truncated-field", render(h0, s0 + [2, 0], sig0), error="unexpectedEndOfTaggedFields", source=382, change="two-symbol field header appended")]
    table = [dict(name=r["name"], hash=r["hash"], signature=r["signature"], pubkey=r.get("pubkey", PAYEE))
             for r in valid + [invalid[1], invalid[12], low] + positive]
    assert len(table) == 23 and len({(r["hash"], r["signature"]) for r in table}) == 22
    assert len(KEYS) == 4
    for hash_hex in {r["hash"] for r in table}:
        low_s = {r["signature"] for r in table if r["hash"] == hash_hex and int(r["signature"][64:128], 16) <= ORDER // 2}
        assert len(low_s) == 1
    print("negative vectors: 20/20; positive vectors: 4/4; outside tests: 3/3; small cases: 3/3")
    print("capability rows: 23/23; distinct pairs: 22/22; accepted keys: 4/4")
    result = subprocess.run([str(PACKAGE / ".lake/build/bin/LightningTests"), "--hash", low_invoice],
                            cwd=PACKAGE, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert result.stdout.strip() == low["hash"], (result.stdout, low["hash"])
    print("Lean signing-hash cross-check: 1/1")
    corpus = dict(valid=valid, invalid=invalid, nfields=nfields, negative=negative,
                  positive=positive, outside=outside, small=extra_cases, table=table, keys=KEYS)
    destination = PACKAGE / "test-data/bolt11.json"
    content = json.dumps(corpus, indent=2) + "\n"
    provenance = (f"Source: {URL}\nCommit: {REVISION}\nPath: 11-payment-encoding.md\n"
                  "Licence: CC-BY-4.0; attribution: lightning/bolts contributors.\n"
                  f"Examples headed at lines {', '.join(map(str, VALID + INVALID))}: extracted and reformatted.\n"
                  "n-field vectors: L858, modified: second s field removed, re-signed with the spec's example key "
                  "(the twin with s replaced by n - s), checksum recomputed.\n"
                  "Negative and small vectors: modified as each row's change specifies, checksum recomputed; "
                  "bech32m: checksum recomputed under bech32m.\n"
                  "Positive vectors and the two length strings: modified as each row's change specifies, "
                  "re-signed with the spec's example key, checksum recomputed.\n"
                  "Tampered signature: modified: one signature byte changed, checksum recomputed.\n"
                  "Hashes computed independently from the as-written HRP and data. Curve table extracted from those rows.\n"
                  "Generated with coincurve 21.0.0, libsecp256k1 0.8.0, RFC 6979, hasher=None.\n")
    for path, text in [(destination, content), (destination.with_suffix(".json.provenance"), provenance)]:
        if args.check:
            assert path.read_text() == text, f"fixture differs: {path.name}"
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_text(text)
    print("fixture reproduction: 1/1")


if __name__ == "__main__":
    main()
