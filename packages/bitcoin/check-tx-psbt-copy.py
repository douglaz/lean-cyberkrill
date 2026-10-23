# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check the exact pinned transaction/PSBT slices and all documented port edits.

python3 -I check-tx-psbt-copy.py FRESH_CHECKOUT [--write]
--write creates absent files only. No network access.
"""
from pathlib import Path
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent
COMMIT = "cb9bc5f2f80987ad18b696a9c660f90f4bc1b6bd"


# Tail-recursive Base64 traversals (docs/upstream-fixes.md).
BASE64_ENCODE_UPSTREAM = """private def encodeList : Nat → List UInt8 → List Char
  | 0, _ => []
  | fuel + 1, bytes =>
      match bytes with
      | [] => []
      | _ => encodeGroup (bytes.take 3) ++ encodeList fuel (bytes.drop 3)
"""
BASE64_ENCODE_PORT = """/-- Groups go into an accumulator, so the traversal is tail recursive and
large inputs do not grow the call stack. -/
private def encodeList (fuel : Nat) (bytes : List UInt8) : List Char :=
  go fuel bytes #[]
where
  go : Nat → List UInt8 → Array Char → List Char
    | 0, _, acc => acc.toList
    | fuel + 1, bytes, acc =>
        match bytes with
        | [] => acc.toList
        | _ => go fuel (bytes.drop 3) (acc ++ encodeGroup (bytes.take 3))
"""
BASE64_DECODE_UPSTREAM = """private def decodeList : Nat → List Char → Option (List UInt8)
  | 0, _ => none
  | fuel + 1, chars =>
      match chars with
      | [] => some []
      | _ => do
          let rest := chars.drop 4
          let group ← decodeGroup rest.isEmpty (chars.take 4)
          return group ++ (← decodeList fuel rest)
"""
BASE64_DECODE_PORT = """/-- Tail recursive, like `encodeList`. -/
private def decodeList (fuel : Nat) (chars : List Char) : Option (List UInt8) :=
  go fuel chars #[]
where
  go : Nat → List Char → Array UInt8 → Option (List UInt8)
    | 0, _, _ => none
    | fuel + 1, chars, acc =>
        match chars with
        | [] => some acc.toList
        | _ =>
            let rest := chars.drop 4
            match decodeGroup rest.isEmpty (chars.take 4) with
            | none => none
            | some group => go fuel rest (acc ++ group)
"""


def replace(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old), count)
    return text.replace(old, new)


def expected_files(source):
    def read(path, ranges):
        lines = (source / "LeanMiniscript" / path).read_text().splitlines(keepends=True)
        return "".join("".join(lines[first-1:last]) for first, last in ranges)

    def provenance(path, ranges, notice="LICENSE-miniscript"):
        spans = ", ".join(f"L{first}-{last}" for first, last in ranges)
        return (f"-- Copied from febyeji/lean-miniscript @ {COMMIT}, "
                f"LeanMiniscript/{path} {spans}; MIT, see {notice}\n")

    files = {}
    for path, target, ranges in [
        ("Script/Syntax.lean", "ByteArrayRepr.lean", [(1, 2)]),
        ("Bitcoin/Transaction.lean", "Transaction.lean", [(1, 55)]),
        ("Bitcoin/Deserialization.lean", "Deserialization.lean", [(81, 170)]),
        ("Bitcoin/DeserializationProofs.lean", "DeserializationProofs.lean", [(180, 232)]),
        ("Bitcoin/Base64.lean", "Base64.lean", [(1, 79)]),
        ("Psbt/Codec.lean", "Psbt/Codec.lean", [(1, 157)]),
        ("Psbt/Fields.lean", "Psbt/Fields.lean", [(1, 582)]),
        ("Psbt/CodecProofs.lean", "Psbt/CodecProofs.lean", [(1, 280)]),
        ("Psbt/ParseProofs.lean", "Psbt/ParseProofs.lean", [(1, 65)]),
    ]:
        text = read(path, ranges)
        text = text.replace("LeanMiniscript.Psbt", "Bitcoin.Psbt")
        text = text.replace("LeanMiniscript.Bitcoin", "Bitcoin")
        if target == "Transaction.lean":
            text = replace(text, "import Bitcoin.Serialization\nimport LeanMiniscript.Script.Syntax",
                           "import Bitcoin.CompactSize\nimport Bitcoin.ByteArrayRepr")
            text = replace(text, "namespace Bitcoin\n", "namespace Bitcoin\n\nopen CompactSize\n")
        elif target == "Deserialization.lean":
            text = "import Bitcoin.Transaction\nimport Sha256\n\nnamespace Bitcoin\n\nopen CompactSize\n\n" + text
            text = replace(text, "doubleSHA256 (serializeTransaction tx)",
                           "Sha256.sha256d (serializeTransaction tx)")
            text = replace(text, "Missing stacks are treated as empty. -/",
                           "Missing stacks are treated as empty, and stacks beyond the inputs are ignored. -/")
            text = replace(text, "  if witnesses.all List.isEmpty then serializeTransaction tx",
                           "  if (witnesses.take tx.inputs.size).all List.isEmpty then serializeTransaction tx")
        elif target == "Base64.lean":
            text = replace(text, BASE64_ENCODE_UPSTREAM, BASE64_ENCODE_PORT)
            text = replace(text, BASE64_DECODE_UPSTREAM, BASE64_DECODE_PORT)
        elif target == "DeserializationProofs.lean":
            text = "import Bitcoin.Deserialization\n\nnamespace Bitcoin\n\nopen CompactSize\n\n" + text
        elif target == "Psbt/Codec.lean":
            text = replace(text, "open Bitcoin\n", "open Bitcoin Bitcoin.CompactSize\n")
            text = replace(text, "  | duplicateKey (key : ByteArray)",
                           "  | duplicateKey (key : ByteArray)\n"
                           "  | duplicateBip32Point (scope : String) (first second : ByteArray)")
        elif target == "Psbt/Fields.lean":
            text = replace(text, "import Bitcoin.ECDSA", "import Bitcoin.Psbt.Capability")
            text = replace(text, "open Bitcoin\n", "open Bitcoin Bitcoin.CompactSize\n")
            text = replace(text, "private def validPublicKey (key : ByteArray) : Bool :=\n"
                           "  (key.size == 33 || key.size == 65) && (ECDSA.parsePublicKey key).isSome\n\n", "")
            text = replace(text, "private def preimageHash (keyType : Nat)",
                           "private def preimageHash (hashes : PreimageHashes) (keyType : Nat)")
            for old, new in [("LeanHash160.RIPEMD160.hash", "hashes.ripemd160"),
                             ("LeanHash160.SHA256.hash", "Sha256.hash"),
                             ("LeanHash160.hash160", "hashes.hash160"),
                             ("doubleSHA256", "Sha256.sha256d")]:
                text = replace(text, old, new)
            for name in ["inputStep", "decodeInput"]:
                text = replace(text, f"def {name} (version : Nat)",
                               f"def {name} (cap : PubkeyCapability) (hashes : PreimageHashes) (version : Nat)")
            for name in ["outputStep", "decodeOutput"]:
                text = replace(text, f"def {name} (version : Nat)",
                               f"def {name} (cap : PubkeyCapability) (version : Nat)")
            text = replace(text, "(validPublicKey keyData)", "(cap.isValidPubkey keyData)", 3)
            for keytype in ["inBip32Derivation", "outBip32Derivation"]:
                text = replace(text, f"keyType == KeyType.{keytype} then\n"
                               '    checkKeyData scope keyType (cap.isValidPubkey keyData) "invalid public key"',
                               f"keyType == KeyType.{keytype} then\n"
                               '    checkKeyData scope keyType (cap.compressPubkey keyData).isSome "invalid public key"')
            text = replace(text, "preimageHash keyType value", "preimageHash hashes keyType value")
            text = replace(text, "(inputStep version)", "(inputStep cap hashes version)")
            text = replace(text, "(outputStep version)", "(outputStep cap version)")
            text = replace(text, "def Psbt.decode (psbt : Psbt)",
                           "def Psbt.decode (cap : PubkeyCapability) (hashes : PreimageHashes) (psbt : Psbt)")
            text = replace(text, "(decodeInput global.psbtVersion)", "(decodeInput cap hashes global.psbtVersion)")
            text = replace(text, "(decodeOutput global.psbtVersion)", "(decodeOutput cap global.psbtVersion)")
            text = replace(text, "def Psbt.parse (bytes : ByteArray)",
                           "def Psbt.parse (cap : PubkeyCapability) (hashes : PreimageHashes) (bytes : ByteArray)")
            text = replace(text, "let _ ← psbt.decode", "let _ ← psbt.decode cap hashes")
            text = replace(text, "def Psbt.parseBase64 (text : String)",
                           "def Psbt.parseBase64 (cap : PubkeyCapability) (hashes : PreimageHashes) (text : String)")
            text = replace(text, "| some bytes => Psbt.parse bytes", "| some bytes => Psbt.parse cap hashes bytes")
            # Non-curve field parity with rust-bitcoin 0.32.8.
            text = replace(text, '\n/-- Control-block shape from BIP341: 33 + 32m bytes with m ≤ 128. -/\n',
                           '\nprivate def standardEcdsaSighash (sighash : UInt8) : Bool :=\n  [1, 2, 3, 129, 130, 131].contains sighash\n\nprivate def validTapSighash (signature : ByteArray) : Bool :=\n  signature.size != 65 || signature[64]! == 0 || standardEcdsaSighash signature[64]!\n\nprivate def validLeafVersion (version : UInt8) : Bool :=\n  version.toNat % 2 == 0 && version != 0x50\n\n/-- Control-block shape from BIP341: 33 + 32m bytes with m ≤ 128. -/\n')
            text = replace(text, '  checkValue scope keyType (!leaves.isEmpty) "empty Taproot tree"\n  checkValue scope keyType (leaves.all (fun leaf => leaf.leafVersion.toNat % 2 == 0))\n    "invalid leaf version"\n',
                           '  checkValue scope keyType (!leaves.isEmpty) "empty Taproot tree"\n  checkValue scope keyType (leaves.all (fun leaf => validLeafVersion leaf.leafVersion))\n    "invalid leaf version"\n')
            text = replace(text, '\nprivate def preimageHash (hashes : PreimageHashes) (keyType : Nat) (preimage : ByteArray) : ByteArray :=\n',
                           '\n/-- rust-bitcoin counts from its one-byte subtype, even when our canonical\nCompactSize subtype occupies more than one byte. -/\nprivate def proprietaryKeyLength (keyData : ByteArray) : Bool :=\n  match readByteVector keyData.data.toList with\n  | .error _ => false\n  | .ok (_, rest) => rest.length ≤ 1025\n\nprivate def preimageHash (hashes : PreimageHashes) (keyType : Nat) (preimage : ByteArray) : ByteArray :=\n')
            text = replace(text, '    checkKeyData scope keyType (validProprietaryKey keyData) "malformed proprietary key"\n  return unknown ++ [record]\n',
                           '    checkKeyData scope keyType (validProprietaryKey keyData) "malformed proprietary key"\n    checkKeyData scope keyType (proprietaryKeyLength keyData) "proprietary key data exceeds 1024 bytes"\n  return unknown ++ [record]\n')
            text = replace(text, '    checkKeyData scope keyType (keyData.size == 78) "extended key must be 78 bytes"\n    let source ← decodeKeySource scope keyType value\n',
                           '    checkKeyData scope keyType (keyData.size == 78) "extended key must be 78 bytes"\n    checkKeyData scope keyType\n      (keyData.extract 0 4 == ⟨#[0x04, 0x88, 0xb2, 0x1e]⟩ ||\n       keyData.extract 0 4 == ⟨#[0x04, 0x35, 0x87, 0xcf]⟩) "invalid extended key version"\n    let source ← decodeKeySource scope keyType value\n')
            text = replace(text, '    checkKeyData scope keyType (cap.isValidPubkey keyData) "invalid public key"\n    return { fields with partialSigs := fields.partialSigs ++ [(keyData, value)] }\n',
                           '    checkKeyData scope keyType (cap.isValidPubkey keyData) "invalid public key"\n    checkValue scope keyType (!value.isEmpty) "empty ECDSA signature"\n    checkValue scope keyType (standardEcdsaSighash value[value.size - 1]!) "non-standard ECDSA sighash type"\n    return { fields with partialSigs := fields.partialSigs ++ [(keyData, value)] }\n')
            text = replace(text, '    checkValue scope keyType (validSchnorrSignature value) "signature must be 64 or 65 bytes"\n    return { fields with tapKeySig := some value }\n',
                           '    checkValue scope keyType (validSchnorrSignature value) "signature must be 64 or 65 bytes"\n    checkValue scope keyType (validTapSighash value) "non-standard Taproot sighash type"\n    return { fields with tapKeySig := some value }\n')
            text = replace(text, '    checkValue scope keyType (validSchnorrSignature value) "signature must be 64 or 65 bytes"\n    return { fields with tapScriptSigs := fields.tapScriptSigs ++\n',
                           '    checkValue scope keyType (validSchnorrSignature value) "signature must be 64 or 65 bytes"\n    checkValue scope keyType (validTapSighash value) "non-standard Taproot sighash type"\n    return { fields with tapScriptSigs := fields.tapScriptSigs ++\n')
            text = replace(text, '    checkValue scope keyType (value.size ≥ 1) "missing leaf version"\n    return { fields with tapLeafScripts := fields.tapLeafScripts ++\n',
                           '    checkValue scope keyType (value.size ≥ 1) "missing leaf version"\n    checkKeyData scope keyType (validLeafVersion (keyData[0]! &&& 0xfe)) "invalid control block leaf version"\n    checkValue scope keyType (validLeafVersion value[value.size - 1]!) "invalid leaf version"\n    return { fields with tapLeafScripts := fields.tapLeafScripts ++\n')
            # Curve-capability parity with rust-bitcoin 0.32.8 / secp256k1 0.29.1.
            text = replace(text,
                           'must parse as secp256k1 points. X-only keys are checked only for length.',
                           'must parse as secp256k1 points. The supplied capability also checks global xpub\n'
                           'points, partial-signature DER, x-only keys and control-block internal keys.')
            old = '    checkValue scope keyType (standardEcdsaSighash value[value.size - 1]!) "non-standard ECDSA sighash type"\n'
            text = replace(text, old, old +
                           '    checkValue scope keyType (cap.isValidDerSignature (value.extract 0 (value.size - 1))) "invalid DER signature"\n')
            for kind, old, new in [
                ("inTapScriptSig",
                 '    checkKeyData scope keyType (keyData.size == 64) "key must be x-only key and leaf hash"\n',
                 '    checkKeyData scope keyType (cap.isValidXOnlyPubkey (keyData.extract 0 32)) "invalid x-only public key"\n'),
                ("inTapLeafScript",
                 '    checkValue scope keyType (validLeafVersion value[value.size - 1]!) "invalid leaf version"\n',
                 '    checkKeyData scope keyType (cap.isValidXOnlyPubkey (keyData.extract 1 33)) "invalid control block internal key"\n'),
                ("inTapBip32Derivation",
                 '    checkKeyData scope keyType (keyData.size == 32) "key must be x-only"\n',
                 '    checkKeyData scope keyType (cap.isValidXOnlyPubkey keyData) "invalid x-only public key"\n'),
                ("inTapInternalKey",
                 '    checkValue scope keyType (value.size == 32) "internal key must be x-only"\n',
                 '    checkValue scope keyType (cap.isValidXOnlyPubkey value) "invalid x-only public key"\n'),
                ("outTapInternalKey",
                 '    checkValue scope keyType (value.size == 32) "internal key must be x-only"\n',
                 '    checkValue scope keyType (cap.isValidXOnlyPubkey value) "invalid x-only public key"\n'),
                ("outTapBip32Derivation",
                 '    checkKeyData scope keyType (keyData.size == 32) "key must be x-only"\n',
                 '    checkKeyData scope keyType (cap.isValidXOnlyPubkey keyData) "invalid x-only public key"\n')]:
                start = text.index(f"  else if keyType == KeyType.{kind} then")
                end = text.index("  else ", start + 3)
                body = text[start:end]
                changed = replace(body, old, old + new)
                text = replace(text, body, changed)
            old = '  if global.counts ≠ (psbt.inputs.length, psbt.outputs.length) then throw .mapCount\n'
            text = replace(text, old, old +
                           '  for (xpub, _) in global.xpubs do\n'
                           '    checkKeyData "global" KeyType.globalXpub (cap.isValidPubkey (xpub.extract 45 78)) "invalid extended key point"\n')
        elif target == "Psbt/CodecProofs.lean":
            text = replace(text, "open Bitcoin\n", "open Bitcoin Bitcoin.CompactSize\n")
            text = replace(text, "if_false", "ite_false", 3)
            text = replace(text, "if_true", "ite_true")
        elif target == "Psbt/ParseProofs.lean":
            text = replace(text, "namespace Bitcoin.Psbt\n", "namespace Bitcoin.Psbt\n\nvariable {cap : PubkeyCapability} {hashes : PreimageHashes}\n")
            text = replace(text, "psbt.decode", "psbt.decode cap hashes", 3)
            text = replace(text, "raw.decode", "raw.decode cap hashes")
            text = replace(text, "Psbt.parse psbt.serialize", "Psbt.parse cap hashes psbt.serialize", 2)
            text = replace(text, "Psbt.parse bytes", "Psbt.parse cap hashes bytes", 2)
        notice = "../LICENSE-miniscript" if target.startswith("Psbt/") else "LICENSE-miniscript"
        files["Bitcoin/" + target] = provenance(path, ranges, notice) + text

    ranges = [(8, 70), (95, 178)]
    files["Bitcoin/PsbtVectors.lean"] = (
        "-- Copied via febyeji/lean-miniscript @ " + COMMIT +
        ", LeanMiniscript/Psbt/Fixtures.lean L8-70, L95-178; source https://github.com/bitcoin/bips @ "
        "927b6de9915c9262615a6399de51b200f81e5aa4, BIP174/370/371; BSD-2-Clause, see LICENSE-psbt-bips\n"
        "namespace BitcoinTests.PsbtVectors\n\n" + read("Psbt/Fixtures.lean", ranges) +
        "\nend BitcoinTests.PsbtVectors\n")
    return files


def main():
    source = Path(sys.argv[1])
    assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == COMMIT
    assert not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True), \
        "upstream checkout has local changes"
    assert (PACKAGE / "Bitcoin/LICENSE-miniscript").read_bytes() == (source / "LICENSE").read_bytes()
    write = sys.argv[2:] == ["--write"]
    assert write or not sys.argv[2:]
    for target, expected in expected_files(source).items():
        path = PACKAGE / target
        if write:
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(expected)
        assert path.read_text() == expected, f"undocumented copy delta: {target}"
        print(f"exact copy plus documented edits: {target}")
    print("transaction/PSBT copy: 10/10; MIT notice reused; forbidden fixture slice excluded")


if __name__ == "__main__":
    main()
