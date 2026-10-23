# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent transaction/PSBT production mutations, restored in finally.

Run with nix develop -c python3 -I check-psbt-mutations.py, without concurrent
writers. Optional labels select a subset for diagnosis. Each foreground lake
test captures separate streams below .lake/psbt-mutation-checks. Compact records
are kept separately in test-data/psbt-mutations.json.
"""
import json
import hashlib
from pathlib import Path
import re
import signal
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent
LOGS = PACKAGE / ".lake/psbt-mutation-checks"


def cancelled(signum, _frame):
    # A timeout must unwind the active mutation's finally block too.
    raise SystemExit(128 + signum)


def replace(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old), count)
    changed = text.replace(old, new)
    assert changed != text and new in changed
    return changed


def mutations(originals):
    result = []

    def add(label, path, old, new, selection, failure, count=1):
        result.append((label, path, replace(originals[path], old, new, count), selection, failure))

    fields = "Bitcoin/Psbt/Fields.lean"
    codec = "Bitcoin/Psbt/Codec.lean"
    same = "Bitcoin/Psbt/SamePoint.lean"
    deser = "Bitcoin/Deserialization.lean"
    transaction = "Bitcoin/Transaction.lean"
    base64 = "Bitcoin/Base64.lean"
    compact = "Bitcoin/CompactSize.lean"
    add("partial-compression", fields, "(cap.isValidPubkey keyData)",
        "(cap.compressPubkey keyData).isSome", "hybrid partial", "hybrid partial rejected")
    for key, selection, flag in [("inBip32Derivation", "hybrid input", "false"),
                                 ("outBip32Derivation", "hybrid output", "true")]:
        add("strict-" + key, fields, f"keyType == KeyType.{key} then\n"
            '    checkKeyData scope keyType (cap.compressPubkey keyData).isSome "invalid public key"',
            f"keyType == KeyType.{key} then\n"
            '    checkKeyData scope keyType (cap.isValidPubkey keyData) "invalid public key"',
            selection, "hybrid parse")
        # Change only this scope's storage, keeping the raw framing layer intact.
        start = originals[fields].index(f"keyType == KeyType.{key} then")
        end = originals[fields].index("  else if ", start)
        old = originals[fields][start:end]
        new = replace(old, "[(keyData, source)]", "[((cap.compressPubkey keyData).getD keyData, source)]")
        add("compress-stored-" + key, fields, old, new, selection, f"hybrid {flag} raw decoded")
    add("same-raw-comparison", same, "fun (_, point) => point == compressed", "fun (first, _) => first == raw",
        "same input collision", "same point false/2")
    add("same-ignore-output", same, 'for map in psbt.outputs do checkMap cap "output" KeyType.outBip32Derivation map',
        'for map in psbt.outputs do checkMap cap "output" KeyType.outBip32Derivation (map.filter (fun _ => false))',
        "same output collision", "same point true/2")
    for scope in ["input", "output"]:
        plural = scope + "s"
        key = "inBip32Derivation" if scope == "input" else "outBip32Derivation"
        add("same-pool-" + scope, same,
            f'for map in psbt.{plural} do checkMap cap "{scope}" KeyType.{key} map',
            f'checkMap cap "{scope}" KeyType.{key} psbt.{plural}.flatten',
            f"same {scope} separate", f"same point separate {str(scope == 'output').lower()}")
        for encoding in ["hybrid", "compressed"]:
            add(f"same-lone-{scope}-{encoding}", same, "seen := seen ++ [(raw, compressed)]",
                'throw (.duplicateBip32Point scope raw raw)',
                f"same {scope} {encoding} alone", f"same point {str(scope == 'output').lower()}/1")
    add("same-accept-invalid", same, '| throw (.invalidKey scope keyType "invalid public key")',
        '| pure ()', "same invalid", "same invalid")
    add("same-skip-malformed", same, 'let (kind, raw) ← splitKey record.key',
        'let (kind, raw) := (splitKey record.key).toOption.getD (255, ByteArray.empty)',
        "same malformed", "same malformed")
    preimage_old = '(preimageHash hashes keyType value == keyData)'
    for name, keytype, selection, number in [
        ("sha256", "inSha256", "SHA256 preimage", 11),
        ("hash256", "inHash256", "HASH256 preimage", 13),
        ("ripemd160", "inRipemd160", "RIPEMD160 preimage", 10),
        ("hash160", "inHash160", "HASH160 preimage", 12)]:
        add("skip-" + name, fields, preimage_old,
            f'(keyType == KeyType.{keytype} || preimageHash hashes keyType value == keyData)',
            selection, f"preimage {number} mismatch")
    add("hash256-single", fields, "else Sha256.sha256d preimage", "else Sha256.hash preimage",
        "HASH256 preimage", "preimage 13 accepted")
    add("sha256-double", fields, "else if keyType == KeyType.inSha256 then Sha256.hash preimage",
        "else if keyType == KeyType.inSha256 then Sha256.sha256d preimage",
        "SHA256 preimage", "preimage 11 accepted")
    for name, selection, number in [("ripemd160", "RIPEMD160 preimage", 10),
                                     ("hash160", "HASH160 preimage", 12)]:
        old = "then hashes.ripemd160 preimage" if number == 10 else "then hashes.hash160 preimage"
        new = "then hashes.hash160 preimage" if number == 10 else "then hashes.ripemd160 preimage"
        add("swap-" + name, fields, old, new, selection, f"preimage {number} accepted")
    add("txid-single", deser, "Sha256.sha256d (serializeTransaction tx)",
        "Sha256.hash (serializeTransaction tx)", "transactions", "wire bip174Invalid[1] input txid")
    add("witness-marker-flag", deser, "++ [0, 1] ++", "++ [0, 3] ++",
        "transactions", "wire bip174Invalid[1] input roundtrip")
    add("surplus-witness-format", deser, "if (witnesses.take tx.inputs.size).all List.isEmpty then",
        "if witnesses.all List.isEmpty then", "surplus witness", "surplus witness legacy")
    add("legacy-version", transaction, "unsignedLE 4 tx.version.toNat",
        "unsignedLE 4 (tx.version.toNat + 1)",
        "transactions", "wire bip174Invalid[0] network roundtrip")
    add("malformed-witness-marker", deser, "if inputCount = 0 ∧ allowWitness then",
        "if inputCount = 0 ∧ (allowWitness || true) then",
        "malformed transaction 18", "malformed transaction 18")
    add("transaction-ignore-trailing", compact,
        "if rest.isEmpty then return value else throw .trailingData",
        "if rest.isEmpty || true then return value else throw .trailingData",
        "malformed transaction 19", "malformed transaction 19")
    add("valid-base64-encode", base64, "String.ofList (encodeList bytes.size bytes.data.toList)",
        'String.ofList (encodeList bytes.size bytes.data.toList) ++ "A"',
        "BIP174 valid", "BIP174 valid 0 base64 encode")
    add("valid-base64-decode", base64, "return ⟨bytes.toArray⟩", "return ⟨(bytes ++ [0]).toArray⟩",
        "BIP174 valid", "BIP174 valid 0 base64 parse")
    # One production mutation for every loaded vector set.
    add("vector-bip174-invalid", codec, "if records.any (fun record => decide (record.key = key)) then",
        "if records.any (fun record => decide (record.key = key)) && false then",
        "BIP174 invalid", "BIP174 invalid hex 4")
    add("vector-bip370-invalid", fields,
        'if fields.txVersion.isSome then throw (.excludedField scope KeyType.globalTxVersion)',
        'if fields.txVersion.isSome && false then throw (.excludedField scope KeyType.globalTxVersion)',
        "BIP370 invalid", "BIP370 invalid hex 1")
    add("vector-bip371-invalid", fields, 'signature.size == 64 || signature.size == 65',
        'signature.size > 0', "BIP371 invalid", "BIP371 invalid hex 1")
    for label, selection in [("bip174-valid", "BIP174 valid"),
                              ("bip174-signer", "BIP174 signer failures"),
                              ("bip370-valid", "BIP370 valid"),
                              ("bip371-valid", "BIP371 valid"), ("bip174-roles", "BIP174 roles")]:
        add("vector-" + label, codec, "map.flatMap Record.encode ++ [0]",
            "map.flatMap Record.encode ++ [1]", selection, selection + " 0 serialize")
    add("vector-locktimes", fields, "some (fallback.getD 0)", "some (fallback.getD 1)",
        "BIP370 locktimes", "locktime determine 0")
    add("unsigned-locktime", fields, "          locktime }", "          locktime := locktime + 1 }",
        "BIP370 locktimes", "locktime transaction 0")
    add("incompatible-locktime", fields, 'none => .error (.invalidUnsignedTransaction "incompatible input locktimes")',
        'none => .error (.invalidUnsignedTransaction "different error")',
        "BIP370 locktimes", "locktime incompatible 9")
    add("invalid-base64-bytes", base64, "return ⟨bytes.toArray⟩", "return ⟨(bytes ++ [0]).toArray⟩",
        "invalid base64 bytes", "invalid base64 bytes 0")
    add("network-magic", codec, "if bytes.take 5 ≠ magicBytes then", "if False then",
        "network magic", "network magic")
    add("base64-error", fields, "| none => .error .base64", "| none => .error .magic",
        "base64 syntax", "base64 syntax")
    add("same-check-partial", same, 'KeyType.inBip32Derivation map', 'KeyType.inPartialSig map',
        "same ignores partial", "same ignores partial")
    add("same-check-global", same, '  for map in psbt.inputs do',
        '  checkMap cap "global" KeyType.inBip32Derivation psbt.global\n  for map in psbt.inputs do',
        "same ignores global", "same ignores global")
    for name, flag, selection in [("input", "inputs", "hybrid input"), ("output", "outputs", "hybrid output")]:
        kind = "inBip32Derivation" if name == "input" else "outBip32Derivation"
        rewrite = ("  let rewrite (record : Record) : Record :=\n"
                   "    match splitKey record.key with\n"
                   f"    | .ok (kind, raw) => if kind == KeyType.{kind} then\n"
                   "        { record with key := recordKey kind ((cap.compressPubkey raw).getD raw) } else record\n"
                   "    | .error _ => record\n"
                   f"  return {{ psbt with {flag} := psbt.{flag}.map (List.map rewrite) }}")
        add("rewrite-raw-" + name, fields, "  return psbt", rewrite, selection,
            "hybrid " + str(name == "output").lower() + " raw serialization")
    add("exact-duplicate", codec, "if records.any (fun record => decide (record.key = key)) then",
        "if records.any (fun record => decide (record.key = key)) && false then",
        "exact duplicate", "exact duplicate")
    add("exact-unsigned", fields, 'throw (.invalidUnsignedTransaction "scriptSig must be empty")',
        'throw (.invalidUnsignedTransaction "different error")', "exact unsigned", "exact unsigned")
    add("exact-excluded", fields, 'if fields.unsignedTx.isSome then throw (.excludedField scope KeyType.globalUnsignedTx)',
        'if fields.unsignedTx.isSome && false then throw (.excludedField scope KeyType.globalUnsignedTx)',
        "exact excluded", "exact excluded")
    add("exact-missing", fields, 'if fields.inputCount.isNone then throw (.missingField scope KeyType.globalInputCount)',
        'if fields.inputCount.isNone && false then throw (.missingField scope KeyType.globalInputCount)',
        "exact missing", "exact missing")
    add("exact-signature", fields, '"signature must be 64 or 65 bytes"',
        '"different error"', "exact signature", "exact signature", count=2)
    add("exact-control", fields, '"invalid control block size"', '"different error"',
        "exact control", "exact control")
    add("sighash-extra", fields, "keyData.size == 0", "keyData.size ≤ 1", "sighash extra", "sighash extra")
    add("sighash-valid", fields,
        'else if keyType == KeyType.inSighashType then\n    noKeyData scope keyType keyData',
        'else if keyType == KeyType.inSighashType then\n    checkKeyData scope keyType false "rejected"',
        "sighash valid", "sighash valid")
    add("map-noncanonical", compact, "if decodeLE bytes < minimum then",
        "if decodeLE bytes < minimum && false then", "map noncanonical", "theorem:readCompactSize_ok")
    add("map-canonical", codec, "if keyLength = 0 then return ([], rest)",
        "if keyLength = 0 then return ([], 0 :: rest)", "map canonical", "map canonical")
    add("key-source", fields, "source.fingerprint ++ ⟨(source.path.flatMap",
        "source.fingerprint.push 0 ++ ⟨(source.path.flatMap", "key source", "key source")
    add("tap-key-source", fields, "⟨(compactSize source.leafHashes.length).toArray⟩ ++",
        "⟨(compactSize (source.leafHashes.length + 1)).toArray⟩ ++", "tap key source", "tap key source")
    add("tap-tree", fields, "UInt8.ofNat leaf.depth, leaf.leafVersion", "UInt8.ofNat (leaf.depth + 1), leaf.leafVersion",
        "tap tree", "tap tree")
    add("trailing-data", codec, "if rest ≠ [] then throw .trailingData",
        "if rest ≠ [] && false then throw .trailingData", "trailing data", "PSBT trailing data")
    for name, selection in [("bip174Invalid", "BIP174 invalid"), ("bip370Invalid", "BIP370 invalid"),
                             ("bip371Invalid", "BIP371 invalid"), ("bip174Valid", "BIP174 valid"),
                             ("bip174SignerFailures", "BIP174 signer failures"), ("bip370Valid", "BIP370 valid"),
                             ("bip371Valid", "BIP371 valid"), ("bip174Roles", "BIP174 roles"),
                             ("bip370Locktimes", "BIP370 locktimes")]:
        path = "Bitcoin/PsbtVectors.lean"
        match = re.search(r"^def " + name + r"[^\n]*\n(  [^\n]+\n)", originals[path], re.M)
        assert match, name
        add("count-" + name, path, match[1], "", selection, selection + " count")
    for name, display, selector in [
        ("bip174Valid", "BIP174 valid", "BIP174 valid definition"),
        ("bip174SignerFailures", "BIP174 signer", "BIP174 signer valid definition"),
        ("bip370Valid", "BIP370 valid", "BIP370 valid definition"),
        ("bip371Valid", "BIP371 valid", "BIP371 valid definition")]:
        path = "Bitcoin/PsbtVectors.lean"
        first = re.search(r"^def " + name + r"[^\n]*\n(  [^\n]+\n)", originals[path], re.M)
        assert first, name
        add("valid-count-" + name, path, first[1], "", selector, display + " valid count")
        add("valid-decode-" + name, fields,
            '  let scope := "input"\n  let (keyType, keyData) ← splitKey record.key',
            '  let scope := "input"\n  checkValue scope 0 false "rejected input field"\n'
            '  let (keyType, keyData) ← splitKey record.key',
            selector, display + " valid decode 0")
    add("valid-formed", codec,
        "0 < record.key.size ∧ record.key.size < 2 ^ 64 ∧ record.value.size < 2 ^ 64",
        "1 < record.key.size ∧ record.key.size < 2 ^ 64 ∧ record.value.size < 2 ^ 64",
        "BIP174 valid definition", "theorem:Bitcoin/Psbt/CodecProofs.lean:decodeMapFuel_ok")
    proof = "Bitcoin/TransactionProofs.lean"
    add("formed-count-exception", proof,
        "  unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0",
        "  unambiguous : tx.inputs.size > 0", "Transaction WellFormed", "formed count and exception")
    for field in ["txidSize", "scriptSigSize", "scriptPubKeySize", "witnessItemSize",
                  "inputCount", "outputCount", "witnessCount", "witnessesLength"]:
        line = re.search(r"^  " + field + r" : (.+)$", originals[proof], re.M)
        assert line, field
        add("formed-conjunct-" + field, proof, line[0],
            f"  {field} : False ∧ ({line[1]})", "Transaction WellFormed", "formed exception " + field)
    add("formed-conjunct-unambiguous", proof,
        "  unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0",
        "  unambiguous : True", "Transaction WellFormed",
        "theorem:Bitcoin/TransactionProofs.lean:readTransaction_legacy")
    add("formed-error", deser,
        "  let (txid, rest) ← takeExact 32 bytes",
        "  let (txid, rest) ← match takeExact 32 bytes with\n"
        "    | .ok pair => pure pair\n"
        "    | .error _ => throw .unknownTransactionFlags",
        "Transaction WellFormed", "formed exception measured error")
    inventory = "test-data/psbt-inventory.json"
    first = re.search(r'    \{\n[^{}]+\n    \},\n',
                      originals[inventory][originals[inventory].index('"transactions": ['):])
    assert first
    add("formed-inventory-count", inventory, first[0], "", "Transaction WellFormed", "formed inventory count")
    add("formed-conjunct-count", proof,
        "  unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0",
        "  unambiguous : tx.inputs.size > 0 ∨ tx.outputs.size = 0\n  extra : True",
        "Transaction WellFormed", "formed exception conjunct count")
    add("valid-bytes", codec, "map.flatMap Record.encode ++ [0]",
        "map.flatMap Record.encode ++ [1]", "BIP174 valid definition",
        "theorem:Bitcoin/Psbt/CodecProofs.lean:decodeMapFuel_encode")
    # Each capture rejection and edited acceptance boundary has its own selector.
    xpub = ('    checkKeyData scope keyType\n'
            '      (keyData.extract 0 4 == ⟨#[0x04, 0x88, 0xb2, 0x1e]⟩ ||\n'
            '       keyData.extract 0 4 == ⟨#[0x04, 0x35, 0x87, 0xcf]⟩) "invalid extended key version"\n')
    def parity(label, old, new, name=None, path=fields):
        name = name or label
        add("parity-" + label, path, old, new, "parity " + name, "parity " + name)

    parity("xpub-version", xpub, "")
    parity("partial-sig-empty", '    checkValue scope keyType (!value.isEmpty) "empty ECDSA signature"\n', "")
    parity("partial-sig-sighash",
           '(standardEcdsaSighash value[value.size - 1]!)', '(true)')
    for kind, name in [("inTapKeySig", "tap-key-sig-sighash"),
                       ("inTapScriptSig", "tap-script-sig-sighash")]:
        start = originals[fields].index(f"  else if keyType == KeyType.{kind} then")
        end = originals[fields].index("  else if ", start + 3)
        old = originals[fields][start:end]
        new = replace(old, '    checkValue scope keyType (validTapSighash value) "non-standard Taproot sighash type"\n', '')
        parity(name, old, new)
    parity("leaf-script-odd", 'version.toNat % 2 == 0 && version != 0x50',
           'version != 0x50')
    parity("leaf-script-annex", 'version.toNat % 2 == 0 && version != 0x50',
           'version.toNat % 2 == 0')
    parity("control-block-annex",
           '    checkKeyData scope keyType (validLeafVersion (keyData[0]! &&& 0xfe)) "invalid control block leaf version"\n', '')
    parity("out-tap-tree-annex", '(leaves.all (fun leaf => validLeafVersion leaf.leafVersion))',
           '(leaves.all (fun leaf => leaf.leafVersion.toNat % 2 == 0))')
    parity("proprietary-1025", 'rest.length ≤ 1025', 'rest.length ≤ 1026')
    parity("partial-sig-83", '[1, 2, 3, 129, 130, 131].contains sighash',
           '[1, 2, 3, 129, 130].contains sighash')
    parity("tap-key-sig-00", 'signature[64]! == 0 ||', 'signature[64]! == 1 ||')
    parity("tap-key-sig-83", 'standardEcdsaSighash signature[64]!',
           '(standardEcdsaSighash signature[64]! && signature[64]! != 131)')
    parity("leaf-script-c2", '(validLeafVersion value[value.size - 1]!)',
           '(validLeafVersion value[value.size - 1]! && value[value.size - 1]! != 0xc2)')
    parity("out-tap-tree-c2", '(leaves.all (fun leaf => validLeafVersion leaf.leafVersion))',
           '(leaves.all (fun leaf => validLeafVersion leaf.leafVersion && leaf.leafVersion != 0xc2))')
    parity("control-block-c2", '(validLeafVersion (keyData[0]! &&& 0xfe))',
           '(validLeafVersion (keyData[0]! &&& 0xfe) && (keyData[0]! &&& 0xfe) != 0xc2)')
    parity("tpub", xpub, replace(xpub,
           'keyData.extract 0 4 == ⟨#[0x04, 0x35, 0x87, 0xcf]⟩', 'false'))
    parity("proprietary-1024", 'rest.length ≤ 1025', 'rest.length ≤ 1024')
    for name, raw in [("key-type-fd01", "[0xfd, 1]"), ("key-type-fd0500", "[0xfd, 5, 0]")]:
        parity(name, '  let (keyType, rest) ← liftDecode (readCompactSize key.data.toList)',
               f'  let (keyType, rest) ← if key.data.toList == {raw} then pure (253, [])\n'
               '    else liftDecode (readCompactSize key.data.toList)', path=codec)
    parity("proprietary-subtype-fd01", '    | .error _ => false\n    | .ok _ => true',
           '    | .error _ => true\n    | .ok _ => true')
    parity("xpub-depth", '(source.path.length == keyData[4]!.toNat)', '(true)')
    # These classifications follow diagnostics from the isolated discovery checks.
    proof_caught = {
        "trailing-data": ("Bitcoin/Psbt/CodecProofs.lean", "decodePsbtWith_ok"),
        "network-magic": ("Bitcoin/Psbt/CodecProofs.lean", "decodePsbtWith_ok"),
        "map-canonical": ("Bitcoin/Psbt/CodecProofs.lean", "decodeMapFuel_encode"),
        "exact-duplicate": ("Bitcoin/Psbt/CodecProofs.lean", "decodeMapFuel_ok"),
        "vector-bip174-invalid": ("Bitcoin/Psbt/CodecProofs.lean", "decodeMapFuel_ok"),
        "witness-marker-flag": ("Bitcoin/TransactionProofs.lean", "readTransaction_witness"),
        "legacy-version": ("Bitcoin/TransactionProofs.lean", "serializeTransaction_data"),
    }
    for label in ["bip174-valid", "bip174-signer", "bip370-valid", "bip371-valid", "bip174-roles"]:
        proof_caught["vector-" + label] = ("Bitcoin/Psbt/CodecProofs.lean", "decodeMapFuel_encode")
    for label in ["rewrite-raw-input", "rewrite-raw-output"]:
        proof_caught[label] = ("Bitcoin/Psbt/ParseProofs.lean", "Psbt.parse_serialize")
    result = [(label, path, changed, selection,
               "theorem:" + ":".join(proof_caught[label]) if label in proof_caught else expected)
              for label, path, changed, selection, expected in result]
    return result


def run(label, selection):
    command = ["lake", "test", "--", "--psbt", selection] if selection else ["lake", "test"]
    stdout, stderr = LOGS / f"{label}.stdout", LOGS / f"{label}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(command, cwd=PACKAGE, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    return result.returncode, command, stdout.read_text() + stderr.read_text()


def main():
    for signum in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
        signal.signal(signum, cancelled)
    LOGS.mkdir(parents=True, exist_ok=True)
    names = ["Bitcoin/Psbt/Fields.lean", "Bitcoin/Psbt/Codec.lean", "Bitcoin/Psbt/SamePoint.lean",
             "Bitcoin/Deserialization.lean", "Bitcoin/Base64.lean", "Bitcoin/CompactSize.lean",
             "Bitcoin/PsbtVectors.lean", "Bitcoin/Transaction.lean",
             "Bitcoin/TransactionProofs.lean", "Bitcoin/Psbt/CodecProofs.lean",
             "Bitcoin/Psbt/ParseProofs.lean", "Bitcoin/Psbt/Proofs.lean",
             "BitcoinTests/TransactionChecks.lean", "test-data/psbt-inventory.json",
             "test-data/cyberkrill-psbt-capture.json",
             "measure-psbt-exception.lean"]
    originals = {name: (PACKAGE / name).read_text() for name in names}
    cases = mutations(originals)
    selected = sys.argv[1:]
    discover = "--discover" in selected
    if discover:
        selected.remove("--discover")
    resume = selected == ["--resume"]
    if resume:
        selected = []
    assert not selected or all(label in [c[0] for c in cases] for label in selected)
    context_paths = [PACKAGE / "Bitcoin.lean", PACKAGE / "BitcoinTests.lean", PACKAGE / "lakefile.lean"]
    for directory in ["Bitcoin", "BitcoinTests"]:
        context_paths.extend(sorted((PACKAGE / directory).rglob("*.lean")))
    context = Path(__file__).read_text() + "".join(originals.values()) + "".join(p.read_text() for p in context_paths)
    context_hash = hashlib.sha256(context.encode()).hexdigest()
    records = []
    for label, name, changed, selection, expected in cases:
        if selected and label not in selected:
            continue
        path = PACKAGE / name
        assert all((PACKAGE / n).read_text() == s for n, s in originals.items())
        fingerprint = hashlib.sha256((context_hash + changed + selection + expected).encode()).hexdigest()
        checkpoint = LOGS / f"{label}.record.json"
        if resume and checkpoint.exists():
            saved = json.loads(checkpoint.read_text())
            if saved["fingerprint"] == fingerprint:
                records.append(saved["record"])
                print(f"{label}: recorded EXIT=1; unchanged source/test fingerprint", flush=True)
                continue
        try:
            path.write_text(changed)
            assert path.read_text() == changed
            print(f"{label}: mutation applied", flush=True)
            status, command, output = run(label, selection)
            assert status == 1, (label, status, output)
            if discover:
                failures = [line for line in output.splitlines()
                            if "assertion failed:" in line or line.startswith("error:")]
                assert failures, (label, output)
                failure = failures[0]
            elif expected.startswith("theorem:"):
                target = expected.split(":", 1)[1]
                theorem_file, theorem = target.split(":") if ":" in target else (name, target)
                unmutated = originals[theorem_file]
                declaration = re.search(r"^(?:private )?theorem " + re.escape(theorem) + r"\b", unmutated, re.M)
                assert declaration, (theorem_file, theorem)
                start = unmutated[:declaration.start()].count("\n") + 1
                following = re.search(r"\n(?:private )?(?:theorem |def |end )", unmutated[declaration.end():])
                end_offset = declaration.end() + following.start() if following else len(unmutated)
                end = unmutated[:end_offset].count("\n") + 1
                diagnostic = re.compile(r"^error: " + re.escape(theorem_file) + r":(\d+):")
                failures = [line for line in output.splitlines() if diagnostic.search(line) and
                    start <= int(diagnostic.search(line)[1]) <= end]
                assert failures, (label, output)
                failure = failures[0]
            else:
                assert re.search(r"Bitcoin axiom gate: \d+ library theorems; 60 named; 0 offenders", output), output
                failures = [line for line in output.splitlines()
                            if "assertion failed:" in line or line.startswith("error:")]
                assert failures and "assertion failed: " + expected in failures[0], (label, output)
                failure = failures[0]
            record = dict(property=selection, mutation=label, source=name, command=command,
                          exit=status, failure=failure)
            if not discover and expected.startswith("theorem:"):
                record.update(theorem=theorem, theorem_file=theorem_file)
            records.append(record)
            if not discover:
                pending = checkpoint.with_suffix(".pending")
                pending.write_text(json.dumps(dict(fingerprint=fingerprint, record=record), indent=2) + "\n")
                pending.replace(checkpoint)
            print(f"{label}: EXIT={status}; {failure}", flush=True)
        finally:
            path.write_text(originals[name])
            assert path.read_text() == originals[name]
    status, command, output = run("restored-tests", None)
    assert status == 0, output
    destination = LOGS / "discovery-records.json" if discover else (
        LOGS / "selected-records.json" if selected else PACKAGE / "test-data/psbt-mutations.json")
    destination.write_text(json.dumps(records, indent=2) + "\n")
    print(f"PSBT mutations: {len(records)}/{len(selected) if selected else len(cases)} detected; restored lake test: EXIT=0")


if __name__ == "__main__":
    main()
