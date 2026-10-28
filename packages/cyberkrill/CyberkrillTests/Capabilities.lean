/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import CyberkrillTests.Support
namespace CyberkrillTests
open Cyberkrill Lean

def capabilities (only : String) : IO Unit := do
  -- The only signing key is the BOLT #11 specification's published example.
  let key ← hex "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
  let secret ← hex "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"
  let cap := bolt11Curve secret
  let offCurve := (ByteArray.empty.push 2) ++ ⟨Array.replicate 32 0⟩
  selected only "cap-pubkey" do
    counted "Bitcoin strict pubkey" 3 3
    check "cap Bitcoin pubkey accepts" (pubkeys.isValidPubkey key)
    check "cap Bitcoin pubkey offcurve" (!pubkeys.isValidPubkey offCurve)
    let hybrid ← hex "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    check "cap Bitcoin pubkey hybrid" (!pubkeys.isValidPubkey hybrid)
  selected only "cap-compress" do
    counted "Bitcoin compression" 3 3
    let hybrid ← hex "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    let compressed ← hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    check "cap Bitcoin compression matches" (pubkeys.compressPubkey hybrid == some compressed)
    check "cap Bitcoin compression mismatch" ((pubkeys.compressPubkey (hybrid.set! 0 7)).isNone)
    check "cap Bitcoin compression offcurve" ((pubkeys.compressPubkey offCurve).isNone)
  selected only "cap-xonly" do
    counted "Bitcoin xonly" 2 2
    check "cap Bitcoin xonly accepts" (pubkeys.isValidXOnlyPubkey (key.extract 1 33))
    check "cap Bitcoin xonly rejects" (!pubkeys.isValidXOnlyPubkey ⟨Array.replicate 32 0⟩)
  selected only "cap-der" do
    counted "Bitcoin DER" 2 2
    check "cap Bitcoin DER accepts" (pubkeys.isValidDerSignature (← hex "3006020101020101"))
    check "cap Bitcoin DER rejects" (!pubkeys.isValidDerSignature (← hex "300602010102010100"))
  selected only "cap-point" do
    counted "BOLT point" 2 2
    check "cap BOLT point accepts" (cap.isValidPubkey key)
    check "cap BOLT point rejects" (!cap.isValidPubkey offCurve)
  let json ← load "../lightning/test-data/bolt11.json"
  for (name, expected) in [("valid",16), ("invalid",15), ("nfields",2), ("negative",20),
      ("positive",4), ("outside",3), ("small",3), ("table",23), ("keys",4)] do
    counted s!"existing BOLT {name}" (← getOk "BOLT rows" (json.getObjValAs? (Array Json) name)).size expected
  let table ← getOk "BOLT table" (json.getObjValAs? (Array Json) "table")
  let pairs ← table.toList.mapM fun row => do return (← text row "hash", ← text row "signature")
  counted "BOLT distinct signature pairs" pairs.eraseDups.length 22
  let find := fun set name => do
    let rows ← getOk "BOLT rows" (json.getObjValAs? (Array Json) set)
    let some row := rows.find? (fun j => (j.getObjValAs? String "name").toOption == some name)
      | throw (IO.userError "assertion failed: BOLT case")
    return row
  selected only "cap-recover" do
    let rows ← getOk "valid BOLT rows" (json.getObjValAs? (Array Json) "valid")
    counted "real BOLT recovery" rows.size 16
    for row in rows do
      let name ← text row "name"
      let inv ← getOk s!"cap BOLT recover {name}" (Lightning.Bolt11.decode cap (← text row "invoice"))
      check s!"cap BOLT recovered key {name}" (inv.payeeKey == (← bytes row "pubkey"))
      if name == "L762" then
        check "cap BOLT L762 unnormalized" (inv.payeeKey == (← hex "02d0139ce7427d6dfffd26a326c18be754ef1e64672b42694ba5b23ef6e6e7803d"))
  selected only "cap-verify" do
    counted "real BOLT verify" 5 5
    let row ← find "nfields" "n-low"
    let inv ← getOk "cap BOLT verify decode" (Lightning.Bolt11.decode cap (← text row "invoice"))
    check "cap BOLT verify n key" (inv.toParts.payeePubkey == some key && inv.payeeKey == key)
    let high ← find "nfields" "n-high"
    check "cap BOLT high n rejects" (match Lightning.Bolt11.decode cap (← text high "invoice") with
      | .error .verifyFailed => true | _ => false)
    let sig := inv.signature.set! 0 (inv.signature[0]! ^^^ 1)
    let (hrp, data) ← getOk "cap BOLT tamper framing" (Lightning.Bolt11.encodeData inv.toParts)
    let tampered := Bitcoin.Bech32.encode hrp (data ++ Bitcoin.Bech32.convertbits8to5 sig) .bech32
    check "cap BOLT tampered signature" (match Lightning.Bolt11.decode cap tampered with
      | .error .verifyFailed => true | _ => false)
    let l858 ← find "invalid" "L858"
    let hash ← bytes l858 "hash"
    let signature := (← bytes l858 "signature").extract 0 64
    check "cap BOLT L858 raw high S" (!cap.verify hash signature key)
    let s := Lightning.Bolt11.readBytes (signature.extract 32 64)
    let normalized := signature.extract 0 32 ++ Lightning.Bolt11.writeBytes 32 (Lightning.Bolt11.curveOrder - s)
    check "cap BOLT L858 normalized" (cap.verify hash normalized key)
  selected only "cap-sign" do
    counted "real BOLT signer" 3 3
    let row ← find "nfields" "n-low"
    let hash ← bytes row "hash"
    let signature ← bytes row "signature"
    check "cap BOLT signature exact" (cap.sign hash == some signature)
    check "cap BOLT signature recovery" (cap.recover hash (signature.extract 0 64) signature[64]! == some key)
    let inv ← getOk "cap BOLT signer decode" (Lightning.Bolt11.decode cap (← text row "invoice"))
    check "cap BOLT signer invoice" ((Lightning.Bolt11.sign cap inv.toParts).toOption == some (← text row "invoice"))
  selected only "hashes" do
    counted "production preimage hashes" 2 2
    check "cap RIPEMD160" (preimageHashes.ripemd160 "abc".toUTF8 ==
      (← hex "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"))
    check "cap HASH160" (preimageHashes.hash160 "abc".toUTF8 ==
      (← hex "bb1be98c142444d7a56aa3981c3942a978e4dc33"))
end CyberkrillTests
