/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Bitcoin
import Lean.Data.Json

namespace BitcoinTests.Bip39Tests

open Bitcoin.Bip39

deriving instance BEq for Except
private instance : Inhabited Error := ⟨.badChecksum⟩

private def check (name : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError s!"assertion failed: {name}"

-- Diagnostics deliberately contain neither input words nor entropy.
private def getOk {ε α : Type} (name : String) (value : Except ε α) : IO α :=
  match value with
  | .ok result => pure result
  | .error _ => throw <| IO.userError s!"assertion failed: {name}"

private def load : IO (Array (ByteArray × List String)) := do
  let fixture ← getOk "bip39 English JSON" (Lean.Json.parse
    (← IO.FS.readFile "test-data/bip39-english-vectors.json"))
  let rows ← getOk "bip39 English rows" fixture.getArr?
  check "bip39 English count" (rows.size == 24)
  let mut result := #[]
  for i in [:rows.size] do
    let label := s!"bip39 English vector {i}"
    let fields ← getOk s!"{label} object" rows[i]!.getObj?
    check s!"{label} fields" (fields.size == 2 && fields.contains "entropy" && fields.contains "mnemonic")
    let entropy ← getOk s!"{label} entropy field" (rows[i]!.getObjValAs? String "entropy")
    let mnemonic ← getOk s!"{label} mnemonic field" (rows[i]!.getObjValAs? String "mnemonic")
    let some bytes := Bitcoin.Hex.decode entropy
      | throw <| IO.userError s!"assertion failed: {label} hex"
    result := result.push (bytes, mnemonic.splitOn " ")
  for count in [12, 18, 24] do
    check s!"bip39 English-{count} count" ((result.filter (fun row => row.2.length == count)).size == 8)
  pure result

def wordlistFile : IO Unit := do
  let bytes ← IO.FS.readBinFile "Bitcoin/bip39-english.txt"
  let some text := String.fromUTF8? bytes
    | throw <| IO.userError "assertion failed: bip39 wordlist UTF-8"
  let lines := text.splitOn "\n"
  let words := lines.take (lines.length - 1)
  check "bip39 wordlist count" (words.length == 2048)
  check "bip39 wordlist bytes" (bytes.size == 13116)
  check "bip39 wordlist digest" (Bitcoin.Hex.encode (Sha256.hash bytes) ==
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
  check "bip39 wordlist LF" (lines.getLast? == some "" && !(text.contains '\r'))
  check "bip39 wordlist library equality" (wordlist == words)
  IO.println "bip39 wordlist: 2048/2048"

def english : IO Unit := do
  let rows ← load
  for i in [:rows.size] do
    let (e, ws) := rows[i]!
    check s!"bip39 English vector {i} encode" (entropyToMnemonic e == .ok ws)
    check s!"bip39 English vector {i} decode" (mnemonicToEntropy ws == .ok e)
  IO.println "bip39 English: 24/24"
  for count in [12, 18, 24] do IO.println s!"bip39 English-{count}: 8/8"

def derived (width count : Nat) : IO Unit := do
  let rows := (← load).filter (fun row => row.2.length == 24)
  check s!"bip39 derived-{count} count" (rows.size == 8)
  for i in [:rows.size] do
    let e := rows[i]!.1.extract 0 width
    let ws ← getOk s!"bip39 derived-{count} vector {i} encode" (entropyToMnemonic e)
    check s!"bip39 derived-{count} vector {i} words" (ws.length == count)
    check s!"bip39 derived-{count} vector {i} roundtrip" (mnemonicToEntropy ws == .ok e)
    let decoded ← getOk s!"bip39 derived-{count} vector {i} decode" (mnemonicToEntropy ws)
    check s!"bip39 derived-{count} vector {i} re-encode" (entropyToMnemonic decoded == .ok ws)
  IO.println s!"bip39 derived-{count}: 8/8"

private def validCases : IO (Array (List String)) := do
  let rows ← load
  let long := rows.filter (fun row => row.2.length == 24)
  check "bip39 valid source count" (long.size == 8)
  let mut result := rows.map Prod.snd
  for width in [20, 28] do
    for i in [:long.size] do
      let ws ← getOk s!"bip39 derived source {width} vector {i} encode"
        (entropyToMnemonic (long[i]!.1.extract 0 width))
      result := result.push ws
  check "bip39 valid cases count" (result.size == 40)
  for count in [12, 15, 18, 21, 24] do
    check s!"bip39 valid-{count} count" ((result.filter (fun ws => ws.length == count)).size == 8)
  pure result

private def flipChecksum (ws : List String) : List String :=
  let i := wordlist.idxOf ws.getLast!
  ws.set (ws.length - 1) wordlist[i ^^^ 1]!

def badChecksum : IO Unit := do
  let cases ← validCases
  check "bip39 bad-checksum count" (cases.size == 40)
  for i in [:cases.size] do
    let ws := cases[i]!
    check s!"bip39 bad-checksum vector {i} last index" (wordlist.idxOf ws.getLast! < 2048)
    check s!"bip39 bad-checksum vector {i} rejected" (mnemonicToEntropy (flipChecksum ws) == .error .badChecksum)
  IO.println "bip39 bad-checksum: 40/40"
  for count in [12, 15, 18, 21, 24] do IO.println s!"bip39 bad-checksum-{count}: 8/8"

def unknownWord : IO Unit := do
  let rows ← load
  let ws := rows[0]!.2
  let word := ws[0]!
  -- English vector 0 starts with a word of at least five letters.
  let cases : Array (Nat × String) := #[(0, "not-a-bip39-word"),
    (1, String.ofList (word.toList.head!.toUpper :: word.toList.tail)), (2, word ++ " "),
    (3, String.ofList (word.toList.take 4)), (4, "")]
  check "bip39 unknown-word count" (cases.size == 5)
  check "bip39 unknown-word source length" (word.toList.length ≥ 5)
  for i in [:cases.size] do
    let (position, replacement) := cases[i]!
    check s!"bip39 unknown-word case {i} absent" (!(wordlist.contains replacement))
    check s!"bip39 unknown-word case {i} position"
      (mnemonicToEntropy (ws.set position replacement) == .error (.unknownWord position))
  IO.println "bip39 unknown-word: 5/5"

def checkOrder : IO Unit := do
  let ws := (← load)[0]!.2
  let unknown := "not-a-bip39-word"
  let cases : Array (List String × Error) := #[
    ((ws.take 11).set 2 unknown, .badWordCount),
    ((flipChecksum ws).set 3 unknown, .unknownWord 3),
    ((ws.set 7 unknown).set 2 unknown, .unknownWord 2)]
  check "bip39 check-order count" (cases.size == 3)
  check "bip39 check-order replacement absent" (!(wordlist.contains unknown))
  for i in [:cases.size] do
    let (words, error) := cases[i]!
    check s!"bip39 check-order case {i} precedence" (mnemonicToEntropy words == .error error)
  IO.println "bip39 check-order: 3/3"

def badWordCount : IO Unit := do
  let rows ← load
  let short := rows[0]!.2
  let long := (rows.filter (fun row => row.2.length == 24))[0]!
  let fifteen ← getOk "bip39 bad-count derived-15 source" (entropyToMnemonic (long.1.extract 0 20))
  let twentyone ← getOk "bip39 bad-count derived-21 source" (entropyToMnemonic (long.1.extract 0 28))
  let cases : Array (List String) := #[short.take 11, short ++ [short[0]!],
    long.2 ++ [long.2[0]!], [], fifteen.take 14, fifteen ++ [fifteen[0]!],
    twentyone.take 20, twentyone ++ [twentyone[0]!]]
  check "bip39 bad-word-count count" (cases.size == 8)
  let counts := #[11, 13, 25, 0, 14, 16, 20, 22]
  for i in [:cases.size] do
    check s!"bip39 bad-word-count case {i} source length" (cases[i]!.length == counts[i]!)
    check s!"bip39 bad-word-count case {i} rejected" (mnemonicToEntropy cases[i]! == .error .badWordCount)
  IO.println "bip39 bad-word-count: 8/8"

def badEntropyLength : IO Unit := do
  let rows ← load
  let short := rows[0]!.1
  let long := (rows.filter (fun row => row.2.length == 24))[0]!.1
  let cases : Array ByteArray := #[short.extract 0 0, short.extract 0 15,
    short ++ short.extract 0 1, long ++ short.extract 0 1, long ++ short.extract 0 4]
  check "bip39 bad-entropy-length count" (cases.size == 5)
  let lengths := #[0, 15, 17, 33, 36]
  for i in [:cases.size] do
    check s!"bip39 bad-entropy-length case {i} source length" (cases[i]!.size == lengths[i]!)
    check s!"bip39 bad-entropy-length case {i} rejected" (entropyToMnemonic cases[i]! == .error .badEntropyLength)
  IO.println "bip39 bad-entropy-length: 5/5"

def run (selection : Option String := none) : IO Unit := do
  match selection with
  | none =>
    wordlistFile; english; derived 20 15; derived 28 21; badChecksum
    unknownWord; checkOrder; badWordCount; badEntropyLength
  | some "wordlist" => wordlistFile
  | some "english" => english
  | some "derived-15" => derived 20 15
  | some "derived-21" => derived 28 21
  | some "bad-checksum" => badChecksum
  | some "unknown-word" => unknownWord
  | some "check-order" => checkOrder
  | some "bad-word-count" => badWordCount
  | some "bad-entropy-length" => badEntropyLength
  | some _ => throw <| IO.userError "unknown bip39 test selection"

end BitcoinTests.Bip39Tests
