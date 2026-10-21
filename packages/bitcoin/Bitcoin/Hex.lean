/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Sha256.Hex

namespace Bitcoin.Hex

def encode (bytes : ByteArray) : String := String.ofList (Sha256.Hex.encodeChars bytes)

/-- Decode case-insensitive hex, with no prefixes, separators or whitespace. -/
def decode (s : String) : Option ByteArray :=
  Sha256.Hex.decodeChars? (s.toList.map Char.toLower)

theorem decode_encode (bytes : ByteArray) : decode (encode bytes) = some bytes := by
  unfold decode encode
  rw [String.toList_ofList]
  have lower : (Sha256.Hex.encodeChars bytes).map Char.toLower =
      Sha256.Hex.encodeChars bytes := by
    simpa using
      (List.map_congr_left (Sha256.Hex.encodeChars_lower bytes))
  rw [lower, Sha256.Hex.decodeChars?_encodeChars]

end Bitcoin.Hex
