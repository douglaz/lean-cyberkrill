-- Extracted from https://github.com/bitcoin/bitcoin @ 9be056a8a72b624dae9623b2f7bded92c2a21c91, src/test/data/key_io_valid.json; MIT, see Bitcoin/LICENSE-bitcoin-core; extracted and reformatted (public P2PKH/P2SH only).
namespace BitcoinTests.CoreAddressVectors

def legacy : Array (String × String × String) := #[
  ("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo", "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac", "main"),
  ("36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm", "a914373b819a068f32b7a6b38b6b38729647cfde01c287", "main"),
  ("mzK2FFDEhxqHcmrJw1ysqFkVyhUULo45hZ", "76a914ce28b26c57472737f5c3561a1761185bd8589a4388ac", "testnet4"),
  ("2NC2hEhe28ULKAJkW5MjZ3jtTMJdvXmByvK", "a914ce0bba75891ff9ec60148d4bd4a09ee2dc5c933187", "testnet4"),
  ("mww4LvqtTMKvmeQvizPz2EQv26xTneWrbg", "76a914b4110ba93ac54afc14da3bdd19614774a2d55d2988ac", "signet"),
  ("2N1r7aC69VHeE7yQJPDLi9T1PYq4wnwvjuT", "a9145e5a35ab44b3efaea5129ba22b88ba3e2976614587", "signet"),
  ("n4fajahJrAuKbN7uNsKjLjQkz9Qn5ewJXQ", "76a914fdeca3b08e38af53d7c4c60e3ad208ce5066441088ac", "regtest"),
  ("2MxFajLApXpYk4VodBSZSt7rw8y4ryABkfA", "a91436e9f191e0b75036a77f65e2eaa4752443233fbe87", "regtest"),
  ("1FjL87pn8ky6Vbavd1ZHeChRXtoxwRGCRd", "76a914a19331b7b2627e663e25a7b001e4c0dcc5e21bc788ac", "main"),
  ("3BZECeAH8gSKkjrTx8PwMrNQBLG18yHpvf", "a9146c382dcdf5b284760c8e3fead91f7422cd76aa8787", "main"),
  ("n4YNbYuFdPwFrxSP8sjHFbAhUbLMUiY9jE", "76a914fc8f9851f3c1e4719cd0b8e4816dd4e88c72e52888ac", "testnet4"),
  ("2NAeQVZayzVFAtgeC3iYJsjpjWDmsDph71A", "a914bedc797342c03fd7a346c4c7857ca03d467013b687", "testnet4"),
  ("mnCBpkNMJEJLehgdEkzSo2eioniyJMxLpZ", "76a914493c455551e48a1423263b62b127b436106a685488ac", "signet"),
  ("2N5sNHomeNJDZv67AcFx9ES7FBZY4jx9KDA", "a9148a776a0f34d56b63e7c595f2b205dbe1c393617a87", "signet"),
  ("mfhE6jAUwjUDNZhaX1PAsDTKfneQF2Nshc", "76a91401f15a4cc063dae4f4d56b89bfbc8bcc9ae5387c88ac", "regtest"),
  ("2MxNm1VHyVU4RuP3u1c1v5aQLk2dQjwy1Qk", "a91438456f7c076356abadcc67b92ad777eb20fb9f8887", "regtest"),
  ("1G9A9j6W8TLuh6dEeVwWeyibK1Uc5MfVFV", "76a914a614da54daacdb8861f451a0b7e3c27cdf8a099e88ac", "main"),
  ("33GA3ZXbw5o5HeUrBEaqkWXFYYZmdxGRRP", "a914113ca1afeb49ff3abf176ffa19c2a2b4df19712a87", "main"),
  ("mwgS2HRbjyfYxFnR1nF9VKLvmdgMfFBmGq", "76a914b14ce7070b53cb0e4b5b5f6e253e876990aeca2e88ac", "testnet4"),
  ("2MwBVrJQ76BdaGD76CTmou8cZzQYLpe4NqU", "a9142b2c149cde619eae3d7fe995243b76a3417541aa87", "testnet4"),
  ("mfnJ8tEkqKNFE5YaHTXFxyHk2mnDK2fvDh", "76a91402e6cd77e649ad8b281271f158fc964ca3f66cb088ac", "signet"),
  ("2My83D67ir7K8PPzeT6mE2oth3ZwNTVRS9F", "a9144074d84d32ff62da7b1b3c61925b934bfeb34b0587", "signet")]

end BitcoinTests.CoreAddressVectors
