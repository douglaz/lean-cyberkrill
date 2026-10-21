-- Extracted from https://github.com/bitcoin/bips @ 130b8e0fa7f30fa45532f080b87b8db27a79e46e, bip-0173.mediawiki L277-283, L291-302; bip-0350.mediawiki L156-162, L167-180; BSD-2-Clause, see LICENSE-bips; extracted and reformatted.
namespace BitcoinTests.Bech32Vectors

def bech32Valid : Array String := #[
  "A12UEL5L",
  "a12uel5l",
  "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
  "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
  "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
  "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
  "?1ezyfcl"]

def bech32Invalid : Array String := #[
  " 1nwldj5",
  "\x7f1axkwrx",
  "\x801eym55h",
  "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
  "pzry9x0s0muk",
  "1pzry9x0s0muk",
  "x1b4n0q5v",
  "li1dgmt3",
  "de1lg7wt\xff",
  "A1G7SGD8",
  "10a06t8",
  "1qzzfhee"]

def bech32mValid : Array String := #[
  "A1LQFN3A",
  "a1lqfn3a",
  "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
  "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
  "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
  "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
  "?1v759aa"]

def bech32mInvalid : Array String := #[
  " 1xj0phk",
  "\x7f1g6xzxy",
  "\x801vctc34",
  "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
  "qyrz8wqd2c9m",
  "1qyrz8wqd2c9m",
  "y1b0jsk6g",
  "lt1igcx5c0",
  "in1muywd",
  "mm1crxm3i",
  "au1s5cgom",
  "M1VUXWEZ",
  "16plkw9",
  "1p2gdwpf"]

end BitcoinTests.Bech32Vectors
