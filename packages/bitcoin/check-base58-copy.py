# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Check the copied slice against an externally fetched pinned upstream file."""

import difflib
from pathlib import Path
import sys


PACKAGE = Path(__file__).resolve().parent
PROVENANCE = (
    "-- Copied from febyeji/lean-miniscript @ cb9bc5f, "
    "LeanMiniscript/Bitcoin/KeyEncodingExamples.lean L29-50; MIT, see LICENSE-miniscript; "
    "originally Bitcoin Core src/test/data/base58_encode_decode.json @ 9be056a, MIT\n"
)


def main():
    assert len(sys.argv) == 2, "usage: check-base58-copy.py <pinned KeyEncodingExamples.lean>"
    upstream = Path(sys.argv[1]).read_text().splitlines(keepends=True)[28:50]
    assert len(upstream) == 22
    assert upstream[0] == "private def rawVectors : Array (String × String) := #[\n"
    assert upstream[-1] == '  ("271F35A1", "211112")]\n'
    integrated = upstream.copy()
    integrated[0] = integrated[0].removeprefix("private ")
    expected = PROVENANCE + "namespace BitcoinTests\n\n" + "".join(integrated) + "\nend BitcoinTests\n"
    assert (PACKAGE / "Bitcoin/Base58Vectors.lean").read_text() == expected
    print("".join(difflib.unified_diff(upstream, integrated,
                                     fromfile="upstream L29-50",
                                     tofile="Bitcoin/Base58Vectors.lean")), end="")
    print("copy check: only removal of private; namespace and provenance wrapping verified")


if __name__ == "__main__":
    main()
