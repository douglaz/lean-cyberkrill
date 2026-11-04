#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Publish executed evidence while retaining the independently pinned landed record."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

from cases import APP

HISTORIES = {'attached-output-refresh.json': 'c6f818433d7bccd4caf3f642bf72b1c2da8a7c4dd56cfe34545977cb8eefd2b3', 'lightning-mutation-record.json': '56921d449ce69bfec4bb9c2362ff313c220650476808b56e87ee8bbb3a4ee4d3', 'list-utxos-lexical-mutation-record.json': '7428bdb1a6e2c115b3ccc6a3f699b453eef0aa5f974207195bd89fbdc1aabf82', 'list-utxos-mutation-record.json': 'e73be9f5fae88a1da5c0f55e7ee406577a0817c8a0163fe780c005658ce6f613', 'mutation-record.json': '212fc82cf71d7fb10ff6cb35203bea6cbff83e98d7e7c2134b2270bdc264c525', 'offline-mutation-record.json': '0c6d1a01a3ca5e0caa173458489a26841370f9fda2076151de65431bc6881fb0', 'output-regression-refresh.json': '6ba426c10f23ec7a4552e5d80048b9c5ddde36a12e12175b9c4b4bb44f4797f1', 'psbt-commands-mutation-record.json': 'f97e430515625daac7b9cb11d34912fc0b68b8f2eecf49e00bb8aea0b6067789', 'regression-refresh.json': '540bdb0f4b7ecc04abea192ef364f42954b72a2dfec65d0f575473696e0d583d', 'revision-mutation-record.json': '6bf012cef7ed9bc063fbe475e733b82cc5d7dc48221de3cc49dfd29e27f3afc4', 'rpc-client-mutation-record.json': 'fbf1f2cab997d9a191c219429e14c647f580f4c6b2e922dbb6e3edb3dee4dc3e'}


def digest(record):
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def publish_history(path, serialized, encoding="utf-8"):
    path = Path(path)
    previous = json.loads(path.read_bytes())
    history = previous.get("pre_move_observation", previous)
    assert digest(history) == HISTORIES[path.name], "pre-move publication history: " + path.name
    record = json.loads(serialized)
    assert "pre_move_observation" not in record, "producer must publish current evidence separately"
    record["pre_move_observation"] = history
    if "pre_move_observation" in previous:
        record["previous_move_observation"] = {k: v for k, v in previous.items() if k != "pre_move_observation"}
    # A failed publication leaves the old record intact.
    with tempfile.NamedTemporaryFile(mode="w", encoding=encoding, dir=path.parent,
                                     prefix=path.name + ".", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(json.dumps(record, indent=2) + "\n")
            output.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def selftest():
    with tempfile.TemporaryDirectory(prefix="history-publication-", dir=os.environ["TMPDIR"]) as directory:
        for name, pin in HISTORIES.items():
            prior = json.loads((APP / "test/golden" / name).read_bytes())
            history = prior.get("pre_move_observation", prior)
            assert digest(history) == pin, "publication control fixed history"
            path = Path(directory) / name
            path.write_text(json.dumps(history))
            for attempt in [1, 2]:
                publish_history(path, json.dumps(dict(executed=attempt)))
                record = json.loads(path.read_bytes())
                assert record.get("pre_move_observation") == history, "history publication retains landed observation"
                assert record["executed"] == attempt, "history publication current execution"
            damaged = dict(record, pre_move_observation={})
            path.write_text(json.dumps(damaged))
            saved = path.read_bytes()
            try:
                publish_history(path, json.dumps(dict(executed=3)))
            except AssertionError as error:
                assert "pre-move publication history" in str(error), "publication refusal assertion"
            else:
                raise AssertionError("history publication must refuse damaged history")
            assert path.read_bytes() == saved, "publication refusal preserves destination"
    print("history publication: 11 first refreshes, 11 repeated refreshes, 11 damaged-history refusals")


if __name__ == "__main__":
    selftest()
