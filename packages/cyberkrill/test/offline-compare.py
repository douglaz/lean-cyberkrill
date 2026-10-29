#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Full output comparison with three narrowly pinned Phase 7c exception kinds."""
import importlib
from decimal import Decimal

from compare import differences, exact_json

ORACLE = importlib.import_module("psbt-oracle")


def check_newline(reference, actual, name):
    if not reference:
        assert actual == "", "offline output newline: " + name
    elif reference.endswith("\n"):
        assert actual == actual.rstrip() + "\n", "offline output newline: " + name
    else:
        assert actual == actual.rstrip(), "offline output newline: " + name


class Comparator:
    def __init__(self, exceptions, errors):
        self.exceptions = {e["id"]: e for e in exceptions}
        assert len(self.exceptions) == len(exceptions), "duplicate offline exception"
        self.errors, self.used, self.used_errors = errors, set(), set()

    def compare(self, row, reference, port):
        name = row["id"]
        entry = self.exceptions.get(name)
        if entry:
            assert reference == entry["reference"], "offline reference exception pin: " + name
            self.used.add(name)
        if entry and entry["kind"] in ["v2", "bip-rules"]:
            pin = entry["port"]
            assert port["status"] == pin["status"] and port["stdout"].endswith("\n") == pin["stdout"].endswith("\n"), "offline exception status/newline: " + name
            assert port["stderr"] == pin["stderr"] and port["files"] == pin["files"], "offline exception stream/file identity: " + name
            if entry["kind"] == "bip-rules":
                assert reference["status"] == 0 and port["status"] == 1 and port["stdout"] == "", "offline BIP status direction: " + name
                assert port["stderr"] == self.errors[name], "offline BIP error identity: " + name
                self.used_errors.add(name)
            else:
                assert row.get("psbt_version") == 2 and reference["status"] == 1 and reference["stdout"] == "" and reference["stderr"], "offline v2 reference rejection: " + name
                assert port["status"] == 0 and port["stderr"] == "", "offline v2 success: " + name
                check_newline(pin["stdout"],port["stdout"],name)
                expected = ORACLE.expected(row)
                assert expected is not None, "offline v2 determinable locktime: " + name
                expected = exact_json(ORACLE.exact_text(expected))
                assert not differences(expected, exact_json(pin["stdout"])), "offline independent v2 pin: " + name
                assert not differences(expected, exact_json(port["stdout"])), "offline v2 complete JSON: " + name
            return
        assert port["files"].keys() == reference["files"].keys(), "offline observed file set: " + name
        if reference["status"] != 0:
            assert entry is None, "offline unexpected failure exception: " + name
            assert port["status"] == 1 and port["stdout"] == "", "offline ordinary failure status: " + name
            assert port["stderr"] == self.errors[name], "offline named failure: " + name
            assert port["files"] == reference["files"], "offline failed output existence/bytes: " + name
            self.used_errors.add(name)
            return
        assert port["status"] == 0, "offline success status: " + name
        assert reference["stderr"] == port["stderr"] == "", "offline success stderr: " + name
        if row.get("help"):
            assert "USAGE:" in port["stdout"] and row["args"][0] in port["stdout"], "offline help: " + name
            assert port["files"] == reference["files"], "offline help file effects: " + name
            return
        texts = [("stdout",reference["stdout"],port["stdout"])]
        for path in reference["files"]:
            a,b = reference["files"][path],port["files"][path]
            assert a["exists"] == b["exists"], "offline output existence: " + name
            if path in row.get("files", {}) and a["content"] == row["files"][path]:
                assert a == b, "offline unchanged input bytes: " + name
                continue
            if a["content"] is not None: texts.append(("file:"+path,a["content"],b["content"]))
            else: assert b["content"] is None, "offline output kind: " + name
        used_fields=set()
        for stream,ref,text in texts:
            assert isinstance(text,str) and ref.endswith("\n") == text.endswith("\n"), "offline output newline: " + name
            check_newline(ref,text,name)
            if row["args"][0] == "fm-encode-invite" or ref == "":
                assert ref == text, "offline exact string: " + name
                continue
            diffs=differences(exact_json(ref),exact_json(text),stream)
            for field,a,b in diffs:
                assert entry and entry["kind"] == "amount", "offline unlisted difference: " + name
                pins=[v for v in entry["fields"] if v["field"] == field]
                assert len(pins) == 1 and field.endswith('["value_btc"]'), "offline numeric field pin: " + name
                pin=pins[0]
                assert type(a) is type(b) is Decimal and a == Decimal(pin["reference"]) and b == Decimal(pin["port"]), "offline numeric value pin: " + name
                value=exact_json(text)["outputs"][0]["value_sats"]
                assert b == value / 10**8, "offline exact amount meaning: " + name
                used_fields.add(field)
        if entry:
            assert entry["kind"] == "amount" and used_fields == {v["field"] for v in entry["fields"]}, "offline unused numeric pin: " + name

    def finish(self):
        assert self.used == self.exceptions.keys(), "unused offline exceptions"
        assert self.used_errors == self.errors.keys(), "unused offline error pins"
