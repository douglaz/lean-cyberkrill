#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""One production mutation per property; separate streams and exact restoration.

Run from packages/http-curl inside nix develop, with no concurrent writers.
Only the responder/launcher are mutated; tests, fixtures and the index are untouched.
"""
import json
from pathlib import Path
import subprocess


def mutations():
    yield "S1", "method", "stub", 'if method != self.spec["method"]:', 'if False:', "S1 method near miss"
    path = 'if path != self.spec["path"]:'
    yield "S1", "path", "stub", path, 'if (path.partition("?")[2] != self.spec["path"].partition("?")[2] if self.spec["path"].startswith("/match") else path != self.spec["path"]):', "S1 path near miss"
    yield "S1", "query", "stub", path, 'if path.partition("?")[0] != self.spec["path"].partition("?")[0]:', "S1 query near miss"
    yield "S1", "percent", "stub", path, 'if __import__("urllib.parse", fromlist=["unquote"]).unquote(path) != __import__("urllib.parse", fromlist=["unquote"]).unquote(self.spec["path"]):', "S1 percent near miss"
    yield "S1", "body", "stub", 'return 0 if body_key(body) == self.body else None', 'return 0', "S1 body near miss"
    yield "S1", "boolean", "stub", 'return ("bool", value)', 'return ("number", Decimal(int(value)))', "S1 boolean distinct"
    yield "S1", "precision", "stub", 'return ("number", value)', 'return ("number", value.normalize())', "S1 precision distinct"
    yield "S1", "array-order", "stub", 'tuple(canonical(v) for v in value)', 'tuple(sorted((canonical(v) for v in value), key=repr))', "S1 array order"
    obj = 'tuple(sorted((k, canonical(v)) for k, v in value.items()))'
    yield "S1", "root-key-order", "stub", obj, 'tuple((k, canonical(v)) for k, v in value.items()) if "nested" in value else ' + obj, "S1 key order and canonical exponent"
    yield "S1", "nested-key-order", "stub", obj, 'tuple((k, canonical(v)) for k, v in value.items()) if "z" in value else ' + obj, "S1 key order and canonical exponent"
    yield "S1", "exact-exponent", "stub", 'parse_float=Decimal', 'parse_float=lambda v: ("raw", v)', "S1 key order and canonical exponent"
    yield "S1", "trailing-zero", "stub", 'return ("number", value)', 'return ("number", str(value) if value.as_tuple().exponent == -2 else value)', "S1 canonical trailing zero"
    yield "S1", "response-order", "stub", 'return responses[cursor]', 'return responses[min(cursor, 1)]', "S1 ordered responses"
    yield "S2", "rpc-method", "stub", 'value.get("method") != self.rpc["method"]', 'False', "S2 rpc method near miss"
    yield "S2", "rpc-params", "stub", 'return self.variants.index(params)', 'return 0', "S2 rpc params near miss"
    for label, condition, assertion in [
        ("string-id", 'value.get("id") == "cyberkrill"', "string id"),
        ("numeric-id", 'value.get("id") == Decimal(7)', "numeric id"),
        ("no-jsonrpc", '"id" not in value', "no jsonrpc")]:
        yield "S2", label, "stub", 'params = canonical(value["params"])', f'if {condition}:\n                    return None\n                params = canonical(value["params"])', f"S2 variant {assertion}"
    yield "S2", "per-variant-cursor", "stub", 'cursor = self.cursors.get(variant, 0)', 'variant = 0\n        cursor = self.cursors.get(variant, 0)', "S2 variant numeric id"
    for label, suffix in [("string-id", "string id"), ("numeric-id", "numeric id"), ("no-jsonrpc", "no jsonrpc")]:
        variant = {"string-id": 0, "numeric-id": 1, "no-jsonrpc": 2}[label]
        yield "S2", "variant-exhaustion-" + label, "stub", 'self.cursors[variant] = cursor + 1', f'self.cursors[variant] = cursor + (0 if self.rpc and variant == {variant} else 1)', f"S2 exhausted variant {suffix}"
    auth = 'authorization != self.spec["authorization"]'
    yield "S3", "missing-auth", "stub", auth, 'authorization is not None and authorization != self.spec["authorization"]', "S3 missing auth"
    yield "S3", "wrong-auth", "stub", auth, 'authorization is None', "S3 wrong auth"
    yield "S3", "auth-consumes", "stub", 'return self.spec["unauthorized"]', 'self.cursors[variant] = 1\n            return self.spec["unauthorized"]', "S3 right auth no consumption"
    yield "S4", "unmatched-status", "stub", 'response = {"status": 599, "json": diagnostic}', 'response = {"status": 404, "json": diagnostic}', "S4 unmatched status"
    for key, new in [("method", '"wrong"'), ("path", '"wrong"'), ("body", '"wrong"')]:
        yield "S4", "diagnostic-" + key, "stub", 'diagnostic = {"error": error, **received}', f'diagnostic = {{"error": error, **received}}\n                    diagnostic["{key}"] = {new}', "S4 diagnostic " + key
    yield "S4", "unmatched-reason", "stub", 'error = "unmatched"', 'error = "exhausted"', "S4 unmatched reason"
    yield "S4", "exhausted-status", "stub", 'response = {"status": 599, "json": diagnostic}', 'response = {"status": 200 if error == "exhausted" else 599, "json": diagnostic}', "S4 exhausted status"
    yield "S4", "exhausted-reason", "stub", 'error = "exhausted"', 'error = "unmatched"', "S4 exhausted reason"
    write = 'self.server.request_log.write(json.dumps(received) + "\\n")'
    yield "S4", "log-complete", "stub", write, 'if self.path != "/auth":\n                ' + write, "S4 log complete"
    yield "S4", "log-flush", "stub", 'self.server.request_log.flush()', 'pass', "S4 log complete"
    yield "S4", "log-order", "stub", write, 'self.server.request_log.seek(0)\n            previous = self.server.request_log.read()\n            self.server.request_log.seek(0)\n            self.server.request_log.truncate()\n            self.server.request_log.write(json.dumps(received) + "\\n" + previous)', "S4 log order"
    for key in ["method", "body"]:
        yield "S4", "log-" + key, "stub", write, f'self.server.request_log.write(json.dumps({{**received, "{key}": "wrong"}}) + "\\n")', "S4 log " + key
    yield "S4", "repeat-first", "stub", 'return responses[cursor]', 'return responses[-1] if self.spec.get("repeat") else responses[cursor]', "S4 repeat first"
    yield "S4", "repeat-last", "stub", 'return responses[cursor]', 'return responses[0] if self.spec.get("repeat") else responses[cursor]', "S4 repeat last"
    yield "S4", "repeat-enabled", "stub", 'if self.spec.get("repeat", False):', 'if False:', "S4 repeat repeat"
    for case in ["S5", "S6", "S7"]:
        yield case, "example-status", "stub", 'self.send_response(int(response.get("status", 200)))', 'self.send_response(201)', f"{case} example status"
        yield case, "example-body", "stub", 'body = json_text(response["json"]).encode("utf-8")', 'body = b"wrong"', f"{case} example body"
        yield case, "example-header", "stub", 'self.send_header(name, value)', 'self.send_header("X-Wrong", value)', f"{case} example header"
    yield "S7", "fixed-port", "stub", '("127.0.0.1", args.port)', '("127.0.0.1", 0)', "S7 fixed port"
    yield "S8", "occupied-exit", "stub", 'main()\n', 'try:\n        main()\n    except OSError:\n        pass\n', "S8 occupied exit"
    yield "S8", "occupied-ready", "stub", 'main()\n', 'try:\n        main()\n    except OSError:\n        print("READY 1 2", flush=True)\n        raise\n', "S8 occupied no ready"
    yield "S8", "launcher-failure", "launcher", 'args := #["-I", "../http-curl/test/responder.py", "--port", toString config.port,', 'args := #["-I", "../http-curl/test/responder.py", "--port", "0",', "S8 occupied launcher message"
    yield "S8", "double-reap", "launcher", 'unless ← reaped.get do', 'if true then', "S8 occupied launcher message"
    yield "S8", "missing-recording-error", "launcher", 'config.recordings\n', '(config.recordings.filter fun path => !path.endsWith "missing-recording.json")\n', "S8 missing recording launcher message"
    framing = '("content-length", "transfer-encoding")'
    yield "S8", "framing-content-length", "stub", framing, '("transfer-encoding",)', "S8 framing content-length rejected"
    yield "S8", "framing-transfer-encoding", "stub", framing, '("content-length",)', "S8 framing transfer-encoding rejected"
    yield "S8", "framing-case", "stub", 'name.lower() in ' + framing, 'name in ("Content-Length", "Transfer-Encoding")', "S8 framing transfer-encoding rejected"
    yield "S9", "recorded-status", "stub", 'self.send_response(int(response.get("status", 200)))', 'self.send_response(200 if response.get("status") == 404 else int(response.get("status", 200)))', "S9 recorded 404"
    yield "S9", "text-body", "stub", 'return 0 if body_key(body) == self.body else None', 'return 0', "S9 text near miss"
    yield "S9", "binary-body", "stub", 'base64.b64decode(selector["base64"], validate=True)', 'b"wrong"', "S9 binary match"
    yield "S9", "binary-diagnostic", "stub", 'return {"base64": base64.b64encode(body).decode("ascii")}', 'return {"base64": "wrong"}', "S9 diagnostic binary"
    yield "S9", "text-diagnostic", "stub", 'diagnostic = {"error": error, **received}', 'diagnostic = {"error": error, **received}\n                    if self.command == "POST": diagnostic["body"] = "wrong" if isinstance(received["body"], str) else received["body"]', "S9 diagnostic text"
    yield "S9", "post-diagnostic", "stub", 'diagnostic = {"error": error, **received}', 'diagnostic = {"error": error, **received}\n                    diagnostic["method"] = "GET"', "S9 diagnostic POST"
    yield "S9", "precedence", "stub", 'for entry in self.server.entries:', 'for entry in reversed(self.server.entries):', "S9 precedence"
    yield "S9", "precedence-exhaustion", "stub", '                        break', '                        if response is not None: break', "S9 precedence exhausted"
    yield "S9", "binary-log", "stub", write, 'self.server.request_log.write(json.dumps({**received, "body": {"base64": "wrong"}} if isinstance(received["body"], dict) else received) + "\\n")', "S9 log binary"
    yield "S9", "no-legacy-fallback", "stub", 'if self.server.replay:', 'if self.server.replay and self.path != "/echo":', "S9 no legacy fallback"
    yield "S12", "stalled-tls-eof", "stub", 'os._exit(0)', 'server.shutdown()', "S12 TLS stdin EOF deadline"
    default_type = 'if not any(name.lower() == "content-type" for name in response.get("headers", {})):'
    yield "S13", "duplicate-content-type", "stub", default_type, 'if True:', "S13 single recorded content-type /content-type/title"
    yield "S13", "content-type-case", "stub", 'name.lower() == "content-type"', 'name == "Content-Type"', "S13 single recorded content-type /content-type/lower"
    yield "S13", "content-type-mixed-case", "stub", 'name.lower() == "content-type"', 'name in ("Content-Type", "content-type")', "S13 single recorded content-type /content-type/mixed"


def main():
    paths = {"stub": Path("test/responder.py"), "launcher": Path("HttpCurlTestSupport.lean")}
    originals = {kind: path.read_bytes() for kind, path in paths.items()}
    logs = Path(".lake/stub-mutation-checks")
    logs.mkdir(parents=True, exist_ok=True)
    records = []
    try:
        for case, label, kind, old, new, assertion in mutations():
            original = originals[kind].decode()
            assert original.count(old) == 1, (case, label, old)
            mutated = original.replace(old, new)
            paths[kind].write_text(mutated)
            assert paths[kind].read_text() == mutated and new in mutated
            assert mutated.count(old) == new.count(old)
            # The reversed-log mutation needs a seekable read/write log.
            if label == "log-order":
                source = paths[kind].read_text()
                assert source.count('open(args.log, "a",') == 1
                paths[kind].write_text(source.replace('open(args.log, "a",', 'open(args.log, "a+",'))
            command = ["lake", "test", "--", "--only", case]
            prefix = logs / f"{case}-{label}"
            with prefix.with_suffix(".stdout").open("wb") as out, prefix.with_suffix(".stderr").open("wb") as err:
                result = subprocess.run(command, stdout=out, stderr=err)
            output = prefix.with_suffix(".stdout").read_text() + prefix.with_suffix(".stderr").read_text()
            failure = f"assertion failed: {assertion}"
            assert result.returncode != 0 and failure in output, (case, label, result.returncode, output)
            records.append(dict(case=case, mutation=label, command=command, exit=result.returncode, failure=failure))
            print(f"{case}/{label}: EXIT={result.returncode}; {failure}", flush=True)
            paths[kind].write_bytes(originals[kind])
            assert paths[kind].read_bytes() == originals[kind]
    finally:
        for kind, path in paths.items():
            path.write_bytes(originals[kind])
            assert path.read_bytes() == originals[kind]
        # Rebuild restored sources, so subsequent test runs cannot use a mutated binary.
        subprocess.run(["lake", "build", "HttpCurlTests"], check=True)
    assert len(records) == 72, ("dropped mutation", len(records))
    (logs / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"stub mutations: {len(records)}/72 detected; production sources restored", flush=True)


if __name__ == "__main__":
    main()
