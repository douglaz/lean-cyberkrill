#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Loopback replay server. Logs request bodies; use only synthetic/test fixtures."""
import argparse
import base64
from decimal import Decimal
import http.server
import json
import os
import socket
import ssl
import sys
import threading
import time


def parse_json(text):
    return json.loads(text, parse_int=Decimal, parse_float=Decimal,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def canonical(value):
    # Decimal equality is exact without normalize() or context-dependent arithmetic.
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, Decimal):
        return ("number", value)
    if isinstance(value, dict):
        return ("object", tuple(sorted((k, canonical(v)) for k, v in value.items())))
    if isinstance(value, list):
        return ("array", tuple(canonical(v) for v in value))
    return (type(value).__name__, value)


def json_text(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + json_text(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(map(json_text, value)) + "]"
    return json.dumps(value)


def body_key(body):
    try:
        return ("json", canonical(parse_json(body)))
    except (ValueError, UnicodeDecodeError):
        return ("bytes", body)


def log_body(body):
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(body).decode("ascii")}


class Entry:
    def __init__(self, spec):
        self.spec = spec
        self.cursors = {}
        self.rpc = spec.get("rpc")
        self.variants = [canonical(v) for v in self.rpc["params"]] if self.rpc else []
        selector = spec.get("body", {"text": ""})
        if "json" in selector:
            self.body = ("json", canonical(selector["json"]))
        elif "text" in selector:
            self.body = body_key(selector["text"].encode("utf-8"))
        else:
            self.body = body_key(base64.b64decode(selector["base64"], validate=True))
        if not spec["responses"]:
            raise ValueError("responses must be nonempty")
        if "authorization" in spec and int(spec["unauthorized"]["status"]) != 401:
            raise ValueError("unauthorized response must have status 401")
        recorded = spec["responses"] + ([spec["unauthorized"]] if "unauthorized" in spec else [])
        for response in recorded:
            for name in response.get("headers", {}):
                if name.lower() in ("content-length", "transfer-encoding"):
                    raise ValueError(f"recorded framing header not allowed: {name}")

    def match(self, method, path, body):
        if method != self.spec["method"]:
            return None
        if path != self.spec["path"]:
            return None
        if self.rpc:
            try:
                value = parse_json(body)
                if not isinstance(value, dict) or value.get("method") != self.rpc["method"]:
                    return None
                params = canonical(value["params"])
                return self.variants.index(params)
            except (ValueError, KeyError, UnicodeDecodeError):
                return None
        return 0 if body_key(body) == self.body else None

    def response(self, variant, authorization):
        if "authorization" in self.spec and authorization != self.spec["authorization"]:
            return self.spec["unauthorized"]
        cursor = self.cursors.get(variant, 0)
        responses = self.spec["responses"]
        if cursor >= len(responses):
            if self.spec.get("repeat", False):
                return responses[-1]
            return None
        self.cursors[variant] = cursor + 1
        return responses[cursor]


class Handler(http.server.BaseHTTPRequestHandler):
    def parse_request(self):
        if not super().parse_request():
            return False
        # BaseHTTPRequestHandler collapses a leading //; replay must not do so.
        self.path = self.requestline.split()[1]
        return True

    def __getattr__(self, name):
        # BaseHTTPRequestHandler otherwise sends 501 for an unknown HTTP verb.
        if name.startswith("do_"):
            return self.respond
        raise AttributeError(name)

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected when a client rejects the certificate or aborts a body.

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        received = {"method": self.command, "path": self.path, "body": log_body(body)}
        # One lock orders the append/flush and cursor allocation, before any reply.
        with self.server.replay_lock:
            self.server.request_log.write(json.dumps(received) + "\n")
            self.server.request_log.flush()
            if self.server.replay:
                response = None
                error = "unmatched"
                for entry in self.server.entries:
                    variant = entry.match(self.command, self.path, body)
                    if variant is not None:
                        response = entry.response(variant, self.headers.get("Authorization"))
                        error = "exhausted"
                        break
                if response is None:
                    diagnostic = {"error": error, **received}
                    print(json.dumps(diagnostic), file=sys.stderr, flush=True)
                    response = {"status": 599, "json": diagnostic}
                self.send_recorded(response)
                return
        self.legacy(body)

    def send_recorded(self, response):
        if "json" in response:
            body = json_text(response["json"]).encode("utf-8")
            content_type = "application/json"
        else:
            body = response.get("text", "").encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        self.send_response(int(response.get("status", 200)))
        if not any(name.lower() == "content-type" for name in response.get("headers", {})):
            self.send_header("Content-Type", content_type)
        for name, value in response.get("headers", {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def legacy(self, body):
        if self.path == "/empty-reply":
            self.close_connection = True
            return
        if self.path == "/stall":
            time.sleep(4)
            return
        if self.path == "/oversize":
            self.send_response(200)
            self.end_headers()  # HTTP/1.0 close-delimited: no Content-Length.
            try:
                self.wfile.write(b"x" * 4096)
                self.wfile.flush()
                time.sleep(4)  # A buffered/unbounded client hits its timeout instead.
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        status = 200
        if self.path == "/auth":
            expected = "Basic " + base64.b64encode(b"synthetic-user:synthetic-password").decode()
            status = 200 if self.headers.get("Authorization") == expected else 401
        if self.path == "/exact":
            body = b"x" * 64
        if self.path == "/one-over":
            body = b"x" * 65
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        for name, value in self.headers.items():
            self.send_header("X-Echo-" + name.lower(), value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("recordings", nargs="*")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log", required=True)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    entries = []
    for path in args.recordings:
        with open(path, encoding="utf-8") as source:
            entries.extend(Entry(spec) for spec in parse_json(source.read())["entries"])
    # Reserve a bound, non-listening socket for deterministic connection-refused tests.
    with socket.socket() as closed, http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server, open(args.log, "a", encoding="utf-8") as request_log:
        closed.bind(("127.0.0.1", 0))
        server.daemon_threads = True
        server.replay_lock = threading.Lock()
        server.request_log = request_log
        server.replay = bool(args.recordings)
        server.entries = entries
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert, args.key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"READY {server.server_port} {closed.getsockname()[1]}", flush=True)
        # The launcher's pipe closes even when the launcher receives SIGKILL.
        def stop_on_eof():
            sys.stdin.buffer.read()
            # Exit even if accept() is blocked in a silent client's TLS handshake.
            # Each request log entry is already flushed before its response.
            os._exit(0)
        threading.Thread(target=stop_on_eof, daemon=True).start()
        server.serve_forever()


if __name__ == "__main__":
    main()
