#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Minimal loopback HTTP/TLS responder; never logs Authorization or bodies."""
import argparse
import base64
import http.server
import socket
import ssl
import time


class Handler(http.server.BaseHTTPRequestHandler):
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
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
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
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    # Reserve a bound, non-listening socket for deterministic connection-refused tests.
    with socket.socket() as closed, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        closed.bind(("127.0.0.1", 0))
        server.daemon_threads = True
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert, args.key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"READY {server.server_port} {closed.getsockname()[1]}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
