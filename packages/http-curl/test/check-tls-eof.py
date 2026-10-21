#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Hold a TLS handshake open while closing the replay server's launcher pipe."""
from pathlib import Path
import socket
import subprocess
import sys
import time


def main():
    directory = Path(sys.argv[1])  # Private TLS artifacts owned by withStub.
    child = subprocess.Popen(
        ["python3", "-I", "../http-curl/test/responder.py", "--tls",
         "--cert", str(directory / "ca.crt"), "--key", str(directory / "server.key"),
         "--log", str(directory / "requests.jsonl"), "../http-curl/test/example.json"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # Inherit stderr.
    try:
        ready = child.stdout.readline().decode().split()
        assert len(ready) == 3 and ready[0] == "READY", ready
        with socket.create_connection(("127.0.0.1", int(ready[1])), timeout=0.5):
            # Let the accepting thread enter the handshake before sending EOF.
            time.sleep(0.1)
            start = time.monotonic()
            child.stdin.close()
            try:
                status = child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                print("TLS stub still alive 1 second after stdin EOF", file=sys.stderr)
                return 1
            elapsed = time.monotonic() - start
            assert status == 0 and elapsed <= 1, (status, elapsed)
            print("TLS silent handshake: exited 0 within 1 second of stdin EOF")
        return 0
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stdin.close()


if __name__ == "__main__":
    sys.exit(main())
