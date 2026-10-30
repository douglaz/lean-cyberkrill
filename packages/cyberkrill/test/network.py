#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Shared pre-spawn refusals and bounded, loopback-only network test execution."""
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

CORE_COMMANDS = {"onchain-list-utxos", "onchain-create-psbt", "onchain-create-funded-psbt", "onchain-move-utxos"}


def fiat(value):
    suffix = re.split(r"[0-9.,]", value.strip())[-1].strip().lower()
    return bool(re.fullmatch(r"[a-z]{3}", suffix)) and suffix not in {"btc", "sat", "sats", "msat", "msats"}


def flag_values(args, name):
    result = []
    for index, token in enumerate(args):
        if token == "--": break
        if token == name and index + 1 < len(args): result.append(args[index + 1])
        elif token.startswith(name + "="): result.append(token[len(name) + 1:])
    return result


def url_material(token):
    yield token
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    for match in re.finditer(r"(?:fed1|lnurl1)[a-z0-9]+", token.lower()):
        # The HRP itself can contain `1`: Fedimint's `fed1` precedes the
        # separator, so a real invite starts with `fed11`.
        encoded = match[0].rsplit("1", 1)[1]
        if len(encoded) < 6 or any(c not in alphabet for c in encoded): continue
        bits, count, decoded = 0, 0, bytearray()
        for c in encoded[:-6]:
            bits = (bits << 5) | alphabet.index(c)
            count += 5
            if count >= 8:
                count -= 8
                decoded.append((bits >> count) & 255)
                bits &= (1 << count) - 1
        yield decoded.decode("latin1")


def refuse_spawn(args, stub_url=None):
    """Validate command argv before starting either implementation's binary."""
    args = list(map(str, args))
    if not args: return
    command = args[0]
    # Repeated URL decoding catches nested invite/address URLs as well as URL flags.
    for token in args:
        for _ in range(4):
            if any(re.search(r":0*8332(?:\D|$)", value) for value in url_material(token)):
                raise ValueError("spawn refused: default RPC port")
            decoded = unquote(token)
            if decoded == token: break
            token = decoded
    if command == "onchain-dca-report":
        raise ValueError("spawn refused: hardcoded DCA endpoint")
    if command in CORE_COMMANDS:
        urls = flag_values(args, "--rpc-url")
        expected = urlsplit(stub_url or "")
        valid = bool(urls) and expected.hostname == "127.0.0.1" and expected.port not in {None, 0, 8332}
        for url in urls:
            try:
                parsed = urlsplit(url)
                valid = valid and parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port == expected.port and parsed.username is None and parsed.password is None
            except ValueError:
                valid = False
        if not valid:
            raise ValueError("spawn refused: explicit stub RPC URL required")
    amounts = flag_values(args, "--max-amount")
    for value in flag_values(args, "--outputs"):
        # Commas also occur in fiat grouping; examine each amount suffix and whole tail.
        amounts.extend(part.rsplit(":", 1)[-1] for part in value.split(","))
        amounts.append(value.rsplit(":", 1)[-1])
    if command == "convert-amount":
        amounts.extend(args[1:])
    if command == "ln-generate-invoice":
        # GenerateInvoiceArgs has ADDRESS AMOUNT and optional comment/output
        # values. Options may precede or separate the two positionals.
        positional = []
        rest = iter(args[1:])
        for token in rest:
            if token == "--":
                positional.extend(rest)
                break
            if token in {"--comment", "-c", "--output", "-o"}:
                next(rest, None)
            elif token.startswith(("--comment=", "--output=", "-c", "-o")) or token in {"--help", "-h"}:
                continue
            else:
                positional.append(token)
        amounts.extend(positional[1:2])
    if any(fiat(value) for value in amounts):
        raise ValueError("spawn refused: hardcoded fiat endpoints")


def checked_run(executable, args, *, stub_url=None, **kwargs):
    refuse_spawn(args, stub_url)
    return subprocess.run([str(executable), *args], **kwargs)


def namespace():
    try: return os.readlink("/proc/self/ns/net")
    except OSError: return None


def isolated():
    current = namespace()
    parent = os.environ.get("LCK_TEST_NET_PARENT")
    marker = os.environ.get("LCK_TEST_NETNS")
    return (current is not None and marker == current and parent is not None and parent != current
            and os.environ.get("LCK_TEST_NET_PID") == str(os.getpid()))


def sandbox():
    # An inherited host marker cannot satisfy the sandbox filesystem contract.
    if not (os.environ.get("LCK_RPC_SANDBOX") == "1" and
            os.environ.get("NIX_BUILD_TOP") == "/build" and Path.cwd().is_relative_to("/build")):
        return False
    try:
        return Path("/build/rpc-network-namespace").read_text(encoding="ascii").strip() == namespace()
    except (OSError, UnicodeError):
        return False


def run_owned(command, *, timeout, env=None, capture_output=False):
    """Wait in the foreground, containing and reaping this invocation's tree.

    Linux subreaping keeps orphaned grandchildren ours until waitpid collects
    them. The child unblocks managed signals before exec, as in the gate.
    """
    import ctypes
    managed = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
    libc = ctypes.CDLL(None, use_errno=True)
    previous_subreaper = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous_subreaper), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot read child subreaper state")
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot enable child subreaper")
    child = None
    handlers = {}
    def children(pid):
        try: return list(map(int, Path(f"/proc/{pid}/task/{pid}/children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError): return []
    def identity(pid):
        try: return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except (FileNotFoundError, ProcessLookupError): return None
    # Do not claim siblings already owned by the caller. Newly adopted children
    # belong to this foreground invocation, including nested runner sessions.
    baseline = {pid: identity(pid) for pid in children(os.getpid())}
    owned = {}
    def discover():
        pending = [*owned, *(pid for pid in children(os.getpid())
                                      if baseline.get(pid) != identity(pid))]
        seen = set()
        while pending:
            pid = pending.pop()
            if pid in seen: continue
            seen.add(pid)
            current = identity(pid)
            if current is None or (pid in owned and owned[pid] != current): continue
            owned[pid] = current
            pending.extend(children(pid))
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    def reap():
        discover()
        child.poll()
        for pid in tuple(owned):
            if pid == child.pid: continue
            try: os.waitpid(pid, os.WNOHANG)
            except ChildProcessError: pass
        for pid, started in tuple(owned.items()):
            if identity(pid) != started: del owned[pid]
    def alive():
        reap()
        try: os.killpg(child.pid, 0); return True
        except ProcessLookupError: return bool(owned)
    def signal_owned(signum):
        # Nested runners and their descendants may occupy separate sessions.
        for pid in tuple(owned):
            if identity(pid) != owned[pid]: continue
            try:
                os.kill(pid, signum)
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError: pass
        try:
            os.killpg(child.pid, signum)
            os.killpg(child.pid, signal.SIGCONT)
        except ProcessLookupError: pass
    def stop():
        for signum, duration in [(signal.SIGTERM, 0.2), (signal.SIGKILL, 2.0)]:
            if not alive(): break
            signal_owned(signum)
            deadline = time.monotonic() + duration
            while alive() and time.monotonic() < deadline:
                # Discovery can adopt a child forked during the last snapshot.
                # Apply this round's signal to it before waiting again.
                signal_owned(signum)
                time.sleep(0.01)
        child.wait(timeout=1)
        if alive(): raise RuntimeError("isolated test process tree did not stop")
    try:
        for signum in managed: handlers[signum] = signal.signal(signum, interrupted)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            bootstrap = ("import os,signal,sys;"
                         "signal.pthread_sigmask(signal.SIG_UNBLOCK,tuple(map(int,sys.argv[1:5])));"
                         "os.execvpe(sys.argv[5],sys.argv[5:],os.environ)")
            child = subprocess.Popen([sys.executable, "-I", "-c", bootstrap,
                                      *map(str, managed), *map(str, command)],
                                     start_new_session=True, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE if capture_output else None,
                                     stderr=subprocess.PIPE if capture_output else None)
            started = identity(child.pid)
            if started is not None: owned[child.pid] = started
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        stdout, stderr = child.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    finally:
        # Once cleanup starts, repeated interruption cannot abandon descendants.
        for signum in handlers: signal.signal(signum, signal.SIG_IGN)
        try:
            if child is not None: stop()
        finally:
            for signum, handler in handlers.items(): signal.signal(signum, handler)
            if libc.prctl(36, previous_subreaper.value, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "cannot restore child subreaper state")


def run_isolated(command, *, timeout=180):
    if sandbox() or isolated():
        return run_owned(command, timeout=timeout).returncode
    unshare = shutil.which("unshare")
    if unshare is None:
        print("SKIP (no unshare)", flush=True)
        return 0
    probe = run_owned([unshare, "-rn", "true"], capture_output=True, timeout=10)
    if probe.returncode:
        print("SKIP (no unshare)", flush=True)
        return 0
    env = dict(os.environ, LCK_TEST_NET_PARENT=namespace() or "unavailable", PYTHONDONTWRITEBYTECODE="1")
    env.pop("LCK_TEST_NETNS", None)
    env.pop("LCK_RPC_SANDBOX", None)
    wrapper = Path(__file__).resolve()
    # A loopback failure is distinct from an unavailable/refused unshare.
    args = [unshare, "-rn", "sh", "-c", 'ip link set lo up || exit 125; exec "$@"',
            "network-tests", sys.executable, "-B", str(wrapper), "--inside", *command]
    return run_owned(args, env=env, timeout=timeout).returncode


def main():
    if sys.argv[1:2] == ["--inside"]:
        current = namespace()
        if not current or current == os.environ.get("LCK_TEST_NET_PARENT"):
            raise RuntimeError("network namespace did not change")
        os.environ["LCK_TEST_NETNS"] = current
        os.environ["LCK_TEST_NET_PID"] = str(os.getpid())
        os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
    raise RuntimeError("network test wrapper requires isolated entry")


if __name__ == "__main__": main()
