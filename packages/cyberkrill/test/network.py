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



def effective_guardians(token):
    """Bounded in-process Phase 7c wrapper, consensus and fallback inspection.

    Invalid wrappers cannot reach fetch. Consensus errors use the same printable
    six-byte-marker fallback; unknown parts stop consensus parsing immediately.
    No decoder executable is started to establish destination safety.
    """
    whitespace = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    text = token.strip(whitespace)
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if not text.startswith("fed1") or len(text) > 1023 or text != text.lower():
        return []
    separator = text.rfind("1")
    if text[:separator] != "fed1" or len(text) - separator - 1 < 6:
        return []
    try: symbols = [alphabet.index(c) for c in text[separator+1:]]
    except ValueError: return []
    checksum = 1
    for value in [ord(c) >> 5 for c in "fed1"] + [0] + [ord(c) & 31 for c in "fed1"] + symbols:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> i) & 1: checksum ^= generator
    if checksum != 0x2bc830a3: return []
    bits = count = 0
    data = bytearray()
    for value in symbols[:-6]:
        bits = (bits << 5) | value
        count += 5
        if count >= 8:
            count -= 8
            data.append((bits >> count) & 255)
            bits &= (1 << count) - 1
    position = 0
    def big():
        nonlocal position
        if position >= len(data): raise ValueError("truncated")
        tag = data[position]; position += 1
        if tag < 253: return tag
        width = {253:2, 254:4, 255:8}[tag]
        return int.from_bytes(take(width), "big")
    def take(size):
        nonlocal position
        if size > len(data) - position: raise ValueError("overrun")
        result = data[position:position+size]; position += size
        return result
    def string(): return take(big()).decode("utf-8")
    try:
        parts = big(); guardians = []; federation = False
        # Every consumed part needs at least one byte. A larger count can only
        # stop on an unknown discriminator or fail before exhausting this fuel.
        for _ in range(min(parts, len(data) + 1)):
            kind = big()
            if kind == 0:
                declared = big(); start = position
                target = string(); big()
                if position - start != declared: raise ValueError("guardian length")
                guardians.append(target)
            elif kind == 1:
                if big() != 32: raise ValueError("federation length")
                take(32); federation = True
            elif kind == 2: string()
            else: break
        else:
            if parts > len(data) + 1: raise ValueError("part count")
        if not federation or not guardians: raise ValueError("missing part")
        return guardians
    except (ValueError, UnicodeDecodeError):
        guardians = []
        for pos in range(len(data)):
            marker = data[pos:pos+6]
            if pos + 6 < len(data) and marker in [b"wss://", b"https:"]:
                end = pos + 6
                while end < len(data) and 31 < data[end] < 127: end += 1
                if end > pos + 6: guardians.append(data[pos:end].decode("ascii"))
        return guardians


def permitted_guardian(target, stub_url):
    """Match the app's whole rewrite and special HTTP authority normalization.

    Fail closed outside the approved subset. Path/query text cannot change the
    already separated authority, including embedded ws:// text in fixture paths.
    """
    target = target.replace("wss://", "https://").replace("ws://", "http://").rstrip("/") + "/config"
    cleaned = target.strip("".join(map(chr, range(33)))).replace("\t", "").replace("\r", "").replace("\n", "")
    scheme, colon, rest = cleaned.partition(":")
    if not colon or scheme.lower() not in {"http", "https"}: return False
    authority = re.split(r"[/\\?#]", rest.lstrip("/\\"), maxsplit=1)[0]
    if "@" in authority or "[" in authority or "]" in authority: return False
    host, separator, port = authority.partition(":")
    if re.search(r"%(?![0-9a-fA-F]{2})", host): return False
    try:
        host = unquote(host, errors="strict").lower()
        expected = urlsplit(stub_url or "")
        return (host == expected.hostname == "127.0.0.1" and separator == ":" and
                bool(re.fullmatch(r"[0-9]+", port)) and len(port.lstrip("0")) <= 5 and
                int(port) == expected.port == 19444)
    except (ValueError, UnicodeError): return False


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
    if command == "fm-fetch-config":
        for token in args[1:]:
            for target in effective_guardians(token):
                if not permitted_guardian(target, stub_url):
                    raise ValueError("spawn refused: explicit stub guardian required")
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
        if positional:
            parts = positional[0].split("@")
            # Malformed addresses fail before any transport. A well-formed one
            # must target this invocation's owned TLS stub, including its port.
            if len(parts) == 2 and all(parts):
                try:
                    assembled = "https://" + parts[1] + "/.well-known/lnurlp/" + parts[0]
                    parsed = urlsplit(assembled)
                    expected = urlsplit(stub_url or "")
                    valid = (parsed.scheme == expected.scheme == "https" and
                             parsed.hostname == expected.hostname == "127.0.0.1" and
                             parsed.port == expected.port and parsed.port not in {None,0,8332} and
                             parsed.username is None and parsed.password is None and
                             "\\" not in assembled and all(ord(c)>=32 for c in assembled))
                    # Permit path spaces, but never concealed targets. Match the
                    # guarded entry's finite decoding and embedded-material rule.
                    material = assembled.split(parsed.netloc,1)[1]
                    for _ in range(5):
                        if any("@" in value or "\\" in value or "://" in value or
                               any(ord(c)<32 for c in value) for value in url_material(material)):
                            valid = False
                            break
                        decoded = unquote(material)
                        if decoded == material: break
                        material = decoded
                    else: valid = False
                except ValueError:
                    valid = False
                if not valid: raise ValueError("spawn refused: explicit stub Lightning address required")
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


def run_owned(command, *, timeout, env=None, capture_output=False, gate_cancellation=False, on_cancel=None):
    """Wait in the foreground, containing and reaping this invocation's tree.

    Linux subreaping keeps orphaned grandchildren ours until waitpid collects
    them. The child unblocks managed signals before exec, as in the gate.
    gate_cancellation keeps mutation commands in the outer gate's group and
    defers signal exceptions out of Popen's wait-lock acquisition boundary.
    Its on_cancel callback only records the first signal in the driver, so
    restored caller handlers retain that status through cancellation handoff.
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
    cancellation = None
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
        nonlocal cancellation
        if not gate_cancellation:
            raise SystemExit(128 + signum)
        # Raising inside Popen._wait can strand its acquired waitpid lock.
        # Record the first signal and unwind only between bounded waits.
        if cancellation is None:
            cancellation = signum
            if on_cancel is not None: on_cancel(signum)
    def reap():
        discover()
        child.poll()
        for pid in tuple(owned):
            if pid == child.pid: continue
            try: os.waitpid(pid, os.WNOHANG)
            except ChildProcessError: pass
        for pid, started in tuple(owned.items()):
            if identity(pid) != started: del owned[pid]
        # A parent's exit may reparent children after the first snapshot.
        # Rescan after reaping/pruning before treating owned as empty.
        discover()
    def alive():
        reap()
        if gate_cancellation: return bool(owned)
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
        if gate_cancellation: return
        try:
            os.killpg(child.pid, signum)
            os.killpg(child.pid, signal.SIGCONT)
        except ProcessLookupError: pass
    def stop():
        # The outer supervisor allows 0.2s before killing its group. Cancelled
        # commands must not spend that grace waiting for TERM-refusing children
        # in other sessions; stop them immediately, then reap before unwinding.
        rounds = [(signal.SIGKILL, 2.0)] if cancellation else [(signal.SIGTERM, 0.2), (signal.SIGKILL, 2.0)]
        for signum, duration in rounds:
            if not alive(): break
            signal_owned(signum)
            deadline = time.monotonic() + duration
            while alive() and time.monotonic() < deadline:
                if gate_cancellation and cancellation and signum != signal.SIGKILL:
                    # A first signal may arrive during an ordinary TERM grace.
                    # Escalate now, within the outer gate's shorter deadline.
                    signum = signal.SIGKILL
                    deadline = time.monotonic() + 2.0
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
                                     start_new_session=not gate_cancellation, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE if capture_output else None,
                                     stderr=subprocess.PIPE if capture_output else None)
            started = identity(child.pid)
            if started is not None: owned[child.pid] = started
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if gate_cancellation:
            deadline = time.monotonic() + timeout
            while True:
                if cancellation: raise SystemExit(128 + cancellation)
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise subprocess.TimeoutExpired(command, timeout)
                try:
                    stdout, stderr = child.communicate(timeout=min(0.02, remaining))
                    break
                except subprocess.TimeoutExpired:
                    if cancellation: raise SystemExit(128 + cancellation)
            if cancellation: raise SystemExit(128 + cancellation)
        else:
            stdout, stderr = child.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    finally:
        # The opt-in recording handler cannot throw through cleanup, and must
        # retain a first cancellation even after ordinary cleanup has begun.
        if not gate_cancellation:
            for signum in handlers: signal.signal(signum, signal.SIG_IGN)
        try:
            if child is not None: stop()
        finally:
            # Caller handlers may raise. Defer delivery until all helper state
            # is restored, then preserve an already recorded cancellation if
            # unmasking delivers a later signal to one of those handlers.
            final_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed) if gate_cancellation else None
            try:
                for signum, handler in handlers.items(): signal.signal(signum, handler)
                if libc.prctl(36, previous_subreaper.value, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), "cannot restore child subreaper state")
            finally:
                if gate_cancellation:
                    try: signal.pthread_sigmask(signal.SIG_SETMASK, final_mask)
                    except (SystemExit, KeyboardInterrupt):
                        if cancellation is None: raise
        if cancellation: raise SystemExit(128 + cancellation)


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
