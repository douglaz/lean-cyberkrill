#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Sentinel-only spawn refusals and controlled namespace entry failures."""
from contextlib import redirect_stdout
import ctypes
import io
import importlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from cases import APP
import network


def encoded_controls():
    # This existing independent constructor computes the checksum and actual
    # Fedimint consensus framing; it does not call the guard or production codec.
    path = APP.parent / "fedimint-invite/generate-fixtures.py"
    spec = importlib.util.spec_from_file_location("invite_fixtures", path)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    rows = []
    for port in ["8332", "0008332", "18444"]:
        invite = fixtures.wrap(fixtures.consensus(fixtures.invite([(0, "ws://127.0.0.1:" + port + "/")])) )
        assert invite.startswith("fed11"), "actual fed1 HRP separator"
        lnurl = fixtures.wrap(("http://127.0.0.1:" + port + "/pay").encode(), hrp="lnurl", variant=1)
        rows.extend([(f"valid-fed1/{port}", ["fm-fetch-config", invite], port == "18444"),
                     (f"valid-lnurl/{port}", ["ln-generate-invoice", lnurl, "1000sats"], port == "18444")])
    assert len(rows) == 6, "checksummed URL control inventory"
    return rows


def invoice_controls():
    rows = []
    for amount in ["1BTC", "100sat", "1000sats", "100msat", "100msats"]:
        for options in [[], ["--comment", "USD", "--output=report.com"],
                        ["-cUSD", "-oreport.com"], ["--comment=USD", "-o", "report.com"]]:
            rows.append(["ln-generate-invoice", *options, "user@example.com", amount])
    rows += [["ln-generate-invoice", "user@example.org", "-c", "USD", "--", "1000sats"],
             ["ln-generate-invoice", "--", "user@example.net", "1000sats"]]
    assert len(rows) == 22, "invoice permission inventory"
    return rows


def spawn_cases():
    rows = []
    for command in sorted(network.CORE_COMMANDS):
        for suffix, args in [
            ("absent", []), ("default", ["--rpc-url", "http://127.0.0.1:8332"]),
            ("wrong-port", ["--rpc-url", "http://127.0.0.1:18445"]),
            ("wrong-host", ["--rpc-url", "http://localhost:18444"]),
            ("attached-host", ["--rpc-url=http://example.invalid:18444"]),
            ("attached-port", ["--rpc-url=http://127.0.0.1:18445"]),
            ("missing-value", ["--rpc-url"]),
            ("duplicate", ["--rpc-url=http://127.0.0.1:18444", "--rpc-url=http://127.0.0.1:18445"])]:
            rows.append((command + "/" + suffix, [command, *args]))
        rows.append((command + "/terminator", [command, "--", "--rpc-url=http://127.0.0.1:18444"]))
    rows.append(("dca", ["onchain-dca-report", "--rpc-url=http://127.0.0.1:18444"]))
    for amount in ["1usd", "-bad1EUR", "oops. GBP", "1,000 UsD", "USD", "1uSd"]:
        for command in ["convert-amount", "ln-generate-invoice"]:
            prefix = ["user@example.com"] if command == "ln-generate-invoice" else []
            rows.append((command + "/" + amount, [command, *prefix, "--", amount]))
        for command in ["onchain-create-psbt", "onchain-create-funded-psbt"]:
            for attached in [False, True]:
                value = "synthetic:" + amount
                flag = ["--outputs=" + value] if attached else ["--outputs", value]
                rows.append((command + "/" + amount + "/" + str(attached),
                             [command, "--rpc-url=http://127.0.0.1:18444", *flag]))
        for attached in [False, True]:
            flag = ["--max-amount=" + amount] if attached else ["--max-amount", amount]
            rows.append(("maximum/" + amount + "/" + str(attached),
                         ["onchain-move-utxos", "--rpc-url=http://127.0.0.1:18444", *flag]))
    for token in ["http://127.0.0.1:8332", "--callback=https://example.invalid:8332/path",
                  '{"invite":"wss://127.0.0.1:8332/x"}', "name@127.0.0.1:8332",
                  "https%3A%2F%2F127.0.0.1%3A8332%2Fpath"]:
        rows.append(("nested/" + token, ["fm-fetch-config", token]))
    for token in ["http://127.0.0.1:08332", "name@127.0.0.1:0008332"]:
        rows.append(("nested/" + token, ["fm-fetch-config", token]))
    # Encode synthetic URL bytes into both invitation and LNURL containers.
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bits = ''.join(f'{b:08b}' for b in b'http://127.0.0.1:8332/path')
    bits += '0' * (-len(bits) % 5)
    data = ''.join(alphabet[int(bits[i:i+5], 2)] for i in range(0, len(bits), 5))
    for prefix in ["fed1", "lnurl1"]:
        rows.append(("encoded/" + prefix, ["fm-fetch-config", prefix + data + "qqqqqq"]))
    bits = ''.join(f'{b:08b}' for b in b'http://127.0.0.1:08332/path')
    bits += '0' * (-len(bits) % 5)
    data = ''.join(alphabet[int(bits[i:i+5], 2)] for i in range(0, len(bits), 5))
    for prefix in ["fed1", "lnurl1"]:
        rows.append(("encoded-zero/" + prefix, ["fm-fetch-config", prefix + data + "qqqqqq"]))
    rows.extend((name, args) for name, args, allowed in encoded_controls() if not allowed)
    for index, args in enumerate(invoice_controls()):
        rows.append((f"invoice-options/{index}", [*args[:-1], "-bad1USD"]))
    assert len(rows) == 122, "spawn refusal inventory"
    return rows


def spawn_checks(only=None):
    directory = APP / ".lake/network-safety"
    directory.mkdir(parents=True, exist_ok=True)
    rows = spawn_cases()
    shell = subprocess.check_output(["sh", "-c", "command -v sh"], timeout=5).decode().strip()
    with tempfile.TemporaryDirectory(dir=directory) as root:
        sentinel = Path(root) / "started"
        child = Path(root) / "sentinel.py"
        child.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n")
        executable = Path(root) / "sentinel"
        executable.write_text("#!" + shell + "\nexec " + shlex.quote(sys.executable) + " -B " + shlex.quote(str(child)) + ' "$@"\n')
        executable.chmod(0o700)
        references = [Path(root) / name for name in ["cyberkrill", "reference-copy"]]
        for reference in references: reference.symlink_to(executable)
        generator = importlib.import_module("generate-rpc-recordings")
        for name, args in rows:
            if only is not None and name != only: continue
            refused = False
            try:
                network.checked_run(executable, args, stub_url="http://127.0.0.1:18444", timeout=5, check=True)
            except ValueError as error:
                assert str(error).startswith("spawn refused:"), "named spawn refusal"
                refused = True
            assert refused and not sentinel.exists(), "spawn sentinel did not start: " + name
            for reference in references:
                refused = False
                try:
                    generator.run([str(reference), *args], reference=True, stub_url="http://127.0.0.1:18444", timeout=5)
                except ValueError:
                    refused = True
                assert refused and not sentinel.exists(), "capture sentinel did not start: " + name + "/" + reference.name
        accepted = [[command, "--rpc-url" + separator + "http://127.0.0.1:18444/wallet/synthetic"]
                    if separator == "=" else [command, "--rpc-url", "http://127.0.0.1:18444/wallet/synthetic"]
                    for command in sorted(network.CORE_COMMANDS) for separator in ["=", " "]]
        accepted += [["convert-amount", "1" + unit] for unit in ["BTC", "sat", "sats", "msat", "msats"]]
        accepted += [args for _, args, allowed in encoded_controls() if allowed] + invoice_controls()
        for index, args in enumerate(accepted):
            if only is not None and only != f"allowed/{index}": continue
            for boundary in ["port", *references]:
                try:
                    if boundary == "port":
                        network.checked_run(executable, args, stub_url="http://127.0.0.1:18444", timeout=5, check=True)
                    else:
                        generator.run([str(boundary), *args], reference=True, stub_url="http://127.0.0.1:18444", timeout=5)
                except ValueError:
                    raise AssertionError("spawn permitted sentinel starts: " + str(index)) from None
                assert sentinel.exists(), "spawn permitted sentinel starts: " + str(index)
                sentinel.unlink()
        if only is None or only == "utility":
            generator.run([str(references[1]), "onchain-dca-report"], timeout=5)
            assert sentinel.exists(), "unrelated utility is not a reference invocation"
            sentinel.unlink()
    if only is None:
        assert len(accepted) == 37, "spawn permission control inventory"
        print("network spawn refusals: 122/122 at port and both reference basenames; permitted controls: 37/37 at all three; utility: 1/1", flush=True)


def namespace_checks(only=None):
    directory = APP / ".lake/network-safety"
    directory.mkdir(parents=True, exist_ok=True)
    cases = ["missing", "refused", "loopback", "marker", "inherited-inode", "nonrecursive", "test-failure", "invalid-entry"]
    with tempfile.TemporaryDirectory(dir=directory) as root:
        root = Path(root)
        sentinel = root / "started"
        child = [sys.executable, "-B", "-c", "from pathlib import Path; Path(" + repr(str(sentinel)) + ").touch()"]
        unshare = root / "unshare"
        ip = root / "ip"
        sh = root / "sh"
        shell = subprocess.check_output(["sh", "-c", "command -v sh"], timeout=5).decode().strip()
        sh.symlink_to(shell)
        # The shim executes the real entry shell. It never creates a network connection.
        header = "#!" + shell + "\n"
        success_probe = header + 'shift\nif [ "$1" = true ]; then exit 0; fi\nexec "$@"\n'
        for name in cases:
            if only is not None and only != name: continue
            env = dict(os.environ, PATH=str(root))
            env["NIX_BUILD_TOP"] = str(root)
            for key in ["LCK_RPC_SANDBOX", "LCK_TEST_NETNS", "LCK_TEST_NET_PARENT"]: env.pop(key, None)
            if unshare.exists(): unshare.unlink()
            if ip.exists(): ip.unlink()
            if name in ["refused", "loopback"]:
                unshare.write_text(header + "exit 1\n" if name == "refused" else success_probe)
                unshare.chmod(0o700)
            if name == "loopback": ip.write_text(header + "exit 1\n"); ip.chmod(0o700)
            if name == "marker": env.update(LCK_RPC_SANDBOX="1", LCK_TEST_NETNS="1", LCK_TEST_NET_PARENT="1")
            if name == "inherited-inode":
                env.update(LCK_RPC_SANDBOX="1", LCK_TEST_NETNS=network.namespace() or "fake", LCK_TEST_NET_PARENT="fake")
            if name in ["missing", "refused", "loopback", "marker", "inherited-inode"]:
                # Exercise in a fresh process with all inherited isolation state removed.
                source = getattr(network, "__source__", None)
                replacement = ("exec(compile(" + repr(source) + ", network.__file__, 'exec'), network.__dict__); ") if source else ""
                probe = "import sys; sys.path.insert(0, sys.argv[1]); import network; " + replacement + "sys.exit(network.run_isolated(sys.argv[2:]))"
                proc = subprocess.run([sys.executable, "-B", "-c", probe, str(Path(__file__).parent), *child],
                                      env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
                expected = 125 if name == "loopback" else 0
                assert not sentinel.exists(), "namespace sentinel did not start: " + name
                assert proc.returncode == expected, "namespace status: " + name + " " + repr((proc.returncode, proc.stdout, proc.stderr))
                assert (proc.stdout == b"SKIP (no unshare)\n") == (name != "loopback"), "namespace skip classification: " + name
            elif name == "nonrecursive":
                assert network.sandbox() or network.isolated(), "nonrecursive test runs isolated"
                with patch.dict(os.environ, {"PATH": str(root)}):
                    assert network.run_isolated(child) == 0 and sentinel.exists(), "namespace nonrecursive success"
                sentinel.unlink()
            elif name == "test-failure":
                assert network.run_isolated([sys.executable, "-B", "-c", "raise SystemExit(23)"]) == 23, "namespace test failure propagates"
            else:
                source = getattr(network, "__source__", Path(network.__file__).read_text())
                entry = "exec(compile(" + repr(source) + ", " + repr(network.__file__) + ", 'exec'), {'__name__':'__main__','__file__':" + repr(network.__file__) + "})"
                proc = subprocess.run([sys.executable, "-B", "-c", entry, "--inside", *child],
                                      env={**env, "LCK_TEST_NET_PARENT": network.namespace() or "unavailable"},
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                assert proc.returncode == 1 and not sentinel.exists(), "namespace invalid entry refused"
    if only is None:
        assert len(cases) == 8, "namespace inventory"
        print("network namespace boundaries: 8/8; missing/refused isolation starts no child", flush=True)


def lifecycle_cases():
    single = [branch + "/" + outcome for branch in ["direct", "host"]
              for outcome in ["success", "failure", "leader-signal", "timeout", "HUP", "INT", "QUIT", "TERM"]]
    nested = ["nested-" + branch + "/" + outcome for branch in ["direct", "host"]
              for outcome in ["success", "failure", "timeout", "HUP", "INT", "QUIT", "TERM"]]
    proc_races = [branch + "/proc-" + field + "-race" for branch in ["direct", "host"]
                  for field in ["stat", "children"]]
    late = ["late-" + branch + "/" + outcome for branch in ["direct", "host"]
            for outcome in ["success", "failure", "timeout", "HUP", "INT", "QUIT", "TERM"]]
    return single + nested + proc_races + late


def lifecycle_checks(only=None):
    """Observe real process trees independently; clean them even under mutation."""
    directory = APP / ".lake/network-safety"
    directory.mkdir(parents=True, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    cases = lifecycle_cases()
    try:
        for name in cases:
            if only is not None and name != only: continue
            branch, outcome = name.split("/")
            nested = branch.startswith("nested-")
            late = branch.startswith("late-")
            direct = branch.removeprefix("nested-").removeprefix("late-") == "direct"
            with tempfile.TemporaryDirectory(dir=directory) as root:
                root = Path(root)
                ready, pids = root / "ready", root / "pids"
                escaped = root / "escaped"
                leaf = root / "leaf.py"
                leaf.write_text("import os,signal,time\nfrom pathlib import Path\n"
                                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                                + ("os.setsid()\n"
                                   "def escape(_signum,_frame):\n"
                                   "    if os.fork()==0:\n"
                                   "        os.setsid()\n"
                                   "        marker=Path(" + repr(str(escaped)) + ")\n"
                                   "        marker.with_suffix('.pending').write_text(str(os.getpid()))\n"
                                   "        marker.with_suffix('.pending').replace(marker)\n"
                                   "        time.sleep(10)\n        os._exit(0)\n"
                                   "signal.signal(signal.SIGUSR1,escape)\n" if late else "") +
                                "Path(" + repr(str(ready)) + ").write_text(str(os.getpid()))\n"
                                "time.sleep(60)\n")
                leader = root / "leader.py"
                leader.write_text("import os,signal,subprocess,sys,time\nfrom pathlib import Path\n"
                                  "os.close(1); os.close(2)\n"
                                  "child = subprocess.Popen([sys.executable,'-B'," + repr(str(leaf)) + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                                  "limit = time.monotonic()+5\n"
                                  "while not Path(" + repr(str(ready)) + ").exists():\n"
                                  "    assert time.monotonic()<limit\n    time.sleep(.01)\n"
                                  "Path(" + repr(str(pids)) + ").write_text(str(os.getpid())+' '+str(child.pid)"
                                  + ("+' '+str(os.getppid())" if nested else "") + ")\n"
                                  + ("sys.exit(0)\n" if outcome == "success" else
                                     "sys.exit(23)\n" if outcome == "failure" else
                                     "os.kill(os.getpid(),signal.SIGTERM)\n" if outcome == "leader-signal" else
                                     "time.sleep(60)\n"))
                shell = subprocess.check_output(["sh", "-c", "command -v sh"], timeout=5).decode().strip()
                (root / "sh").symlink_to(shell)
                # Connection-free entry shim still executes the real loopback
                # shell, --inside wrapper and payload, within the owned group.
                unshare = root / "unshare"
                unshare.write_text("#!" + shell + "\nshift\nif [ \"$1\" = true ]; then exit 0; fi\n"
                                   "export LCK_TEST_NET_PARENT=controlled-parent\nexec \"$@\"\n")
                ip = root / "ip"
                ip.write_text("#!" + shell + "\nexit 0\n")
                unshare.chmod(0o700); ip.chmod(0o700)
                source = getattr(network, "__source__", Path(network.__file__).read_text())
                payload = leader
                if nested:
                    inner = root / "inner.py"
                    # A leaked inner runner must not hold the observer's pipes
                    # open and hide the PID/reaping assertion under a timeout.
                    inner.write_text("import os,sys\nnull=os.open(os.devnull,os.O_WRONLY)\n"
                                     "os.dup2(null,1); os.dup2(null,2); os.close(null)\nsys.path.insert(0," + repr(str(Path(__file__).parent)) + ")\n"
                                     "import network\nexec(compile(" + repr(source) + ", network.__file__, 'exec'),network.__dict__)\n"
                                     "network.sandbox=lambda: " + repr(direct) + "\n"
                                     "network.isolated=lambda: False\n"
                                     "sys.exit(network.run_isolated([sys.executable,'-B'," + repr(str(leader)) + "],timeout=60))\n")
                    payload = inner
                driver = root / "driver.py"
                driver.write_text("import sys,subprocess\nsys.path.insert(0," + repr(str(Path(__file__).parent)) + ")\n"
                                  "import network\nexec(compile(" + repr(source) + ", network.__file__, 'exec'),network.__dict__)\n"
                                  "network.sandbox=lambda: " + repr(direct) + "\n"
                                  "network.isolated=lambda: False\n"
                                  # Schedule one real fork after the KILL snapshot
                                  # has been taken. Signals still reach real PIDs;
                                  # no discovery, ownership or reaping is mocked.
                                  + ("import os,signal,time\nfrom pathlib import Path\n"
                                     "kill=os.kill\n"
                                     "def scheduled_kill(pid,signum):\n"
                                     "    if signum==signal.SIGKILL and Path(" + repr(str(ready)) + ").exists() and pid==int(Path(" + repr(str(ready)) + ").read_text()) and not Path(" + repr(str(escaped)) + ").exists():\n"
                                     "        kill(pid,signal.SIGUSR1)\n"
                                     "        deadline=time.monotonic()+3\n"
                                     "        while not Path(" + repr(str(escaped)) + ").exists():\n"
                                     "            assert time.monotonic()<deadline, 'late child readiness'\n"
                                     "            time.sleep(.001)\n"
                                     "    return kill(pid,signum)\n"
                                     "os.kill=scheduled_kill\n" if late else "")
                                  + ("import os\nfrom pathlib import Path\n"
                                     "read_text=Path.read_text\ninjected=[False]\n"
                                     "def proc_read(path,*args,**kwargs):\n"
                                     "    if not injected[0] and Path(" + repr(str(pids)) + ").exists() and str(path).startswith('/proc/') and path.name==" + repr("stat" if outcome == "proc-stat-race" else "children") + " and path.parts[2]!=str(os.getpid()):\n"
                                     "        injected[0]=True\n        raise ProcessLookupError(3,'synthetic disappearing process')\n"
                                     "    return read_text(path,*args,**kwargs)\n"
                                     "Path.read_text=proc_read\n" if outcome.startswith("proc-") else "") +
                                  "try:\n    status=network.run_isolated([sys.executable,'-B'," + repr(str(payload)) + "],timeout=" + ("2" if nested else "1") + ")\n"
                                  "    print('RETURN',status,flush=True)\n"
                                  "except subprocess.TimeoutExpired:\n"
                                  + ("    assert injected[0], 'lifecycle proc race injected'\n" if outcome.startswith("proc-") else "") +
                                  "    print('TIMEOUT',flush=True)\n    sys.exit(124)\n")
                env = {**os.environ, "PATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
                process = subprocess.Popen([sys.executable, "-B", str(driver)], env=env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True)
                owned = []
                try:
                    deadline = time.monotonic() + 6
                    while not pids.exists():
                        assert time.monotonic() < deadline and process.poll() is None, "lifecycle sentinel startup: " + name
                        time.sleep(.01)
                    owned = list(map(int, pids.read_text().split()))
                    if outcome in {"HUP", "INT", "QUIT", "TERM"}:
                        process.send_signal(getattr(signal, "SIG" + outcome))
                    stdout, stderr = process.communicate(timeout=8)
                    if escaped.exists(): owned.append(int(escaped.read_text()))
                    # /proc includes zombies. No PID may remain, and this outer
                    # observer must not inherit an unreaped descendant.
                    absent = all(not Path("/proc", str(pid)).exists() for pid in owned)
                    reaped = True
                    observations = {}
                    for pid in owned:
                        try: observations[pid] = Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()[:3]
                        except (FileNotFoundError, ProcessLookupError): observations[pid] = "absent"
                        try:
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                            reaped = False
                        except ChildProcessError: pass
                    assert absent and reaped, "lifecycle descendants stopped/reaped: " + name + repr((observations, process.returncode, stdout, stderr))
                    if late: assert escaped.exists(), "late child scheduling reached: " + name
                    timed_out = outcome == "timeout" or outcome.startswith("proc-")
                    expected_status = 124 if timed_out else 128 + getattr(signal, "SIG" + outcome) if outcome in {"HUP", "INT", "QUIT", "TERM"} else 0
                    expected_output = b"TIMEOUT\n" if timed_out else b"" if expected_status else (
                        b"RETURN 23\n" if outcome == "failure" else b"RETURN -15\n" if outcome == "leader-signal" else b"RETURN 0\n")
                    assert (process.returncode, stdout, stderr) == (expected_status, expected_output, b""), "lifecycle outcome: " + name + repr((process.returncode, stdout, stderr))
                finally:
                    # Independent bounded recovery keeps mutation probes safe;
                    # these kills occur only after the cleanup observation.
                    if process.poll() is None: process.kill()
                    if pids.exists(): owned = list(map(int, pids.read_text().split()))
                    if escaped.exists(): owned.append(int(escaped.read_text()))
                    if owned:
                        try: os.killpg(owned[0], signal.SIGKILL)
                        except ProcessLookupError: pass
                    for pid in owned:
                        try: os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                    process.communicate(timeout=3)
                    deadline = time.monotonic() + 3
                    for pid in owned:
                        while True:
                            try: waited, _ = os.waitpid(pid, os.WNOHANG)
                            except ChildProcessError: break
                            if waited == pid: break
                            assert time.monotonic() < deadline, "independent lifecycle recovery deadline"
                            time.sleep(.01)
    finally:
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0
    assert len(cases) == 48 and (only is None or only in cases), "lifecycle inventory"
    if only is None: print("network process lifecycle: 48/48; 16 single-level, 14 nested, four disappearing-process read controls, 14 late-child escalation controls; direct and host entry; success/failure/timeout/four interruptions; descendants stopped and reaped", flush=True)


def main():
    args = sys.argv[1:]
    if args and args[0] == "--spawn":
        spawn_checks(args[1] if len(args) > 1 else None)
        return 0
    if not (network.sandbox() or network.isolated()):
        return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), *args])
    if args and args[0] == "--namespace": namespace_checks(args[1] if len(args) > 1 else None)
    elif args and args[0] == "--lifecycle": lifecycle_checks(args[1] if len(args) > 1 else None)
    else:
        assert not args
        spawn_checks()
        namespace_checks()
        lifecycle_checks()
    return 0


if __name__ == "__main__": sys.exit(main())
