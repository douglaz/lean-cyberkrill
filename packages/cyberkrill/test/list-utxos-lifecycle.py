#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Disposable mutation-driver sentinels: cleanup must precede source restoration."""
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
import subprocess

from cases import APP
from network import run_owned

M = importlib.import_module("list-utxos-mutations")
X = importlib.import_module("list-utxos-lexical-mutations")
DEST = APP / "test/golden/list-utxos-lifecycle-record.json"
MODES = ["timeout", "SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"]
FOCUSED = ["gate-SIGTERM", "wait-SIGTERM"]
CLEANUP = ["cleanup-entry-SIGTERM", "cleanup-wait-SIGTERM", "gate-cleanup-wait-SIGTERM"]
HANDOFF = ["finalization-post-unmask-SIGTERM", "finalization-pending-SIGTERM"]
STATUS_RECORD = ["finalization-status-record-SIGTERM"]
RECORDING = ["finalization-status-decision-SIGTERM", "finalization-status-write-SIGTERM"]
RECORDING_PREVIOUS_SHA256 = "55d31eb80e0f78d5c9604bd01e2035163d4863a0ccee86723a8f0ac6193cb4d1"
STATUS_PREVIOUS_SHA256 = "33d8b42187c54faaeaa7f029aee8019dd9160af60e6ae8e84df39cf60b980a16"
FINALIZATION = ["finalization-SIGTERM", "finalization-repeat-SIGTERM", *HANDOFF, *STATUS_RECORD, *RECORDING]
FINALIZATION_PREVIOUS_SHA256 = "6f9dc36d53a7e5c20287ad300717e058537c081f7475d05517e36caaa6cc261b"
HANDOFF_PREVIOUS_SHA256 = "6596703d991c25539e720ed10d32d4d82ca5db5d56df717860fc07b903e9dec5"
PREVIOUS_SHA256 = "3a5c8fdcf2d25a1dcca549827c4a785876108a2c5dddc3f04c87ae25a68978e7"
CLEANUP_PREVIOUS_SHA256 = "fcc3db3bb590cb8f51471cfbfb7938426f5c170dc570472330a8cb351b179057"


def present(pid):
    # A zombie is still unreaped and therefore also fails the boundary.
    return Path(f"/proc/{pid}/stat").exists()


def worker(root, suite, mode):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    def subreaper():
        value = ctypes.c_int()
        assert libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0
        return value.value
    managed = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
    helper_state = []
    if mode in FINALIZATION:
        # Exercise restoration to both zero and a previously enabled setting,
        # with a nonempty caller mask that must survive the handoff exactly.
        assert libc.prctl(36, int(mode == "finalization-SIGTERM"), 0, 0, 0) == 0
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1, signal.SIGINT])
    root = Path(root)
    source = root / "disposable.lean"
    source.write_bytes(b"original")
    events = []
    (root / "worker.pid").write_text(str(os.getpid()))
    original_write = Path.write_bytes

    def observe(event):
        pidfile = root / "sentinel.pid"
        if pidfile.exists():
            pid = int(pidfile.read_text())
            immediate = root / "command.pid"
            events.append(dict(event=event, descendant_present=present(pid),
                               immediate_present=immediate.exists() and present(int(immediate.read_text()))))
            (root / "events.json").write_text(json.dumps(dict(events=events)))

    def write(path, data):
        if path == source and data == b"original":
            observe("restore")
        return original_write(path, data)

    # Only disposable source bytes and command selection are substituted. The
    # real main(), command(), signal handlers, finally and recovery paths run.
    Path.write_bytes = write
    M.LOGS = root
    M.APP = X.APP = root
    M.fingerprints = lambda: {}
    M.edits = lambda: [("sentinel", str(source), "original", "changed", [], "unused")]
    X.SOURCE = source
    X.fingerprints = lambda: {}
    X.edits = lambda: [("sentinel", "original", "changed")]
    X.check = lambda _: None
    actual = M.command
    command_code = actual.__code__
    command_lines, command_start = inspect.getsourcelines(actual)
    status_assignment = command_start + next(i for i, line in enumerate(command_lines)
                                              if "terminal = error.code" in line)
    status_decision = command_start + next(i for i, line in enumerate(command_lines)
                                            if "if isinstance(sys.exception(), SystemExit)" in line)
    status_write = command_start + next(i for i, line in enumerate(command_lines)
                                         if '(LOGS / (label + ".status")).write_text' in line)

    def command(label, args, status, assertion=None):
        M.LOGS = root
        if label == "failure-restore-build":
            observe("recovery")
        if label in {"00-sentinel-build", "sentinel-build"}:
            args = [sys.executable, "-B", str(Path(__file__).resolve()), "--sentinel",
                    str(root), str(os.getpid()), mode]
        elif label == "failure-restore-build" and mode == "gate-SIGTERM":
            args = [sys.executable, "-B", "-c",
                    "import os,sys,time;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(20)",
                    str(root / "recovery.pid")]
        else:
            args = [sys.executable, "-B", "-c", "pass"]
        state = None
        if mode in FINALIZATION and label in {"00-sentinel-build", "sentinel-build"}:
            state = dict(subreaper_before=subreaper(),
                         mask_before=sorted(map(int, signal.pthread_sigmask(signal.SIG_BLOCK, []))))
            before_handlers = {sig: signal.getsignal(sig) for sig in managed}
        try:
            return actual(label, args, status, assertion)
        finally:
            if state is not None:
                state.update(subreaper_after=subreaper(),
                             mask_after=sorted(map(int, signal.pthread_sigmask(signal.SIG_BLOCK, []))),
                             handlers_restored=all(signal.getsignal(sig) == handler
                                                   for sig, handler in before_handlers.items()))
                helper_state.append(state)
            if label in {"00-sentinel-build", "sentinel-build"}:
                observe("command-return")

    M.command = command
    if mode in [*CLEANUP, *FINALIZATION]:
        import network
        lines, start = inspect.getsourcelines(network.run_owned)
        entry = start + next(i for i, line in enumerate(lines) if "if child is not None: stop()" in line)
        waiting = start + next(i for i, line in enumerate(lines) if "time.sleep(0.01)" in line)
        finalizing = start + next(i for i, line in enumerate(lines)
                                  if "if libc.prctl(36, previous_subreaper.value, 0, 0, 0) != 0:" in line)
        handoff = start + max(i for i, line in enumerate(lines)
                              if "if cancellation: raise SystemExit(128 + cancellation)" in line)
        fired = False
        finalized = False
        handed_off = False
        status_recorded = False
        cleanup_waits = []
        def trace_cleanup(frame, event, _arg):
            nonlocal fired, finalized, handed_off, status_recorded
            if (mode in RECORDING and finalized and not status_recorded
                    and event == "line" and frame.f_code == command_code
                    and frame.f_lineno == (status_decision if mode == RECORDING[0] else status_write)):
                assert M.CANCELLED == signal.SIGTERM, "recording transition retains TERM latch"
                status_recorded = True
                (root / "recording-boundary.json").write_text(json.dumps(dict(
                    phase="decision" if mode == RECORDING[0] else "write",
                    cancellation=int(M.CANCELLED), signals=[int(signal.SIGHUP)],
                    mask=sorted(map(int, signal.pthread_sigmask(signal.SIG_BLOCK, []))))))
                os.kill(os.getpid(), signal.SIGHUP)
            if (mode in STATUS_RECORD and finalized and not status_recorded
                    and event == "line" and frame.f_code == command_code
                    and frame.f_lineno == status_assignment):
                assert M.CANCELLED == signal.SIGTERM, "status recording retains TERM latch"
                assert frame.f_locals["error"].code == 143, "status recording caught original cancellation"
                status_recorded = True
                (root / "status-boundary.json").write_text(json.dumps(dict(
                    phase="caught-before-terminal-assignment", cancellation=int(M.CANCELLED),
                    caught_status=frame.f_locals["error"].code, terminal=frame.f_locals["terminal"],
                    signals=[int(signal.SIGHUP)])))
                os.kill(os.getpid(), signal.SIGHUP)
            if (mode == "finalization-post-unmask-SIGTERM" and finalized and not handed_off
                    and event == "line" and frame.f_code == network.run_owned.__code__
                    and frame.f_lineno == handoff):
                assert frame.f_locals["cancellation"] == signal.SIGTERM, "handoff retains TERM"
                assert frame.f_locals["owned"] == {}, "handoff tree already reaped"
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                assert signal.SIGHUP not in mask, "post-unmask HUP is unblocked"
                handed_off = True
                (root / "handoff-boundary.json").write_text(json.dumps(dict(
                    phase="post-unmask", cancellation=int(signal.SIGTERM),
                    mask=sorted(map(int, mask)), signals=[int(signal.SIGHUP)])))
                os.kill(os.getpid(), signal.SIGHUP)
            if (mode in FINALIZATION and fired and not finalized and event == "line"
                    and frame.f_code == network.run_owned.__code__ and frame.f_lineno == finalizing):
                assert frame.f_locals["cancellation"] == signal.SIGTERM, "first TERM recorded"
                assert frame.f_locals["owned"] == {}, "finalization tree already reaped"
                finalized = True
                (root / "finalization-boundary.ready").write_text(mode)
                if mode in ["finalization-repeat-SIGTERM", "finalization-pending-SIGTERM"]:
                    os.kill(os.getpid(), signal.SIGHUP)
                if mode == "finalization-pending-SIGTERM":
                    os.kill(os.getpid(), signal.SIGQUIT)
                    pending = signal.sigpending()
                    assert {signal.SIGHUP, signal.SIGQUIT} <= pending, "two distinct late signals pending"
                    (root / "handoff-boundary.json").write_text(json.dumps(dict(
                        phase="blocked-finalization", cancellation=int(signal.SIGTERM),
                        mask=sorted(map(int, signal.pthread_sigmask(signal.SIG_BLOCK, []))),
                        signals=sorted(map(int, pending)))))
            if (fired and event == "line" and frame.f_code.co_filename == network.__file__
                    and frame.f_lineno == waiting):
                cleanup_waits.append(int(frame.f_locals["signum"]))
                (root / "cleanup-waits.json").write_text(json.dumps(cleanup_waits))
            boundary = entry if mode in ["cleanup-entry-SIGTERM", *FINALIZATION] else waiting
            if (not fired and event == "line" and frame.f_code.co_filename == network.__file__
                    and frame.f_lineno == boundary and (root / "sentinel.pid").exists()):
                if mode not in ["cleanup-entry-SIGTERM", *FINALIZATION]:
                    assert frame.f_locals["signum"] == signal.SIGTERM, "ordinary TERM grace reached"
                fired = True
                (root / "cleanup-boundary.ready").write_text(mode)
                pid = os.getpid()
                if mode.startswith("gate-"):
                    while pid > 1:
                        tokens = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                        if any(token.rsplit(b"/", 1)[-1] == b"supervisor.py" for token in tokens):
                            break
                        pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
                    assert pid > 1, "actual cleanup gate supervisor found"
                os.kill(pid, signal.SIGTERM)
                if not mode.startswith("gate-") and mode not in FINALIZATION:
                    # Repeated cancellation must preserve the first status and
                    # cannot raise through descendant cleanup.
                    os.kill(pid, signal.SIGHUP)
            return trace_cleanup
        sys.settrace(trace_cleanup)
    if mode == "wait-SIGTERM":
        lines, start = inspect.getsourcelines(subprocess.Popen._wait)
        boundary = start + next(i for i, line in enumerate(lines) if "if self._waitpid_lock.acquire(False):" in line) + 1
        fired = False
        def trace(frame, event, _arg):
            nonlocal fired
            if not fired and event == "line" and frame.f_code == subprocess.Popen._wait.__code__ and frame.f_lineno == boundary and (root / "changed.ready").exists():
                deadline = time.monotonic() + 3
                while not (root / "sentinel.pid").exists():
                    if time.monotonic() > deadline: raise RuntimeError("wait boundary readiness deadline")
                    time.sleep(0.005)
                assert frame.f_locals["self"]._waitpid_lock.locked()
                (root / "wait-boundary.ready").touch()
                (root / "command.pid").write_text(str(frame.f_locals["self"].pid))
                fired = True
                os.kill(os.getpid(), signal.SIGTERM)
            return trace
        sys.settrace(trace)
    sys.argv = ["mutation-driver"]
    outcome = None
    try:
        (M if suite == "primary" else X).main()
    except (AssertionError, SystemExit, subprocess.TimeoutExpired) as error:
        outcome = dict(type=type(error).__name__, value=str(error))
    finally:
        Path.write_bytes = original_write
        sys.settrace(None)
        (root / "events.json").write_text(json.dumps(dict(events=events, outcome=outcome,
                                                         restored=source.read_bytes() == b"original",
                                                         helper_state=helper_state)))


def sentinel(root, driver, mode):
    import subprocess
    import time
    # The child occupies a separate session and refuses TERM. This exercises
    # descendant discovery, bounded escalation and reaping, not just killpg.
    code = ("import os,signal,sys,time; from pathlib import Path;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)")
    (Path(root) / "command.pid").write_text(str(os.getppid()))
    (Path(root) / "changed.ready").touch()
    child = subprocess.Popen([sys.executable, "-B", "-c", code, str(Path(root) / "sentinel.pid")],
                             start_new_session=True)
    deadline = time.monotonic() + 3
    while not (Path(root) / "sentinel.pid").exists():
        if time.monotonic() > deadline:
            raise RuntimeError("sentinel readiness deadline")
        time.sleep(0.005)
    if mode in ["cleanup-entry-SIGTERM", *FINALIZATION]:
        # A successful immediate command must still propagate cancellation
        # first delivered while cleaning up its adopted descendant.
        return
    if mode not in ["timeout", *FOCUSED, *CLEANUP]:
        os.kill(int(driver), getattr(signal, mode))
    child.wait(timeout=35)


def fingerprints():
    paths = ["test/list-utxos-lifecycle.py", "test/list-utxos-mutations.py",
             "test/list-utxos-lexical-mutations.py", "test/network.py", "test/gate.py"]
    return {p: hashlib.sha256((APP / p).read_bytes()).hexdigest() for p in paths}


def checks(selected):
    rows = []
    for suite, mode in selected:
        with tempfile.TemporaryDirectory(prefix="list-lifecycle-", dir=os.environ["TMPDIR"]) as tmp:
            root = Path(tmp)
            # Shorten only the real GNU timeout's timer, preserving its mode
            # and the helper's actual status/assertion and driver code.
            shim = root / "timeout"
            real_timeout = shutil.which("timeout")
            assert real_timeout, "GNU timeout required"
            shim.write_text("#!" + sys.executable + "\nimport os,sys\n"
                            "args=sys.argv[1:]\n"
                            "assert args[:2] == ['--foreground','180']\n"
                            "os.execv(" + repr(real_timeout) + ", ['timeout','--foreground'," + repr("5" if mode in FOCUSED else "0.5") + ",*args[2:]])\n")
            shim.chmod(0o700)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"], TMPDIR=tmp,
                       PYTHONDONTWRITEBYTECODE="1")
            # Independent ownership surrounds even the broken helper. Its
            # sentinels are always stopped/reaped before assertions can fail.
            args = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", tmp, suite, mode]
            sender = None
            errors = []
            gate_survivors = []
            gate_restored = []
            original_popen = subprocess.Popen
            real_gate = mode.startswith("gate-")
            if real_gate:
                args = [sys.executable, "-B", str(APP / "test/gate.py"), *args]
                class ObservedPopen(original_popen):
                    def communicate(self, *args, **kwargs):
                        result = super().communicate(*args, **kwargs)
                        if self.returncode is not None:
                            gate_restored.append((root / "disposable.lean").read_bytes() == b"original")
                            gate_survivors.extend(name for name in ["command", "sentinel", "recovery"]
                                                  if (root / (name + ".pid")).exists()
                                                  and present(int((root / (name + ".pid")).read_text())))
                        return result
                subprocess.Popen = ObservedPopen
                def cancel_gate():
                    try:
                        deadline = time.monotonic() + 5
                        while not (root / "sentinel.pid").exists():
                            if time.monotonic() > deadline: raise RuntimeError("real gate readiness deadline")
                            time.sleep(0.005)
                        pid = int((root / "worker.pid").read_text())
                        while pid > 1:
                            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                            if any(token.rsplit(b"/", 1)[-1] == b"supervisor.py" for token in cmdline.split(b"\0")):
                                os.kill(pid, signal.SIGTERM); return
                            pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
                        raise RuntimeError("actual gate supervisor not found")
                    except BaseException as error: errors.append(repr(error))
                if mode == "gate-SIGTERM":
                    sender = threading.Thread(target=cancel_gate)
                    sender.start()
            try:
                proc = run_owned(args, env=env, capture_output=True, timeout=10)
            finally:
                if sender: sender.join(timeout=6)
                subprocess.Popen = original_popen
            assert not errors and (not sender or not sender.is_alive()), ("lifecycle gate sender", errors)
            assert proc.returncode == (143 if real_gate else 0), ("lifecycle worker", proc.returncode, proc.stdout, proc.stderr)
            assert not present(int((root / "sentinel.pid").read_text())), "lifecycle observer reaped sentinel"
            assert not present(int((root / "command.pid").read_text())), "lifecycle observer reaped immediate child"
            assert not gate_survivors, "list lifecycle no survivor at real gate exit " + suite + ": " + repr(gate_survivors)
            assert not real_gate or gate_restored == [True], "list lifecycle restored at real gate exit " + suite
            if mode == "wait-SIGTERM":
                assert (root / "wait-boundary.ready").exists(), "lifecycle acquired wait lock exercised " + suite
            if mode in CLEANUP:
                assert (root / "cleanup-boundary.ready").read_text() == mode, "lifecycle cleanup boundary exercised " + suite
                waits = json.loads((root / "cleanup-waits.json").read_text()) if (root / "cleanup-waits.json").exists() else []
                if mode != "cleanup-entry-SIGTERM":
                    assert all(value == signal.SIGKILL for value in waits), "list lifecycle cleanup cancellation escalates " + suite
            else:
                waits = []
            record = json.loads((root / "events.json").read_bytes())
            events = record["events"]
            label = f"{suite}/{mode}"
            assert any(e["event"] == "restore" for e in events), "lifecycle restoration reached " + label
            if real_gate:
                assert not (root / "recovery.pid").exists(), "list lifecycle real gate cancellation starts no recovery " + label
            assert all(not e["descendant_present"] for e in events), "list lifecycle cleanup before restoration/recovery " + label + ": " + repr(events)
            assert all(not e["immediate_present"] for e in events), "list lifecycle immediate child reaped before restoration " + label + ": " + repr(events)
            order = [e["event"] for e in events]
            assert order[0] == "command-return", "lifecycle unwind ordering " + label
            assert ("recovery" in order) == (mode == "timeout"), "list lifecycle cancellation skips recovery " + label
            if mode == "timeout": assert order.index("restore") < order.index("recovery")
            assert record["restored"], "lifecycle exact restoration " + label
            expected = 124 if mode == "timeout" else 128 + getattr(signal, mode.split("-")[-1])
            outcome = record["outcome"]
            handoff_boundary = None
            if mode in HANDOFF:
                handoff_boundary = json.loads((root / "handoff-boundary.json").read_bytes())
                assert handoff_boundary["cancellation"] == signal.SIGTERM, "lifecycle saved cancellation exercised " + label
                assert outcome == dict(type="SystemExit", value="143"), "list lifecycle handoff preserves first status " + label + ": " + repr(outcome)
            if mode in FINALIZATION:
                assert (root / "finalization-boundary.ready").read_text() == mode, "lifecycle finalization boundary exercised " + label
                state, = record["helper_state"]
                assert state["handlers_restored"], "list lifecycle finalization restores handlers " + label
                assert state["mask_after"] == state["mask_before"], "list lifecycle finalization restores mask " + label
                assert state["subreaper_after"] == state["subreaper_before"], "list lifecycle finalization restores subreaper " + label + ": " + repr((state, outcome))
                assert outcome == dict(type="SystemExit", value="143"), "list lifecycle finalization preserves first status " + label + ": " + repr(outcome)
            if mode == "timeout":
                assert outcome["type"] == "AssertionError" and "got 124" in outcome["value"], "lifecycle real timeout status " + label
            else:
                assert outcome == dict(type="SystemExit", value=str(expected)), "lifecycle managed status " + label
            # The command record must exist even for a managed interruption.
            stem = "00-sentinel-build" if suite == "primary" else "sentinel-build"
            recording_boundary = None
            if mode in RECORDING:
                recording_boundary = json.loads((root / "recording-boundary.json").read_bytes())
                assert recording_boundary["phase"] == ("decision" if mode == RECORDING[0] else "write"), "lifecycle recording transition exercised " + label
                assert recording_boundary["cancellation"] == signal.SIGTERM, "lifecycle recording transition after TERM " + label
                assert recording_boundary["signals"] == [signal.SIGHUP], "lifecycle recording transition sends HUP " + label
            status_path = root / (stem + ".status")
            assert status_path.is_file(), "list lifecycle command status record exists " + label + ": " + repr((outcome, recording_boundary))
            status_bytes = status_path.read_bytes()
            assert status_bytes == f"{expected}\n".encode(), "list lifecycle complete command status record " + label + ": " + repr(status_bytes)
            recorded_status = int(status_bytes)
            if mode in RECORDING:
                assert recorded_status == expected == int(outcome["value"]) == 143, "list lifecycle recording outcome/status agreement " + label
            status_boundary = None
            if mode in STATUS_RECORD:
                status_boundary = json.loads((root / "status-boundary.json").read_bytes())
                assert status_boundary == dict(phase="caught-before-terminal-assignment",
                                               cancellation=int(signal.SIGTERM), caught_status=143,
                                               terminal=1, signals=[int(signal.SIGHUP)]), "lifecycle status recording boundary exercised " + label
                assert recorded_status == expected == int(outcome["value"]) == 143, "list lifecycle status record preserves first cancellation " + label + ": " + repr((outcome, recorded_status))
            assert recorded_status == expected, "lifecycle retained status " + label
            streams = {s: (root / (stem + "." + s)).read_bytes() for s in ["stdout", "stderr"]}
            assert streams == {"stdout": b"", "stderr": b""}, "lifecycle separated empty streams " + label
            rows.append(dict(suite=suite, mode=mode, status=expected, events=events,
                             python_version=sys.version.split()[0], worker_status=proc.returncode,
                             gate_survivors=gate_survivors, gate_restored=gate_restored,
                             cleanup_boundary=mode if mode in CLEANUP else None,
                             cleanup_wait_signals=waits,
                             helper_state=record["helper_state"],
                             handoff_boundary=handoff_boundary, outcome=outcome,
                             recording_boundary=recording_boundary,
                             recorded_status_bytes=status_bytes.decode(),
                             status_boundary=status_boundary, recorded_status=recorded_status,
                             stdout_sha256=hashlib.sha256(streams["stdout"]).hexdigest(),
                             stderr_sha256=hashlib.sha256(streams["stderr"]).hexdigest()))
            print("list lifecycle " + label + ": immediate/descendant reaping, restoration and status checked", flush=True)
    return rows


def main():
    args = sys.argv[1:]
    if args[:1] == ["--sentinel"]:
        sentinel(*args[1:]); return
    if args[:1] == ["--worker"]:
        worker(*args[1:]); return
    if args == ["--verify"]:
        record = json.loads(DEST.read_bytes())
        assert record["source_sha256"] == fingerprints(), "stale list lifecycle evidence"
        assert [(r["suite"], r["mode"]) for r in record["checks"]] == [(s, m) for s in ["primary", "lexical"] for m in [*MODES, *FOCUSED, *CLEANUP, *FINALIZATION]]
        assert all(not e["descendant_present"] for r in record["checks"] for e in r["events"])
        assert all(not e["immediate_present"] for r in record["checks"] for e in r["events"])
        empty = hashlib.sha256(b"").hexdigest()
        for row in record["checks"]:
            assert row["status"] == (124 if row["mode"] == "timeout" else 128 + getattr(signal, row["mode"].split("-")[-1]))
            assert row["recorded_status"] == row["status"]
            assert row["recorded_status_bytes"] == str(row["status"]) + "\n"
            assert row["worker_status"] == (143 if row["mode"].startswith("gate-") else 0)
            assert row["cleanup_boundary"] == (row["mode"] if row["mode"] in CLEANUP else None)
            assert all(value == signal.SIGKILL for value in row["cleanup_wait_signals"])
            assert not row["gate_survivors"] and row["python_version"]
            assert row["gate_restored"] == ([True] if row["mode"].startswith("gate-") else [])
            assert row["stdout_sha256"] == row["stderr_sha256"] == empty
            if row["mode"] in FINALIZATION:
                state, = row["helper_state"]
                assert state["subreaper_before"] == int(row["mode"] == "finalization-SIGTERM")
                assert state["subreaper_after"] == state["subreaper_before"]
                assert state["handlers_restored"] and state["mask_after"] == state["mask_before"]
                assert {int(signal.SIGUSR1), int(signal.SIGINT)} <= set(state["mask_before"])
            else: assert row["helper_state"] == []
            if row["mode"] in HANDOFF:
                boundary = row["handoff_boundary"]
                assert boundary["cancellation"] == signal.SIGTERM
                assert row["outcome"] == dict(type="SystemExit", value="143")
                if row["mode"] == "finalization-post-unmask-SIGTERM":
                    assert boundary["phase"] == "post-unmask" and boundary["signals"] == [signal.SIGHUP]
                    assert signal.SIGHUP not in boundary["mask"]
                else:
                    assert boundary["phase"] == "blocked-finalization"
                    assert {signal.SIGHUP, signal.SIGQUIT} <= set(boundary["signals"]) <= set(boundary["mask"])
            else: assert row["handoff_boundary"] is None
            if row["mode"] in STATUS_RECORD:
                assert row["status_boundary"] == dict(phase="caught-before-terminal-assignment",
                                                      cancellation=int(signal.SIGTERM), caught_status=143,
                                                      terminal=1, signals=[int(signal.SIGHUP)])
                assert row["outcome"] == dict(type="SystemExit", value="143")
                assert row["recorded_status"] == 143
            else: assert row["status_boundary"] is None
            if row["mode"] in RECORDING:
                boundary = row["recording_boundary"]
                assert boundary["phase"] == ("decision" if row["mode"] == RECORDING[0] else "write")
                assert boundary["cancellation"] == signal.SIGTERM and boundary["signals"] == [signal.SIGHUP]
                assert {signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM} <= set(boundary["mask"])
                assert row["recorded_status"] == 143 and row["outcome"] == dict(type="SystemExit", value="143")
            else: assert row["recording_boundary"] is None
            order = [e["event"] for e in row["events"]]
            assert order[0] == "command-return" and "restore" in order
            assert ("recovery" in order) == (row["mode"] == "timeout")
            if row["mode"] == "timeout": assert order.index("restore") < order.index("recovery")
        retained = record["regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in retained] == [
            (s, m, 1) for s in ["primary", "lexical"] for m in ["timeout", "SIGTERM"]]
        assert all(r["assertion"] == "list lifecycle cleanup before restoration/recovery" for r in retained)
        previous = record["previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == PREVIOUS_SHA256, "retained ten-case lifecycle observation"
        focused = record["focused_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in focused] == [(s, m, 1) for s in ["primary", "lexical"] for m in FOCUSED]
        assert all(r["assertion"] == ("list lifecycle no survivor at real gate exit" if r["mode"] == "gate-SIGTERM" else "list lifecycle immediate child reaped before restoration") for r in focused)
        previous = record["cleanup_previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == CLEANUP_PREVIOUS_SHA256, "retained fourteen-case lifecycle observation"
        cleanup = record["cleanup_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in cleanup] == [(s, m, 1) for s in ["primary", "lexical"] for m in CLEANUP]
        for row in cleanup:
            allowed = (["list lifecycle no survivor at real gate exit", "list lifecycle restored at real gate exit"]
                       if row["mode"].startswith("gate-") else
                       ["list lifecycle cleanup cancellation escalates"] if row["mode"] == "cleanup-wait-SIGTERM" else
                       ["list lifecycle cancellation skips recovery"])
            assert row["assertion"] in allowed, "named cleanup runtime regression"
        escalation = record["cleanup_escalation_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in escalation] == [(s, "cleanup-wait-SIGTERM", 1) for s in ["primary", "lexical"]]
        assert all(r["assertion"] == "list lifecycle cleanup cancellation escalates" for r in escalation)
        previous = record["finalization_previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == FINALIZATION_PREVIOUS_SHA256, "retained twenty-case lifecycle observation"
        finalization = record["finalization_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in finalization] == [(s, "finalization-repeat-SIGTERM", 1) for s in ["primary", "lexical"]]
        assert all(r["assertion"] == "list lifecycle finalization restores subreaper" for r in finalization)
        previous = record["handoff_previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == HANDOFF_PREVIOUS_SHA256, "retained twenty-four-case lifecycle observation"
        handoff = record["handoff_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in handoff] == [(s, m, 1) for s in ["primary", "lexical"] for m in HANDOFF]
        assert all(r["assertion"] == "list lifecycle handoff preserves first status" for r in handoff)
        previous = record["status_previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == STATUS_PREVIOUS_SHA256, "retained twenty-eight-case lifecycle observation"
        status = record["status_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in status] == [(s, STATUS_RECORD[0], 1) for s in ["primary", "lexical"]]
        assert all(r["assertion"] == "list lifecycle status record preserves first cancellation" for r in status)
        previous = record["recording_previous_observation"]
        assert hashlib.sha256((json.dumps(previous, indent=2) + "\n").encode()).hexdigest() == RECORDING_PREVIOUS_SHA256, "retained thirty-case lifecycle observation"
        recording = record["recording_regression_observations"]
        assert [(r["suite"], r["mode"], r["status"]) for r in recording] == [(s, m, 1) for s in ["primary", "lexical"] for m in RECORDING]
        assert all(r["assertion"] == "list lifecycle command status record exists" and r["observed_outcome"] == 143 and r["observed_record_exists"] is False for r in recording)
        print("list lifecycle evidence: 34 boundaries; complete command records survive late signals at decision/write; first status, handlers, mask and prior subreaper retained; earlier observations retained"); return
    selected = [(s, m) for s in ["primary", "lexical"] for m in [*MODES, *FOCUSED, *CLEANUP, *FINALIZATION]]
    if args[:1] == ["--case"]:
        _, suite, mode = args
        assert (suite, mode) in selected
        selected = [(suite, mode)]
    else:
        assert args in [[], ["--record"]]
    rows = checks(selected)
    assert len(rows) == len(selected)
    if args == ["--record"]:
        retained = json.loads(DEST.read_bytes()) if DEST.exists() else {}
        record = dict(source_sha256=fingerprints(), checks=rows,
                      regression_observations=retained.get("regression_observations", []))
        record["previous_observation"] = retained.get("previous_observation", retained)
        record["focused_regression_observations"] = retained.get("focused_regression_observations", [])
        record["cleanup_previous_observation"] = retained.get("cleanup_previous_observation", retained)
        record["cleanup_regression_observations"] = retained.get("cleanup_regression_observations", [])
        record["cleanup_escalation_regression_observations"] = retained.get("cleanup_escalation_regression_observations", [])
        record["finalization_previous_observation"] = retained.get("finalization_previous_observation", retained)
        record["finalization_regression_observations"] = retained.get("finalization_regression_observations", [])
        record["handoff_previous_observation"] = retained.get("handoff_previous_observation", retained)
        record["handoff_regression_observations"] = retained.get("handoff_regression_observations", [])
        record["status_previous_observation"] = retained.get("status_previous_observation", retained)
        record["status_regression_observations"] = retained.get("status_regression_observations", [])
        record["recording_previous_observation"] = retained.get("recording_previous_observation", retained)
        record["recording_regression_observations"] = retained.get("recording_regression_observations", [])
        if "unfixed_source_sha256" in retained:
            record["unfixed_source_sha256"] = retained["unfixed_source_sha256"]
        DEST.write_text(json.dumps(record, indent=2) + "\n")
    print(f"list lifecycle: {len(rows)}/{len(selected)} boundaries")


if __name__ == "__main__":
    main()
