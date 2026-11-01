POSIXLY_CORRECT=y
\unset -f command builtin exec unset
_gate_outer_bash=$(\command -p -v bash) ||
  { echo "cannot locate trusted Bash"; exit 1; }
\exec "$_gate_outer_bash" --noprofile --norc -p -s <<'__AGENT_GATE_WRAPPER__'
_gate_environment=$(command -p env) || exit 1
while IFS="=" read -r _gate_env_name _; do
  case $_gate_env_name in
    BASH_FUNC_command%%)
      printf "%s\n" "refusing exported command function" >&2
      exit 97
      ;;
    BASH_FUNC_*%%)
      printf "%s\n" "refusing exported shell function" >&2
      exit 97
      ;;
  esac
done <<<"$_gate_environment"
command type -P python3 >/dev/null 2>&1 ||
  { echo "python3 is required for gate supervision"; exit 1; }
_gate_dir=$(command mktemp -d) || { echo "cannot create gate directory"; exit 1; }
_gate_log="$_gate_dir/output.log"
_gate_error="$_gate_dir/error.log"
_gate_script="$_gate_dir/gate.bash"
_gate_runner="$_gate_dir/supervisor.py"
_gate_pending="$_gate_dir/exec.pending"
  _gate_remove_dir() {
    _gate_remove_rc=0
    for _gate_file in "$_gate_log" "$_gate_error" "$_gate_script" "$_gate_runner" "$_gate_pending"; do
      if [ -e "$_gate_file" ] && ! command unlink "$_gate_file"; then
        _gate_remove_rc=1
      fi
    done
    if ! command rmdir "$_gate_dir"; then
      _gate_remove_rc=1
    fi
    return "$_gate_remove_rc"
  }
  _gate_cleanup() {
    _gate_cleanup_rc=$?
    if ! _gate_remove_dir; then
      echo "cannot remove gate directory" >&2
      [ "$_gate_cleanup_rc" -ne 0 ] || _gate_cleanup_rc=1
    fi
    trap - EXIT
    exit "$_gate_cleanup_rc"
  }
  trap _gate_cleanup EXIT
  chmod 700 "$_gate_dir" || { echo "cannot protect gate directory"; exit 1; }
  if ! command cat >"$_gate_script" <<'__AGENT_GATE__'
<gate>
__AGENT_GATE__
  then
    echo "cannot write gate script"
    exit 1
  fi
  if ! command cat >"$_gate_runner" <<'__AGENT_SUPERVISOR__'
import os
import select
import signal
import subprocess
import sys
import time

root, bash, watchdog_pid, pending_path = sys.argv[1:5]
watchdog_pid = int(watchdog_pid)
log_path = os.path.join(root, "output.log")
error_path = os.path.join(root, "error.log")
gate_path = os.path.join(root, "gate.bash")
runner_path = os.path.join(root, "supervisor.py")
managed_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
child = None
gate_pgid = None
cancelled = None
signal_ready = False
pending_signal = None

class GateCancelled(BaseException):
    def __init__(self, signum):
        self.signum = signum


def receive_signal(signum, _frame):
    global pending_signal, signal_ready
    was_ready = signal_ready
    signal_ready = False
    if pending_signal is None:
        pending_signal = signum
    if not was_ready:
        return
    signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
    raise GateCancelled(pending_signal)


def ignore_managed_signals():
    for signum in managed_signals:
        signal.signal(signum, signal.SIG_IGN)


def write_terminal_status(stdout_fd, status):
    global signal_ready
    data = f"EXIT={status}\n".encode("ascii")
    while True:
        signal_ready = True
        _, writable, _ = select.select([], [stdout_fd], [], 0.1)
        if not writable:
            continue
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        signal_ready = False
        kernel_pending = signal.sigpending().intersection(managed_signals)
        if pending_signal is not None or kernel_pending:
            signum = pending_signal
            if signum is None:
                signum = min(kernel_pending)
            raise GateCancelled(signum)
        ignore_managed_signals()
        try:
            written = os.write(stdout_fd, data)
        except BaseException:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            raise
        if written != len(data):
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            raise RuntimeError("partial terminal status write")
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        return


def replay_worker(path, destination_fd):
    source_fd = None
    try:
        source_fd = os.open(path, os.O_RDONLY)
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                os._exit(0)
            pending = memoryview(chunk)
            while pending:
                try:
                    written = os.write(destination_fd, pending)
                except BlockingIOError:
                    select.select([], [destination_fd], [], 0.1)
                    continue
                if written <= 0:
                    os._exit(1)
                pending = pending[written:]
    except BaseException:
        os._exit(1)
    finally:
        if source_fd is not None:
            os.close(source_fd)


def replay_logs(items):
    workers = []
    reaped = set()
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        try:
            for path, destination_fd in items:
                pid = os.fork()
                if pid == 0:
                    try:
                        for signum in managed_signals:
                            signal.signal(signum, signal.SIG_DFL)
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                        replay_worker(path, destination_fd)
                    except BaseException:
                        os._exit(1)
                workers.append(pid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        while len(reaped) != len(workers):
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
            try:
                for pid in workers:
                    if pid in reaped:
                        continue
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    if waited == pid:
                        reaped.add(pid)
                        if (
                            not os.WIFEXITED(status)
                            or os.WEXITSTATUS(status) != 0
                        ):
                            raise RuntimeError("cannot replay gate output")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            if len(reaped) != len(workers):
                time.sleep(0.05)
    except BaseException:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        try:
            for pid in workers:
                if pid not in reaped:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            for pid in workers:
                if pid not in reaped:
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


subreaper_enabled = False


def enable_child_subreaper():
    global subreaper_enabled
    if not sys.platform.startswith("linux"):
        return
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        raise OSError("Linux libc has no prctl")
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    subreaper_enabled = True


def reap_adopted_children():
    if not subreaper_enabled:
        return
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def stop_group(signum):
    global gate_pgid
    if child is None or gate_pgid is None:
        return True
    pgid = gate_pgid
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass
    try:
        os.killpg(pgid, signal.SIGCONT)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 0.2
    while group_alive(pgid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        child.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return False
    deadline = time.monotonic() + 1.0
    while group_alive(pgid) and time.monotonic() < deadline:
        reap_adopted_children()
        time.sleep(0.01)
    reap_adopted_children()
    stopped = not group_alive(pgid)
    if stopped:
        gate_pgid = None
    return stopped


def remove_private_dir():
    ok = True
    for path in (log_path, error_path, gate_path, runner_path, pending_path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            ok = False
    try:
        os.rmdir(root)
    except FileNotFoundError:
        pass
    except OSError:
        ok = False
    return ok and not os.path.lexists(root)


for managed_signal in managed_signals:
    signal.signal(managed_signal, receive_signal)
signal.signal(signal.SIGCHLD, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_UNBLOCK, managed_signals)

try:
    os.unlink(pending_path)
except FileNotFoundError:
    pass
try:
    os.kill(watchdog_pid, signal.SIGTERM)
except ProcessLookupError:
    pass
try:
    os.waitpid(watchdog_pid, 0)
except ChildProcessError:
    pass

rc = 1
try:
    signal_ready = True
    if pending_signal is not None:
        signal_ready = False
        signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        raise GateCancelled(pending_signal)
    enable_child_subreaper()
    environment = os.environ.copy()
    shell_control = {
        "BASHOPTS",
        "BASH_COMPAT",
        "BASH_ENV",
        "BASH_LOADABLES_PATH",
        "BASH_XTRACEFD",
        "CDPATH",
        "ENV",
        "GLOBIGNORE",
        "POSIXLY_CORRECT",
        "SHELLOPTS",
    }
    for name in tuple(environment):
        if name in shell_control or name.startswith("BASH_FUNC_"):
            environment.pop(name, None)
    environment["BASH_ENV"] = "/dev/null"
    with open(log_path, "wb") as output, open(error_path, "wb") as errors:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
        try:
            child_bootstrap = (
                "import os,signal,sys;"
                "managed=tuple(map(int,sys.argv[3:]));"
                "signal.pthread_sigmask(signal.SIG_UNBLOCK,managed);"
                "os.execvpe(sys.argv[1],"
                "[sys.argv[1],'--noprofile','--norc','-eo','pipefail',sys.argv[2]],"
                "os.environ)"
            )
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    child_bootstrap,
                    bash,
                    gate_path,
                    *(str(signum) for signum in managed_signals),
                ],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                env=environment,
                start_new_session=True,
            )
            gate_pgid = child.pid
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        rc = child.wait()
        if rc < 0:
            rc = 128 - rc
        reap_adopted_children()
        if group_alive(gate_pgid):
            if not stop_group(signal.SIGTERM):
                print("cannot terminate gate process group", file=sys.stderr)
                rc = rc if rc != 0 else 1
            elif rc == 0:
                print("gate left background processes running", file=sys.stderr)
                rc = 1
        else:
            gate_pgid = None
except GateCancelled as cancellation:
    cancelled = cancellation.signum
    ignore_managed_signals()
    if not stop_group(cancellation.signum):
        print("cannot terminate gate process group", file=sys.stderr)
    rc = 128 + cancellation.signum
except BaseException as error:
    ignore_managed_signals()
    if gate_pgid is not None and group_alive(gate_pgid):
        stop_group(signal.SIGTERM)
    print(f"cannot run gate: {error}", file=sys.stderr)
    rc = rc if rc != 0 else 1
try:
    if cancelled is None:
        stdout_fd = sys.stdout.fileno()
        stderr_fd = sys.stderr.fileno()
        replay_logs(
            (
                (log_path, stdout_fd),
                (error_path, stderr_fd),
            )
        )
    if not remove_private_dir():
        print("cannot remove gate directory", file=sys.stderr)
        rc = rc if rc != 0 else 1
    if cancelled is None:
        write_terminal_status(stdout_fd, rc)
except GateCancelled as cancellation:
    cancelled = cancellation.signum
    ignore_managed_signals()
    if gate_pgid is not None and group_alive(gate_pgid):
        stop_group(cancellation.signum)
    rc = 128 + cancellation.signum
    if not remove_private_dir():
        print("cannot remove gate directory", file=sys.stderr)
except BaseException as error:
    ignore_managed_signals()
    print(f"cannot finalize gate: {error}", file=sys.stderr)
    rc = rc if rc != 0 else 1
    if not remove_private_dir():
        print("cannot remove gate directory", file=sys.stderr)
sys.exit(rc)
__AGENT_SUPERVISOR__
  then
    echo "cannot write gate supervisor"
    exit 1
  fi
: >"$_gate_pending" || { echo "cannot create exec marker"; exit 1; }
_gate_python=$(command type -P python3) ||
  { echo "cannot locate python3"; exit 1; }
command unset BASH_ENV ENV ||
  { echo "cannot clear shell startup environment"; exit 1; }
while command builtin read -r _ _ _gate_function; do
  command builtin export -n -f -- "$_gate_function" ||
    { echo "cannot clear exported shell function"; exit 1; }
done < <(command builtin declare -F)
_gate_owner_pid=$BASHPID
"$_gate_python" -I -c '
import os
import sys
import time

root, pending, owner_pid, *paths = sys.argv[1:]
owner_pid = int(owner_pid)
while os.path.lexists(pending):
    if os.getppid() != owner_pid:
        break
    try:
        os.kill(owner_pid, 0)
    except ProcessLookupError:
        break
    except PermissionError:
        pass
    time.sleep(0.05)
if os.path.lexists(pending):
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    try:
        os.rmdir(root)
    except OSError:
        pass
' "$_gate_dir" "$_gate_pending" \
  "$_gate_owner_pid" "$_gate_log" "$_gate_error" "$_gate_script" "$_gate_runner" \
  "$_gate_pending" &
_gate_exec_watchdog=$!
command exec "$_gate_python" -I "$_gate_runner" "$_gate_dir" "${BASH:-bash}" \
  "$_gate_exec_watchdog" "$_gate_pending"
__AGENT_GATE_WRAPPER__