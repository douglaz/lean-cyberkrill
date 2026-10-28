#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Linux x86-64 capture-only getrandom injection; never used by the installed CLI.

Run only inside the offline namespace. Replace each main-thread getrandom syscall
before it reaches the kernel with bytes from published BIP39 vector 0. The pinned
binary and its RNG algorithm remain unchanged. No unpredictable mnemonic is drawn.
"""
import ctypes
import json
import os
from pathlib import Path
import signal
import sys

from cases import ROOT


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()]


def main():
    executable, output, evidence = sys.argv[1:]
    seed = bytes.fromhex(json.loads((ROOT / "packages/bitcoin/test-data/bip39-english-vectors.json").read_bytes())[0]["entropy"])
    assert seed == bytes(16) and os.uname().machine == "x86_64"
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

    def trace(request, pid, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(request, pid, address, data)
        error = ctypes.get_errno()
        if result == -1 and error: raise OSError(error, "capture ptrace failed")
        return result

    child = os.fork()
    if child == 0:
        trace(0, 0)  # PTRACE_TRACEME
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv(executable, [executable, "generate-mnemonic", "-w", "12", "-o", output])
    sizes = []
    try:
        _, status = os.waitpid(child, 0)
        assert os.WIFSTOPPED(status)
        trace(0x4200, child, 0, 1 | 0x100000)  # TRACESYSGOOD | EXITKILL
        entering, pending, delivered = True, None, 0
        while True:
            trace(24, child, 0, delivered)  # PTRACE_SYSCALL
            _, status = os.waitpid(child, 0)
            if os.WIFEXITED(status):
                result = os.WEXITSTATUS(status)
                break
            assert os.WIFSTOPPED(status), "reference terminated abnormally"
            stopped = os.WSTOPSIG(status)
            delivered = 0 if stopped in [signal.SIGTRAP, signal.SIGTRAP | 0x80] else stopped
            if stopped != signal.SIGTRAP | 0x80: continue
            registers = Registers()
            trace(12, child, 0, ctypes.addressof(registers))
            if entering and registers.orig_rax == 318:  # x86-64 getrandom
                address, count = registers.rdi, registers.rsi
                assert count <= 4096, "unexpected entropy request"
                pending = address, count
                registers.orig_rax = 2**64 - 1  # do not execute the entropy syscall
                trace(13, child, 0, ctypes.addressof(registers))
            elif not entering and pending is not None:
                address, count = pending
                for offset in range(0, count, 8):
                    width = min(8, count - offset)
                    previous = trace(2, child, address + offset) & (2**64 - 1)
                    value = previous & ~((1 << (width * 8)) - 1)
                    trace(5, child, address + offset, value)
                registers.rax = count
                trace(13, child, 0, ctypes.addressof(registers))
                sizes.append(count)
                pending = None
            entering = not entering
        assert sizes and 32 in sizes, "reference RNG seed was not intercepted"
        Path(evidence).write_text(json.dumps(dict(status=result, getrandom_sizes=sizes,
            seed_source="published BIP39 English vector 0; repeated zero bytes")) + "\n", encoding="utf-8")
        return result
    finally:
        try: os.kill(child, signal.SIGKILL)
        except ProcessLookupError: pass
        try: os.waitpid(child, 0)
        except ChildProcessError: pass


if __name__ == "__main__":
    sys.exit(main())
