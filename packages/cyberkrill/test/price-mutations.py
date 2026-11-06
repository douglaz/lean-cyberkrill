#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled price regressions with intended runtime failures and exact restoration."""
from contextlib import chdir
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

from cases import APP
from evidence import write_record
from network import run_owned

DEST = APP / "test/http/mutation-record.json"


def mutations():
    fiat, feed, entry, app = ["Cyberkrill/"+s+".lean" for s in ["Fiat","PriceFeed","TestEntry","App"]]
    pure = ["python3", "-B", "test/price-feeds.py", "--pure"]
    guard = [".lake/build/bin/CyberkrillTests", "--price-guards"]
    replay = ["python3", "-B", "test/price-feeds.py"]
    rows = [
        ("msat-half-away",fiat,'(2 * a.numerator + a.denominator) / (2 * a.denominator)',
         'a.numerator / a.denominator',pure,'convert/0.000010925'),
        ("whole-after-msat",fiat,'| .wholeSat => wholeSat ⟨rounded⟩','| .wholeSat => floorSat ⟨rounded⟩',pure,'precision/0.001424525/whole'),
        ("floor-after-msat",fiat,'| .floorSat => floorSat ⟨rounded⟩','| .floorSat => wholeSat ⟨rounded⟩',pure,'precision/0.001424525/floor'),
        ("quorum-three",feed,'if quotes.size < 3 then','if quotes.size < 2 then',pure,'aggregate/2'),
        ("even-mean",feed,'return ((← sorted[middle - 1]?).add (← sorted[middle]?)).div ⟨2, 1⟩',
         'return (← sorted[middle - 1]?)',pure,'aggregate/4'),
        ("strict-spread",feed,'unless (Exact.mk 102 100).lt ratio do return ""',
         'unless !(ratio.lt (Exact.mk 102 100)) do return ""',pure,'aggregate/exact-spread'),
        ("fedi-orientation",feed,'return some (btc.div fiat)','return some (btc.mul fiat)',pure,'fedi/orientation'),
        ("special-404-only",feed,'if r.status == 404 && feed.missing404 then return none',
         'if r.status == 404 then return none',pure,'coingecko/http-404'),
        ("parallel-fanout",feed,'tasks := task :: tasks','let _ ← IO.wait task\n    tasks := task :: tasks',replay,'actual nine-request overlapping fanout'),
        ("all-override-slots",entry,'(urls.feedBases ++ #[urls.coinGeckoHistory, urls.dcaRpc]).all (fun url => permitted url && !forbiddenPort url)',
         'urls.feedBases.all (fun url => permitted url && !forbiddenPort url)',guard,'every unused override slot before action'),
        ("embedded-port-guard",entry,'if args.any forbiddenPort then','if false then',guard,'nested URL port refused'),
        ("source-list-order",app,'("feeds", toJson (p.sources.map (·.source)))',
         '("feeds", toJson (p.sources.reverse.map (·.source)))',replay,'nine-feed exact handler JSON'),
        ("tiny-quote-json",fiat,'24 + (toString a.denominator).length - (toString a.numerator).length',
         '24',pure,'fedi/tiny-repeating-output'),
        ("nested-override-decoding",entry,'for _ in [:5] do','for _ in [:2] do',guard,'safe encoded override fixed point'),
        ("nested-override-port",entry,'(urls.feedBases ++ #[urls.coinGeckoHistory, urls.dcaRpc]).all (fun url => permitted url && !forbiddenPort url)',
         '(urls.feedBases ++ #[urls.coinGeckoHistory, urls.dcaRpc]).all permitted',guard,'every unused override slot before action'),
    ]
    rows += [
        ("numeric-json-preflight",fiat,'if power.natAbs > 1024 then none else do',
         'if power.natAbs > 1025 then none else do',
         ["python3","-B","test/price-feeds.py","--probe","numeric-limit"], 'numeric token rejected before JSON expansion'),
        ("string-coefficient-bound",fiat,'if coefficient.length > 1024 || negative then none else do',
         'if coefficient.length > 2048 || negative then none else do',pure,'grammar/coefficient-1025'),
        ("unicode-json-preflight",feed,'if 0xD800 ≤ unit && unit ≤ 0xDBFF then',
         'if false then',
         ["python3","-B","test/price-feeds.py","--probe","surrogate"], 'lone surrogate rejected in ignored field'),
        ("lossy-response-text",feed,'let body := Lightning.Lnurl.lossyUtf8 r.body',
         'let some body := String.fromUTF8? r.body | throw s!"Failed to read {feed.label} response"',pure,'bitstamp/raw-ignored'),
        ("no-early-connect-cutoff",feed,'connectTimeoutMs := 0','connectTimeoutMs := 5000',
         [".lake/build/bin/CyberkrillTests","--price-tasks"],'per-feed deadline and response bound'),
        ("exhausted-override-decoding",entry,'-- Exhausting the decoding budget never constitutes validation.\n  return false',
         '-- Exhausting the decoding budget never constitutes validation.\n  return true',
         guard,'permitted decode exhaustion'),
    ]
    rows.append(("bech32-override-target",entry,
        'if next == decoded then return !(encodedMaterial decoded).any (concealedTarget 5)',
        'if next == decoded then return true',guard,'every unused override slot before action'))
    rows.append(("argv-decoding-exhaustion",entry,
        'private def concealedPort : Nat → String → Bool\n  | 0, _ => true',
        'private def concealedPort : Nat → String → Bool\n  | 0, _ => false',guard,'nested argv fail closed'))
    rows += [
        ("json-container-depth",feed,'if depth ≥ 128 then return none',
         'if false then return none',pure,'bitstamp/depth-array-127'),
        ("ignored-numeric-underflow",feed,'if order < 308 then return true',
         'if order < 308 then return order ≥ -1024',pure,'bitstamp/ignored-1e-1025'),
        ("ignored-numeric-overflow",feed,'unless (quoted && used.contains i) || finiteJsonNumber numbers[i]! do throw invalid',
         'unless true do throw invalid',pure,'bitstamp/ignored-1e400'),
        ("zero-json-exponent",feed,'unless token.length ≤ 2048 && decimalSyntax token true do return none',
         'unless token.length ≤ 2048 && decimalSyntax token true && (((token.splitOn "e")[1]?.getD "0").toInt?.getD 2049).natAbs ≤ 2048 do return none',
         ["python3","-B","test/price-feeds.py","--probe","zero-token"], 'zero-token parser correction'),
        ("malformed-sign-category",feed,'unless decimalSyntax text do throw (label ++ " is not a number")',
         'unless text.startsWith "-" || decimalSyntax text do throw (label ++ " is not a number")',pure,'bitstamp/sign--+5'),
        ("negative-range-category",feed,'if text.startsWith "-" then throw (label ++ " must be positive")',
         'if text.startsWith "-" && (Exact.parse unsigned).isSome then throw (label ++ " must be positive")',pure,'bitstamp/sign--1e2000'),
        ("fedi-exact-overflow",feed,'return some (btc.div fiat)',
         'let cross := btc.div fiat\n    unless cross.lt ⟨2^1024, 1⟩ do throw "Fedi cross-rate must be positive"\n    return some cross',pure,'fedi/cross-overflow'),
        ("fedi-exact-underflow",feed,'return some (btc.div fiat)',
         'let cross := btc.div fiat\n    if cross.lt ⟨1, 10^324⟩ then throw "Fedi cross-rate must be positive"\n    return some cross',pure,'fedi/cross-underflow'),
        ("json-number-grammar",feed,'decimalSyntax token true',
         'decimalSyntax token false',pure,'bitstamp/json-syntax-01'),
    ]
    rows += [
        ("numeric-object-key",feed,
         'if (rest.dropWhile (fun ch => " \\t\\r\\n".contains ch)).head? == some \':\' then return none',
         'if false then return none',pure,'bitstamp/numeric-key-first-1'),
        ("losing-candidate-range",feed,'set (chosen.map (·.2.2) |>.getD #[])',
         'set (candidates.flatMap (·.2.2))',pure,'kraken/losing-USD-overflow309'),
        ("selected-candidate-exemption",feed,'set (chosen.map (·.2.2) |>.getD #[])',
         'set (#[] : Array Nat)',pure,'kraken/selected-single-1e400'),
    ]
    rows.append(("warning-before-issues",feed,
        'spreadWarning p ++ (if summary.isEmpty then "" else "[price-feed] " ++ summary ++ "\\n")',
        '(if summary.isEmpty then "" else "[price-feed] " ++ summary ++ "\\n") ++ spreadWarning p',
        replay,'cent median warning/issues/breadcrumb order'))
    assert len(rows) == 36
    return rows


def fingerprints():
    paths = ["Cyberkrill/Fiat.lean", "Cyberkrill/PriceFeed.lean", "Cyberkrill/TestEntry.lean", "Cyberkrill/App.lean",
        "CyberkrillTests/PriceFeed.lean", "CyberkrillTests.lean", "test/price-mutations.py", "test/price-feeds.py",
        "test/price-cases.py", "test/price-parity.py", "test/http/success.json", "test/http/reference.json", "test/http/exact-deltas.json"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record = json.loads(DEST.read_bytes())
    assert record["source_sha256"] == fingerprints(), "stale price mutation evidence"
    assert len(record["checks"]) == len(mutations()) == 36
    for result, row in zip(record["checks"],mutations()):
        assert [result[k] for k in ["property","file","replace","with_text","command","assertion"]] == list(row)
        assert [result[k]["status"] for k in ["build","red","restore_build","green"]] == [0,1,0,0]
        assert row[-1] in result["failure"] and ("AssertionError:" in result["failure"] or "assertion failed:" in result["failure"])
    assert record["initial_build"]["status"] == record["initial_green"]["status"] == record["restored_full"]["status"] == 0
    print("price mutation evidence: 36/36 compiled detecting failures and restored greens",flush=True)


def main(full=None):
    if sys.argv[1:] == ["--verify"]: verify(); return
    assert not sys.argv[1:]
    logs = APP / ".lake/validation/price-mutations" / str(time.time_ns())
    logs.mkdir(parents=True)
    originals = {p:(APP/p).read_bytes() for _,p,*_ in mutations()}
    hashes = fingerprints()
    managed = [signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM]
    def write(path,data):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,managed)
        try:
            (APP/path).write_bytes(data)
            assert (APP/path).read_bytes() == data, "exact price source bytes"
        finally: signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    def restore():
        for path,data in originals.items(): write(path,data)
    def interrupted(signum,_): raise InterruptedError("price mutation interrupted")
    handlers = {s:signal.signal(s,interrupted) for s in managed}
    def command(name,args,status,assertion=None):
        start = time.monotonic()
        with tempfile.TemporaryDirectory(dir=logs) as temporary, chdir(APP):
            result = run_owned(args, env=dict(os.environ,TMPDIR=temporary,PYTHONDONTWRITEBYTECODE="1"),
                capture_output=True,timeout=600)
        for stream in ["stdout","stderr"]: (logs/(name+"."+stream)).write_bytes(getattr(result,stream))
        (logs/(name+".status")).write_text(str(result.returncode)+"\n")
        output = (result.stdout+result.stderr).decode()
        assert result.returncode == status, "price mutation status " + name + ": " + output
        if assertion:
            assert assertion in output and ("AssertionError:" in output or "assertion failed:" in output), "price intended runtime failure " + name
        return dict(command=args,status=result.returncode,seconds=round(time.monotonic()-start,3)),output
    build = ["lake","build","cyberkrill","CyberkrillTests"]
    full = full or ["python3","-B","test/price-feeds.py"]
    complete = False
    try:
        initial_build,_ = command("initial-build",build,0)
        initial_green,_ = command("initial-green",full,0)
        checks = []
        for name,path,old,new,args,assertion in mutations():
            source = originals[path].decode()
            assert source.count(old) == 1, "unique price mutation target " + name
            try:
                write(path,source.replace(old,new,1).encode())
                compiled,_ = command(name+"-build",build,0)
                red,output = command(name+"-red",args,1,assertion)
            finally: restore()
            restored,_ = command(name+"-restore-build",build,0)
            green,_ = command(name+"-green",args,0)
            checks.append(dict(property=name,file=path,replace=old,with_text=new,command=args,assertion=assertion,
                failure=next(line for line in output.splitlines() if assertion in line and
                    ("AssertionError:" in line or "assertion failed:" in line)),build=compiled,red=red,restore_build=restored,green=green))
            print(name+": build/red/restore/green 0/1/0/0",flush=True)
        restored_full,_ = command("restored-full",full,0)
        assert fingerprints() == hashes, "price final exact restoration"
        write_record(DEST,json.dumps(dict(source_sha256=hashes,initial_build=initial_build,initial_green=initial_green,
            checks=checks,restored_full=restored_full),indent=2)+"\n")
        verify(); complete=True
    finally:
        restore()
        if not complete: command("failure-restored-build",build,0)
        for s,handler in handlers.items(): signal.signal(s,handler)


if __name__ == "__main__": main()
