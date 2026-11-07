#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compile deliberate production changes, detect runtime assertions, restore and rerun."""
from contextlib import chdir
import hashlib
from evidence import write_record
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

from cases import APP
from network import run_owned

DEST=APP/"test/golden/move-utxos-mutation-record.json"


def mutations():
    move="Cyberkrill/MoveUtxos.lean";app="Cyberkrill/App.lean";core="Cyberkrill/CoreRpc.lean"
    rows = [
        ("scope-raw-bytes","test/scope.py",'assert all(original_raw[k] == current_raw[k] for k in original_raw if k != ISSUE)','assert all(original_raw[k] == current_raw[k] for k in [] if k != ISSUE)',["scope-bytes"],"move scope raw serialization"),
        ("registration",app,'Cli.Cmd.mk "onchain-move-utxos"','Cli.Cmd.mk "disabled-onchain-move-utxos"',["replay","absolute"],"move CLI success"),
        ("required-input",app,'if inputs.isEmpty then throw .invalidArguments','if false then throw .invalidArguments',["refusals"],"move required flags"),
        ("required-destination",app,'let some destination := flag "destination" | throw .invalidArguments','let destination := (flag "destination").getD ""',["refusals"],"move required flags"),
        ("fee-units-absolute","Cyberkrill/Amounts.lean",'if hasBitcoinUnit s then parseAmount s else .error .feeUnitRequired','parseAmount s',["replay","absolute-bare"],"move bare fee handler refusal"),
        ("fee-units-rate","Cyberkrill/Amounts.lean",'if hasBitcoinUnit s then parseAmount s else .error .feeUnitRequired','parseAmount s',["replay","rate-bare"],"move bare fee handler refusal"),
        ("max-grammar",move,'if PsbtCommands.fiatValid text then return else throw e','if false then return else throw e',["injected"],"move runtime ordering"),
        ("max-grouped-exponent",move,'if PsbtCommands.fiatValid text then return else throw e','if recognizableFiat text then\n      match PsbtCommands.parseOutputs ("unused:" ++ text) with\n      | .error .fiatNotSupported => return\n      | _ => throw e\n    else throw e',["injected"],"move runtime ordering"),
        ("maximum-floor",move,'floorSat (← parseAmount text)','wholeSat (← parseAmount text)',["controls","fractional-cap"],"move synthetic success"),
        ("maximum-subsat",move,'floorSat (← parseAmount text)','pure (← parseAmount text)',["refusals"],"move executable refusal/help"),
        ("lookup-all",move,'for input in inputs do','for input in (if maximum.isSome then inputs.extract 0 1 else inputs) do',["replay","overshoot"],"move CLI success"),
        ("lookup-order",move,'for input in inputs do','for input in inputs.reverse do',["replay","f64"],"move CLI success"),
        ("lookup-index",move,'let some output := outputs[index]? | throw .invalidResult','let some output := outputs.find? (fun output => (output.getObjValAs? Nat "n").toOption == some index) | throw .invalidResult',["controls","unrelated-fields"],"move synthetic success"),
        ("lookup-precision",move,'CoreRpc.amount value','CoreRpc.amount value |>.map (fun amount => (⟨amount.msat.toUInt64.toFloat.toUInt64.toNat⟩ : Amount))',["controls","exact-values"],"move synthetic"),
        ("no-global-dedup",move,'  let mut values := #[]','  let inputs := inputs.foldl (fun acc input => if acc.any (fun i => i.txid == input.txid && i.vout == input.vout) then acc else acc.push input) (#[] : Array CoreRpc.Input)\n  let mut values := #[]',["controls","duplicate-input"],"move synthetic success"),
        ("uncapped-order",move,'| none => values.toList','| none => values.toList.reverse',["controls","no-cap"],"move synthetic success"),
        ("stable-ties",move,'a.2.msat ≥ b.2.msat','a.2.msat > b.2.msat',["controls","overshoot"],"move synthetic success"),
        ("descending",move,'a.2.msat ≥ b.2.msat','a.2.msat ≤ b.2.msat',["controls","below-largest"],"move synthetic success"),
        ("threshold-before-add",move,'total.msat ≥ cap.msat','total.msat > cap.msat',["controls","exact-cap"],"move synthetic success"),
        ("no-clamp",move,'let output : Amount := ⟨total.msat - fee.msat⟩','let output : Amount := ⟨(maximum.map (fun cap => min cap.msat total.msat)).getD total.msat - fee.msat⟩',["replay","overshoot"],"move complete JSON overshoot"),
        ("fee-selected-count",move,'Fee.estimateWeight selected.size 1','Fee.estimateWeight inputs.size 1',["controls","capped-rate"],"move synthetic success"),
        ("fee-one-output",move,'Fee.estimateWeight selected.size 1','Fee.estimateWeight selected.size 2',["controls","fractional-rate"],"move synthetic success"),
        ("fee-absolute-floor",move,'Amount.ofSats (fee.msat / 1000)','Amount.ofSats ((fee.msat + 500) / 1000)',["controls","fractional-fee"],"move synthetic success"),
        ("fee-subsat-allowed",move,'pure (Amount.ofSats (fee.msat / 1000))','pure (Amount.ofSats (max 1 (fee.msat / 1000)))',["controls","subsat-fee"],"move synthetic success"),
        ("positive-output",move,'unless total.msat > fee.msat do','unless true do',["controls","equal-fee"],"move synthetic refusal"),
        ("psbt-original-spelling",move,'unless (Base64.decode psbt).isSome do throw (.offline "psbtBase64")','unless true do throw (.offline "psbtBase64")',["controls","psbt-space-10"],"move synthetic refusal"),
        ("psbt-curve",move,'let _ ← PsbtCli.parse psbt','let _ := psbt',["deep","curve"],"move synthetic refusal"),
        ("psbt-hash",move,'let _ ← PsbtCli.parse psbt','let _ := psbt',["deep","hash"],"move synthetic refusal"),
        ("psbt-same-point",move,'let _ ← PsbtCli.parse psbt','let _ := psbt',["deep","same-point"],"move synthetic refusal"),
        ("writer-retained",app,'    let .ok writer ← prepareDecodeOutput services args.output | return .error .outputFailure\n    if args.feeRate.isNone','    let .ok writer ← prepareDecodeOutput services none | return .error .outputFailure\n    if args.feeRate.isNone',["injected"],"move injected success"),
        ("raw-bytes",app,'          services.writeOrdinaryFile path result.psbt','          services.writeOrdinaryFile path (result.psbt ++ "\\n")',["replay","raw"],"move raw bytes no newline"),
        ("descriptor-dedup",core,'unless result.any (fun u => u.txid == value.txid && u.vout == value.vout) do','if true then',["expansions","scope-dedup"],"move expansion status"),
        ("derive-fallback",core,'| .error _ => pure #[]','| .error e => return .error e',["expansions","derive-fallback"],"move expansion status"),
        ("implicit-cookie",core,'  return pairAuth flags.user flags.password','  if flags.bitcoinDir.isNone then\n    if let some home ← IO.getEnv "HOME" then\n      try\n        if let some auth := parseCookie (← IO.FS.readFile (System.FilePath.mk home / ".bitcoin" / ".cookie")) then return some auth\n      catch _ => pure ()\n  return pairAuth flags.user flags.password',["auth","none"],"move auth secret suppression"),
        *[(stage+"-"+kind,move,old,new,["limits",stage+"-"+kind],"move inherited "+stage+"-"+kind)
          for stage,old,newbase in [
            ("expansion","PsbtCommands.expand client args.inputs","PsbtCommands.expand { client with FIELD := VALUE } args.inputs"),
            ("lookup",'client.call "getrawtransaction"','({ client with FIELD := VALUE } : CoreRpc.Client).call "getrawtransaction"'),
            ("final","client.createPsbt selected","({ client with FIELD := VALUE } : CoreRpc.Client).createPsbt selected")]
          for kind,new in [
            ("size",newbase.replace("FIELD","maxResponseBytes").replace("VALUE","1048576")),
            ("timeout",newbase.replace("FIELD","totalTimeoutMs").replace("VALUE","30000"))]],
    ]

    # Use context only where creation deliberately shares an identical check.
    # The mutation itself remains confined to move's dispatch branch.
    source = (APP / app).read_text()
    branch = source[source.index("  | .moveUtxos args => do"):source.index("  | .createPsbt args => do")]
    def dispatch(name, old, new, selection, assertion):
        assert branch.count(old) == 1, "move dispatch edit target " + name
        context = old
        while source.count(context) != 1:
            start = branch.index(context)
            preceding = branch.rfind("\n", 0, max(0, start-1)) + 1
            context = branch[preceding:start] + context
        changed = context.replace(old, new, 1)
        rows.append((name, app, context, changed, selection, assertion))
    writer = "    let .ok writer ← prepareDecodeOutput services args.output | return .error .outputFailure\n"
    missing = '    if args.feeRate.isNone && args.fee.isNone then\n      return .error (.onchain "missingFee: Specify either --fee-rate or --fee")\n'
    dispatch("missing-fee-after-open", writer+missing, missing+writer,
             ["ordering", "missing-fee"], "move runtime ordering missing-fee")
    network = '    unless ListUtxos.networkValid args.network do\n      return .error (.onchain "invalidNetwork: Expected mainnet, bitcoin, testnet, signet or regtest")\n'
    backend = '    if args.walletFile.isSome then\n      return .error (.onchain "unsupportedWalletFile: PSBT wallet-file routing requires BDK")\n    if args.descriptor.isSome && args.rpc.bitcoinDir.isSome then\n      return .error (.onchain "unsupportedBackend: descriptor with bitcoin-dir requires BDK")\n'
    dispatch("network-before-backend",network+backend,backend+network,
             ["ordering", "network-before-backend"],"move runtime ordering network-before-backend")
    for name, condition, assertion in [
        ("wallet-no-directory", "args.rpc.bitcoinDir.isSome", "move injected wallet"),
        ("wallet-directory", "args.rpc.bitcoinDir.isNone", "move injected wallet-directory")]:
        dispatch(name, "    if args.walletFile.isSome then", "    if args.walletFile.isSome && " + condition + " then",
                 ["injected"], assertion)
    dispatch("descriptor-directory", "    if args.descriptor.isSome && args.rpc.bitcoinDir.isSome then",
             "    if false then", ["injected"], "move injected bdk")
    maximum = '    let maximumResult ← match args.maxAmount with\n      | none => pure (.ok none)\n      | some text => do pure ((← maximumWith services text).map some)\n    let maximum ← match maximumResult with\n      | .error e => return .error e\n      | .ok maximum => pure maximum\n'
    client = '    let client ← try services.coreClient args.rpc catch _ =>\n      return .error (.onchain "rpcTransport: Cannot initialize Core client")\n'
    for name in ["fiat", "floor"]:
        dispatch("maximum-before-client-"+name, maximum+client, client+maximum,
                 ["ordering",name],"move runtime ordering "+name)
    rows += [
        ("strict-raw-missing-identity",core,'txid := ← string raw "txid", raw,','txid := (string raw "txid").toOption.getD "synthetic", raw,',["strict","missing-identity"],"move strict raw result"),
        ("strict-raw-malformed-identity",core,'txid := ← string raw "txid", raw,','txid := (string raw "txid").toOption.getD "synthetic", raw,',["strict","malformed-identity"],"move strict raw result"),
        ("strict-raw-missing-unrelated",core,'do amount (← field output "value")','pure (((field output "value").bind amount).toOption.getD (Amount.ofSats 0))',["strict","missing-unrelated"],"move strict raw result"),
        ("strict-raw-malformed-unrelated",core,'do amount (← field output "value")','pure (((field output "value").bind amount).toOption.getD (Amount.ofSats 0))',["strict","malformed-unrelated"],"move strict raw result"),
        ("typed-before-open",app,'| .error e => return ← reportError services e','| .error e =>\n      let _ ← services.openOrdinaryFile "json"\n      return ← reportError services e',["ordering","typed-fee"],"move runtime ordering typed-fee"),
        ("fee-parser-exclusivity",app,'    if p.hasFlag "fee-rate" && p.hasFlag "fee" then throw .invalidArguments','    if false then throw .invalidArguments',["ordering","fee-exclusive"],"move runtime ordering fee-exclusive"),
        ("typed-before-help",app,'validateTypedArgs (args.head?.getD "") args.tail','pure ()',["refusals"],"move executable refusal/help"),
        ("effective-help-before-typed",app,'let args := throughHelp args','validateTypedArgs (args.head?.getD "") args.tail\n  let args := throughHelp args',["refusals"],"move executable refusal/help"),
        ("existing-command-preprocessing",app,'if command == "onchain-move-utxos" then\n    valueFlags ++','if true then\n    valueFlags ++',["preprocessing"],"move preserves existing preprocessing"),
    ]
    return rows



def fingerprints():
    paths=["Cyberkrill/App.lean","Cyberkrill/MoveUtxos.lean","Cyberkrill/Amounts.lean","Cyberkrill/CoreRpc.lean",
        "Cyberkrill/PsbtCommands.lean","CyberkrillTests.lean","CyberkrillTests/MoveUtxos.lean",
        "test/move-utxos.py","test/move-utxos-mutations.py","test/move-utxos-provenance.json",
        "test/golden/move-utxos-reference.json","test/scope.py","test/evidence.py"]
    return {p:hashlib.sha256((APP/p).read_bytes()).hexdigest() for p in paths}


def verify():
    record=json.loads(DEST.read_bytes());rows=mutations()
    assert len(rows)==len(record["checks"])==56,"move detecting selection inventory"
    assert record["source_sha256"]==fingerprints(),"move stale mutation evidence"
    for check,row in zip(record["checks"],rows):
        assert [check[k] for k in ["property","file","replace","with_text","selection","assertion"]]==list(row),"move mutation identity"
        assert check["build"]["status"]==check["restore_build"]["status"]==check["green"]["status"]==0,"move mutation compiled/restored"
        assert check["red"]["status"]==1 and row[-1] in check["failure"],"move intended runtime red"
    assert record["initial_build"]["status"]==record["initial_green"]["status"]==record["restored_full"]["status"]==0
    print(f"move mutation evidence: {len(rows)}/56 compiled changes/runtime reds, exact restoration and greens",flush=True)


def main():
    if sys.argv[1:]==["--verify"]:verify();return 0
    assert not sys.argv[1:]
    logs=APP/".lake/validation/move-mutations"/str(time.time_ns());logs.mkdir(parents=True)
    rows=mutations();originals={p:(APP/p).read_bytes() for _,p,*_ in rows};source=fingerprints()
    managed=[signal.SIGHUP,signal.SIGINT,signal.SIGTERM,signal.SIGQUIT]
    def interrupted(signum,_):raise InterruptedError("move mutation interrupted")
    handlers={sig:signal.signal(sig,interrupted) for sig in managed}
    def write(path,data):
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,managed)
        try:(APP/path).write_bytes(data);assert (APP/path).read_bytes()==data,"move exact source bytes"
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    def restore():
        for p,data in originals.items():write(p,data)
    def command(name,args,status,assertion=None):
        start=time.monotonic()
        with tempfile.TemporaryDirectory(prefix=name+"-",dir=logs) as parent,chdir(APP):
            proc=run_owned(args,env=dict(os.environ,TMPDIR=parent,PYTHONDONTWRITEBYTECODE="1"),capture_output=True,timeout=300)
        for stream in ["stdout","stderr"]:(logs/(name+"."+stream)).write_bytes(getattr(proc,stream))
        (logs/(name+".status")).write_text(str(proc.returncode)+"\n")
        failure=(proc.stdout+proc.stderr).decode(errors="replace")
        assert proc.returncode==status,"move mutation status "+name+": "+failure
        if assertion:assert assertion in failure and ("AssertionError:" in failure or "assertion failed:" in failure),"move intended runtime red "+name
        return dict(command=args,status=proc.returncode,seconds=round(time.monotonic()-start,3)),failure
    build=["lake","build","cyberkrill","CyberkrillTests"];tests=["python3","-B","test/move-utxos.py"]
    complete=False
    try:
        initial_build,_=command("initial-build",build,0)
        initial_green,_=command("initial-green",tests,0)
        checks=[]
        for index,(name,path,old,new,selection,assertion) in enumerate(rows):
            text=originals[path].decode();assert text.count(old)==1,"move mutation match "+name
            label=f"{index:02}-{name}"
            try:
                write(path,text.replace(old,new,1).encode())
                compiled,_=command(label+"-build",build,0)
                red,failure=command(label+"-red",tests+selection,1,assertion)
            finally:restore()
            rebuilt,_=command(label+"-restore-build",build,0)
            green,_=command(label+"-green",tests+selection,0)
            checks.append(dict(property=name,file=path,replace=old,with_text=new,selection=selection,
                assertion=assertion,failure=next(line for line in failure.splitlines() if assertion in line and ("AssertionError:" in line or "assertion failed:" in line)),
                build=compiled,red=red,restore_build=rebuilt,green=green))
            print(name+": build/red/restore/green 0/1/0/0",flush=True)
        full,_=command("restored-full",tests,0)
        assert fingerprints()==source,"move final source restoration"
        write_record(DEST, json.dumps(dict(source_sha256=source, initial_build=initial_build, initial_green=initial_green, checks=checks, restored_full=full), indent=2) + '\n')
        verify();complete=True
    finally:
        restore()
        if not complete:command("failure-restored-build",build,0)
        for sig,handler in handlers.items():signal.signal(sig,handler)
    return 0


if __name__=="__main__":sys.exit(main())
