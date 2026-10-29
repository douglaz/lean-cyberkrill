#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Compiled independent production regressions, exact restoration and evidence."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cases import APP


def mutations():
    app="Cyberkrill/App.lean"; invite="Cyberkrill/Invite.lean"; psbt="Cyberkrill/Psbt.lean"
    rows=[]
    def add(name,path,old,new,case,assertion):
        rows.append((name,path,old,new,[(case,assertion)]))
    add("invite-dispatch",app,'return .decodeInvite input (flag "output")','return .help "wrong"',"invite/primary-0","offline output newline")
    add("invite-encode-dispatch",app,'return .encodeInvite input.value (p.hasFlag "skip-api-secret") (flag "output")','return .help "wrong"',"invite-json/primary-0","offline exact string")
    add("psbt-dispatch",app,'return .decodePsbt input ((flag "network").getD "mainnet") (flag "output")','return .decodeInvite input (flag "output")',"bip174Valid/0","offline success status")
    add("psbt-path-routing",app,'if ← services.pathExists value then services.readFile value else pure value','if false then services.readFile value else pure value',"routing/onchain-decode-psbt/existing-file","offline success status")
    add("psbt-dash-routing",app,'| some value =>\n        if ← services.pathExists value','| some value =>\n        if value == "-" then services.readStdin else\n        if ← services.pathExists value',"routing/onchain-decode-psbt/literal-dash","offline ordinary failure status")
    add("invite-skip-secret",invite,'if skipSecret then { invite with apiSecret := none } else invite','if false then { invite with apiSecret := none } else invite',"invite-json/primary-skip-1","offline exact string")
    add("invite-consensus-before-fallback",invite,'| .ok invite => return invite','| .ok _ => fallback bytes',"invite/primary-1","offline unlisted difference")
    add("invite-no-fallback",invite,'| .error _ => fallback bytes','| .error _ => throw failure',"invite/truncated-wss","offline success status")
    add("invite-prefix",invite,'decodePayload input','decodePayload input.toLower',"invite/uppercase","offline ordinary failure status")
    add("invite-checksum",invite,'let symbols ← (decodePayload input).mapError fun _ => failure',
        'let symbols ← match decodePayload input with\n    | .ok symbols => pure symbols\n    | .error _ => return ← fallback "wss://x".toUTF8',
        "invite/checksum","offline ordinary failure status")
    rows[-1][4].extend(("invite/"+case,"offline ordinary failure status") for case in ["wrong-hrp","wrong-variant"])
    add("invite-original-padding",invite,'Bitcoin.Bech32.fesToBytesLax symbols','Bitcoin.Bech32.fesToBytesLax (symbols.dropLast)',"invite/lax-padding","offline unlisted difference")
    add("fallback-prefix-width",invite,'pos + 6 < bytes.size','pos + 7 < bytes.size',"invite/id-length-8","offline success status")
    add("fallback-printable-low",invite,'b.toNat > 31 &&','b.toNat > 32 &&',"invite/ascii32","offline unlisted difference")
    add("fallback-printable-high",invite,'b.toNat < 127','b.toNat < 128',"invite/ascii127","offline unlisted difference")
    add("fallback-no-http",invite,'marker == "https:".toUTF8','marker == "http:/".toUTF8',"invite/http-fallback-reject","offline ordinary failure status")
    rows[-1][4].append(("invite/https-six","offline success status"))
    add("fallback-overlap-order",invite,'for pos in [:bytes.size] do','for pos in (List.range bytes.size).reverse do',"invite/nested","offline unlisted difference")
    add("fallback-id-threshold",invite,'bytes.size ≥ 64','bytes.size > 64',"invite/id-length-64","offline unlisted difference")
    add("fallback-id-width",invite,'min 32 bytes.size','min 31 bytes.size',"invite/id-length-32","offline unlisted difference")
    add("invite-peer-width",invite,'peer ≥ 65536','peer > 65536',"invite-json/peer-2","offline ordinary failure status")
    add("invite-json-token", "Cyberkrill/InvoiceJson.lean",'let _ ← checkObject guardian ["peer_id", "url"] ["peer_id"]','let _ ← checkObject guardian ["peer_id", "url"] []',"invite-json/peer-token-exponent","offline ordinary failure status")
    add("invite-json-ignored-field", "Cyberkrill/InvoiceJson.lean",'let fields ← structFields root known','let fields ← checkObject root known []',"invite-json/guardian-unknown-surrogate","offline success status")
    add("psbt-network-canonical",psbt,'| .mainnet => "bitcoin"','| .mainnet => "mainnet"',"bip174Valid/0","offline unlisted difference")
    add("psbt-network-case",psbt,'match input.toLower with','match input with',"network/bip174Valid/0/MAINNET","offline success status")
    add("psbt-strict-curve","Cyberkrill/Capabilities.lean",'where\n  isValidPubkey := Secp256k1.isValidPubkey\n  compressPubkey','where\n  isValidPubkey := fun _ => true\n  compressPubkey',"hybrid-partial-06-G","offline ordinary failure status")
    rows[-1][4].append(("hybrid-partial-07-negG","offline ordinary failure status"))
    add("psbt-hybrid-curve","Cyberkrill/Capabilities.lean",'compressPubkey := Secp256k1.compressPubkey','compressPubkey := fun key => if Secp256k1.isValidPubkey key then some key else none',"hybrid-input-06-G","offline success status")
    rows[-1][4].extend((case,"offline success status") for case in ["hybrid-input-07-negG","hybrid-output-06-G","hybrid-output-07-negG"])
    add("psbt-same-point",psbt,'let _ ← (psbt.checkBip32SamePoint pubkeys).mapError parseError','let _ : Unit := ()',"hybrid-input-02-G-and-04-G","offline ordinary failure status")
    rows[-1][4].extend((case,"offline ordinary failure status") for case in ["hybrid-input-04-G-and-06-G","hybrid-output-02-G-and-04-G"])
    add("psbt-signed-version",psbt,'toJson tx.signedVersion','toJson tx.version.toNat',"synthetic-psbt/signed-version","offline unlisted difference")
    add("psbt-v2-version",psbt,'toJson tx.signedVersion','toJson (if decoded.global.psbtVersion == 2 then (0 : Int) else tx.signedVersion)',"bip370Valid/0","offline v2 complete JSON")
    add("psbt-locktime",psbt,'toJson tx.locktime.toNat','toJson (tx.locktime.toNat + 1)',"bip370Locktimes/2","offline v2 complete JSON")
    rows[-1][4].append(("synthetic-psbt/missing-value","offline unlisted difference"))
    add("psbt-incompatible-locktime",psbt,'let tx ← decoded.unsignedTransaction.mapError parseError',
        'let tx := decoded.unsignedTransaction.toOption.getD { version := 0, inputs := #[], outputs := #[], locktime := 0 }',"bip370Locktimes/9","offline ordinary failure status")
    add("psbt-txid-order",psbt,'input.previousOutput.txid.data.toList.reverse.toArray','input.previousOutput.txid.data.toList.toArray',"bip370Valid/0","offline v2 complete JSON")
    rows[-1][4].append(("synthetic-psbt/missing-value","offline unlisted difference"))
    add("psbt-vout",psbt,'toJson input.previousOutput.index.toNat','toJson (input.previousOutput.index.toNat + 1)',"bip370Valid/0","offline v2 complete JSON")
    rows[-1][4].append(("synthetic-psbt/missing-value","offline unlisted difference"))
    add("psbt-sequence",psbt,'toJson input.sequence.toNat','toJson (input.sequence.toNat % 65536)',"bip370Valid/0","offline v2 complete JSON")
    rows[-1][4].append(("bip174Valid/0","offline unlisted difference"))
    add("psbt-witness-precedence",psbt,'fields.witnessUtxo.map (·.amount)','(none : Option UInt64)',"synthetic-psbt/witness-precedence","offline unlisted difference")
    add("psbt-nonwitness-index",psbt,'tx.outputs[input.previousOutput.index.toNat]?','tx.outputs[0]?',"synthetic-psbt/nonwitness-out-of-range","field set")
    add("psbt-total-input",psbt,'totalInput + value.toNat','totalInput + value.toNat + 1',"synthetic-psbt/fee-saturates","offline unlisted difference")
    add("psbt-total-output",psbt,'sum + out.amount.toNat','sum + out.amount.toNat + 1',"synthetic-psbt/fee-saturates","offline unlisted difference")
    add("psbt-fee-saturating",psbt,'totalInput - totalOutput','totalOutput - totalInput',"synthetic-psbt/fee-saturates","offline unlisted difference")
    add("psbt-exact-btc",psbt,'.num ⟨Int.ofNat sats, 8⟩','.num ⟨Int.ofNat (sats + 1), 8⟩',"synthetic-psbt/max-output","offline numeric value pin")
    rows[-1][4].append(("synthetic-psbt/witness","offline unlisted difference"))
    add("psbt-bip-excluded-identity",psbt,'.offline s!"psbtExcludedField:{scope}:{kind}"','.offline s!"psbtMissingField:{scope}:{kind}"',"parity/bip370-invalid-1","offline exception stream/file identity")
    add("psbt-bip-canonical-identity",psbt,'| .decode _ => .offline "psbtFraming"','| .decode _ => .offline "psbtBase64"',"parity/key-type-fd01","offline exception stream/file identity")
    add("psbt-bip-xpub-identity",psbt,'.offline s!"psbtInvalidValue:{scope}:{kind}:{reason}"','.offline s!"psbtInvalidValue:{scope}:{kind}:wrong"',"parity/xpub-depth","offline exception stream/file identity")
    add("invite-read-before-open",app,
        'let .ok text ← lightningInput services input false | return .error .inputFailure\n    let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure\n    return (InviteCli.decode',
        'let .ok writer ← prepareDecodeOutput services path | return .error .outputFailure\n    let .ok text ← lightningInput services input false | return .error .inputFailure\n    return (InviteCli.decode',"injected","offline error order inputFailure")
    add("invite-encode-late-open",app,'| .encodeInvite input skipSecret path => do',
        '| .encodeInvite input skipSecret path => do\n    let .ok _ ← prepareDecodeOutput services path | return .error .outputFailure',
        "routing/fm-encode-invite/bad-json-preserve","offline failed output existence/bytes")
    add("psbt-late-open",app,'| .decodePsbt input net path => do',
        '| .decodePsbt input net path => do\n    let .ok _ ← prepareDecodeOutput services path | return .error .outputFailure',
        "routing/onchain-decode-psbt/bad-psbt-preserve","offline failed output existence/bytes")
    add("psbt-network-before-input",app,'| .decodePsbt input net path => do',
        '| .decodePsbt input net path => do\n    let _ ← try services.readStdin catch _ => pure ""',
        "injected","offline boundary events invalidNetwork")
    add("invite-file-newline",app,'some (write, invite ++ "\\n")','some (write, invite)',
        "routing/fm-encode-invite/output-0","offline output newline")
    add("psbt-file-newline",app,'some (write, text ++ "\\n")','some (write, text)',
        "routing/onchain-decode-psbt/output-0","offline output newline")
    add("comparator-final-newline","test/offline-compare.py",'assert actual == actual.rstrip() + "\\n"',
        'assert actual.endswith("\\n")',"exact-selftest","exact comparator accepted incorrect final newline")
    add("ordinary-writer-lifetime",app,'return fun text => do\n      handle.putStr text\n      handle.flush',
        'return fun text => do\n      let _ := handle\n      pure ()',"fifo/fm-decode-invite","FIFO output bytes before EOF")
    rows[-1][4].extend(("fifo/"+name,"FIFO output bytes before EOF") for name in ["fm-encode-invite","onchain-decode-psbt"])
    add("help-short-circuit",app,'let args := throughHelp args','let args := args',
        "ordered-help/fm-decode-invite/help-unknown","ordered help short circuit")
    rows[-1][4].extend(("ordered-help/"+command+"/help-unknown","ordered help short circuit")
        for command in ["fm-encode-invite","onchain-decode-psbt"])
    add("help-earlier-error",app,'let args := throughHelp args',
        'let args := if args.contains "--help" then [args.head?.getD "", "--help"] else throughHelp args',
        "ordered-help/fm-decode-invite/unknown-help","ordered help earlier error or operand")
    rows[-1][4].extend(("ordered-help/"+command+"/unknown-help","ordered help earlier error or operand")
        for command in ["fm-encode-invite","onchain-decode-psbt"])
    add("file-observation-newlines","test/capture-offline.py",'path.read_bytes().decode("utf-8") if path.is_file()',
        'path.read_text() if path.is_file()',"file/fm-encode-invite/crlf","file comparator accepted newline/field")
    rows[-1][4].extend(("file/"+case,"file comparator accepted newline/field")
        for case in ["fm-encode-invite/cr","onchain-decode-psbt/crlf","onchain-decode-psbt/cr"])
    commands = ["fm-decode-invite", "fm-encode-invite", "onchain-decode-psbt"]
    def cluster_checks(names, assertion):
        return [("cluster-help/"+command+"/"+name, assertion) for command in commands for name in names]
    add("cluster-recognition", app, 'flag.startsWith "-h"', 'flag == "-h"',
        "cluster-help/fm-decode-invite/hx", "cluster help short circuit")
    rows[-1][4][:] = cluster_checks(["hx", "hh", "h-equals-one"], "cluster help short circuit")
    add("cluster-earlier-errors", app, 'let args := throughHelp args',
        'let args := if args.any (·.startsWith "-h") then [args.head?.getD "", "-h"] else throughHelp args',
        "cluster-help/fm-decode-invite/unknown-hh", "cluster help earlier error or operand")
    rows[-1][4][:] = cluster_checks(["unknown-hh", "repeat-output-cluster"], "cluster help earlier error or operand")
    rows[-1][4].extend(("cluster-help/"+command+"/"+case, "cluster help earlier error or operand")
        for command,case in [("fm-encode-invite","repeat-skip-cluster"), ("onchain-decode-psbt","repeat-network-cluster")])
    add("cluster-short-output-attachment", app, 'flag.startsWith "-h"',
        '(flag.startsWith "-h" || flag.startsWith "-oh" || flag.startsWith "-o-h")',
        "cluster-help/fm-decode-invite/output-short-h", "offline output existence")
    rows[-1][4][:] = [("cluster-help/"+command+"/"+case, assertion) for command in commands
        for case,assertion in [("output-short-h", "offline output existence"), ("output-short-hyphen", "offline output newline")]]
    add("cluster-long-output-attachment", app, 'flag == "--help"',
        '(flag == "--help" || flag.startsWith "--output=-h")',
        "cluster-help/fm-decode-invite/output-long-hyphen", "offline output newline")
    rows[-1][4][:] = cluster_checks(["output-long-hyphen"], "offline output newline")
    add("cluster-output-value-guard", app, 'unless outputArgsValid args.tail do throw .invalidArguments', 'pure ()',
        "cluster-help/fm-decode-invite/value-missing-then-help", "cluster help earlier error or operand")
    rows[-1][4][:] = cluster_checks(["value-missing-then-help"], "cluster help earlier error or operand")
    add("cluster-terminator", app,
        'private def throughHelp : List String → List String\n  | "--" :: rest => "--" :: rest',
        'private def throughHelp : List String → List String\n  | "--" :: rest => throughHelp rest',
        "cluster-help/fm-decode-invite/terminator-long-help", "cluster help earlier error or operand")
    rows[-1][4][:] = cluster_checks(["terminator-long-help"], "cluster help earlier error or operand")
    add("cluster-long-help-value", app, 'flag == "--help"', 'flag.startsWith "--help"',
        "cluster-help/fm-decode-invite/long-help-value", "cluster help earlier error or operand")
    rows[-1][4][:] = cluster_checks(["long-help-value"], "cluster help earlier error or operand")
    add("comparator-unchanged-input", "test/offline-compare.py",
        'assert a == b, "offline unchanged input bytes: " + name', 'assert True',
        "offline-selftest", "offline comparator accepted changed input bytes")
    add("typed-help-enum", app,
        'unless ["btc", "sats", "msats"].contains value do throw .invalidUnit', 'pure ()',
        "carried-help/enum-attached", "carried help preceding typed error")
    rows[-1][4].extend(("carried-help/"+case, "carried help preceding typed error")
        for case in ["enum-spaced", "enum-missing-terminator"])
    add("typed-help-u32-grammar", app,
        'unless (wordCount? value).isSome do throw .invalidWordCount',
        'unless value == "abc" || (wordCount? value).isSome do throw .invalidWordCount',
        "carried-help/words-spaced", "carried help preceding typed error")
    rows[-1][4].append(("carried-help/words-equals", "carried help preceding typed error"))
    add("typed-help-u32-width", app, 'if n ≤ 4294967295 then some n else none',
        'if n ≤ 4294967296 then some n else none',
        "carried-help/words-u32-overflow", "carried help preceding typed error")
    rows[-1][4].append(("carried-help/words-long-overflow", "carried help preceding typed error"))
    add("typed-help-missing", app, 'if pending then\n      check flag',
        'if pending then\n      if flag != "--" then check flag',
        "carried-help/enum-missing-terminator", "carried help preceding typed error")
    rows[-1][4].append(("carried-help/words-missing-terminator", "carried help preceding typed error"))
    add("typed-help-order", app,
        'let args := throughHelp args\n  validateTypedArgs (args.head?.getD "") args.tail',
        'validateTypedArgs (args.head?.getD "") (args.tail.filter (fun token => !(token.startsWith "-h") && token != "--help"))\n  let args := throughHelp args',
        "carried-help/enum-help-first-attached", "carried help before runtime")
    rows[-1][4].append(("carried-help/words-help-first-grammar", "carried help before runtime"))
    add("typed-help-semantic-count", app,
        'unless (wordCount? value).isSome do throw .invalidWordCount',
        'unless (wordCount? value).isSome && value != "13" do throw .invalidWordCount',
        "carried-help/words-semantic-13", "carried help before runtime")
    rows[-1][4].append(("carried-help/words-semantic-attached", "carried help before runtime"))
    assert len(rows) == 67 and sum(len(row[4]) for row in rows) == 125, "offline mutation construction counts"
    return rows


def fingerprints():
    paths=sorted((APP/"Cyberkrill").glob("*.lean"))+sorted((APP/"CyberkrillTests").glob("*.lean"))
    paths += [APP/name for name in ["Main.lean","Cyberkrill.lean","CyberkrillTests.lean","lakefile.lean"]]
    paths += [APP/"test"/name for name in ["offline.py","offline-inputs.py","offline-compare.py","offline-mutate.py",
        "capture-offline.py","record-offline.py","hybrid-inputs.py","psbt-oracle.py","fifo.py","compare.py","driver.py","verify.py","scope.py","validate.py",
        "offline-exact-selftest.py","recapture-history.py","ordered-help.py","file-observation.py","boundary-regressions.py",
        "cluster-help.py","cluster-regressions.py","carried-help.py","carried-regressions.py"]]
    paths += [APP/"test/golden"/name for name in ["offline-reference.json","offline-provenance.json","offline-exceptions.json","offline-errors.json","hybrid-inputs.json","offline-port-timings.json",
        "offline-exact-comparator-record.json","offline-history-recapture.json","ordered-boundary-regression.json","cluster-regression.json","carried-regression.json"]]
    return {str(p.relative_to(APP)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def verify():
    record=json.loads((APP/"test/golden/offline-mutation-record.json").read_bytes())
    assert record["source_sha256"] == fingerprints(), "stale offline mutation evidence"
    planned=mutations()
    assert record["count"] == len(record["mutations"]) == len(planned)
    assert len({tuple(r[1:4]) for r in planned}) == len(planned), "distinct offline production edits"
    for row, (name,path,old,new,tests) in zip(record["mutations"],planned):
        assert (row["property"],row["file"],row["replace"],row["with_text"]) == (name,path,old,new)
        assert row["build"]["status"] == row["restore_build"]["status"] == 0
        for observed,(case,assertion) in zip(row["checks"],tests):
            assert observed["case"] == case and observed["assertion"] == assertion
            assert observed["red"]["status"] == 1 and assertion in observed["failure"] and "AssertionError:" in observed["failure"]
            assert observed["green"]["status"] == 0
        assert len(row["checks"]) == len(tests)
    assert record["executions"] == sum(len(r[4]) for r in planned)
    assert record["restored_full"]["status"] == 0
    print(f"offline mutations: {len(planned)} distinct compiled edits, {record['executions']} selected runtime reds; exact restoration and full suite exit 0")


def main():
    if sys.argv[1:] == ["--verify"]: verify(); return
    assert not sys.argv[1:]
    os.chdir(APP)
    rows=mutations(); hashes=fingerprints()
    logs=APP/".lake/offline-mutations"; logs.mkdir(parents=True,exist_ok=True)
    originals={Path(r[1]):Path(r[1]).read_bytes() for r in rows}
    signals=(signal.SIGHUP,signal.SIGINT,signal.SIGQUIT,signal.SIGTERM)
    def write(path,data):
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,signals)
        try: path.write_bytes(data); assert path.read_bytes() == data, "offline exact restoration"
        finally: signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    def restore():
        for path,data in originals.items(): write(path,data)
    def interrupted(signum,_): restore(); raise SystemExit(128+signum)
    for signum in signals: signal.signal(signum,interrupted)
    def command(label,args):
        bounded=["timeout","--foreground","180",*args]; start=time.monotonic()
        result=subprocess.run(bounded,stdin=subprocess.DEVNULL,capture_output=True,timeout=190)
        for stream in ["stdout","stderr"]: (logs/(label+"."+stream)).write_bytes(getattr(result,stream))
        (logs/(label+".status")).write_text(str(result.returncode)+"\n")
        return result,dict(command=bounded,status=result.returncode,seconds=round(time.monotonic()-start,3))
    def test(case):
        if case.startswith("carried-help/"): return ["python3","-B","test/carried-help.py",case]
        if case.startswith("cluster-help/"): return ["python3","-B","test/cluster-help.py",case]
        if case.startswith("ordered-help/"): return ["python3","-B","test/ordered-help.py",case]
        if case.startswith("file/"): return ["python3","-B","test/file-observation.py",case[5:]]
        if case.startswith("fifo/"): return ["python3","-B","test/fifo.py",case[5:]]
        if case == "exact-selftest": return ["python3","-B","test/offline-exact-selftest.py","--verify"]
        if case == "offline-selftest": return ["python3","-B","test/offline.py","--selftest"]
        if case == "injected": return ["python3","-B","-c",
            'import subprocess; p=subprocess.run([".lake/build/bin/CyberkrillTests","--offline-boundaries"],stdin=subprocess.DEVNULL,capture_output=True,timeout=30); assert p.returncode == 0, p.stderr.decode()']
        return ["python3","-B","test/offline.py","--case",case]
    records=[]
    try:
        for name,path,old,new,tests in rows:
            original=originals[Path(path)]; source=original.decode()
            assert source.count(old) == 1 and old != new, "unique offline mutation: "+name
            checks=[]
            try:
                write(Path(path),source.replace(old,new,1).encode())
                compiled,build=command(name+"-build",["lake","build","cyberkrill","CyberkrillTests"])
                assert compiled.returncode == 0, "offline mutation must compile: "+name
                for index,(case,assertion) in enumerate(tests):
                    p,red=command(name+f"-{index}-red",test(case)); failure=p.stderr.decode()
                    assert p.returncode == 1 and assertion in failure and "AssertionError:" in failure, "offline detecting runtime assertion: "+name
                    detecting=next(line for line in failure.splitlines() if line.startswith("AssertionError:"))
                    checks.append(dict(case=case,assertion=assertion,red=red,failure=detecting))
            finally: write(Path(path),original)
            p,restored=command(name+"-restore",["lake","build","cyberkrill","CyberkrillTests"])
            assert p.returncode == 0, "offline restored compilation: "+name
            for index,(check,(case,_)) in enumerate(zip(checks,tests)):
                p,check["green"]=command(name+f"-{index}-green",test(case))
                assert p.returncode == 0, "offline restored selected case: "+name
            records.append(dict(property=name,file=path,replace=old,with_text=new,build=build,restore_build=restored,checks=checks))
            print(name+": compiled; runtime red(s); restored green(s)",flush=True)
        p,full=command("restored-full",["lake","test"])
        assert p.returncode == 0, "offline restored full suite"
        assert fingerprints() == hashes, "offline final exact source restoration"
        record=dict(count=len(records),executions=sum(len(r["checks"]) for r in records),
                    source_sha256=hashes,mutations=records,restored_full=full)
        (APP/"test/golden/offline-mutation-record.json").write_text(json.dumps(record,indent=2)+"\n")
    finally:
        restore()
        # Even a failed experiment leaves executable artifacts built from the
        # restored bytes, before any subsequent local binary is invoked.
        p,_=command("final-restored-build",["lake","build","cyberkrill","CyberkrillTests"])
        assert p.returncode == 0, "offline final restored build"
    verify()


if __name__ == "__main__": main()
