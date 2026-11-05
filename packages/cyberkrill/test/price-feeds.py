#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Exact pure vectors and isolated, owned TLS replay through the app entry point."""
from contextlib import contextmanager, ExitStack, chdir
from decimal import Decimal
from fractions import Fraction
import importlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile

from cases import APP, ROOT
from compare import exact_json
import network

C = importlib.import_module("price-cases")
EXE = APP / ".lake/build/bin/CyberkrillTests"


def invoke(selector, payload, *, environment=None):
    cwd = Path((environment or os.environ)["HOME"]) if network.sandbox() or network.isolated() else APP
    result = subprocess.run([str(EXE), selector], input=json.dumps(payload).encode(), cwd=cwd,
                            env=environment, capture_output=True, timeout=45)
    assert result.returncode == 0 and not result.stderr, "price test process: " + result.stderr.decode()
    return exact_json(result.stdout)


def pure():
    rows = C.pure_cases()
    assert len(rows) == 561, "price pure vector inventory"
    actual = invoke("--price-evaluate", [{k: v for k, v in row.items() if k != "expected"} for row in rows])
    assert len(actual) == len(rows), "price result inventory"
    for row, observed in zip(rows, actual):
        assert observed["id"] == row["id"], "price vector identity"
        expected = row["expected"]
        if isinstance(expected, dict) and "error_contains" in expected:
            assert set(observed["result"]) == {"error"} and expected["error_contains"] in observed["result"]["error"], row["id"] + " diagnostic"
        else:
            assert observed["result"] == expected, row["id"] + ": " + repr(observed["result"]) + " != " + repr(expected)
    added = C.observed_price_cases()
    assert len(added) == 61 and rows[426:487] == added, "observed price pure coverage"
    remaining = C.remaining_price_cases(rows[:487])
    assert len(remaining) == 74 and rows[487:] == remaining, "remaining precision/path pure coverage"
    print(f"price exact parser/grammar/conversion/median vectors: {len(rows)}/561; observed additions: {len(added)}/61", flush=True)
    print("remaining precision/path additions: 74/74; diagnostic inputs 66 parser + 5 CLI; five existing Bitstamp authorities reused", flush=True)
    importlib.import_module("price-parity").verify(rows, actual)


def correction_probe(name):
    if name == "numeric-limit":
        rows = [dict(id="bounded-exponent", op="parse", source="bitstamp", currency="USD", body='{"last":1e1025}')]
        result = invoke("--price-evaluate", rows)[0]["result"]
        assert result == dict(error="Invalid Bitstamp JSON"), "numeric token rejected before JSON expansion"
    elif name == "surrogate":
        rows = [dict(id="lone-surrogate", op="parse", source="bitstamp", currency="USD", body='{"x":"\\ud800","last":1}')]
        result = invoke("--price-evaluate", rows)[0]["result"]
        assert result == dict(error="Invalid Bitstamp JSON"), "lone surrogate rejected in ignored field"
    elif name in ["depth", "ignored-underflow", "ignored-overflow", "zero-token", "malformed-sign", "negative-range"]:
        bodies = {
            "depth": ('{"last":95000,"ignored":'+'['*127+'0'+']'*127+'}', dict(error="Invalid Bitstamp JSON")),
            "ignored-underflow": ('{"ignored":1e-1025,"last":95000}', dict(ok=C.ratio(95000))),
            "ignored-overflow": ('{"ignored":1e400,"last":95000}', dict(error="Invalid Bitstamp JSON")),
            "zero-token": ('{"last":0e5000}', dict(error="Bitstamp last price must be positive")),
            "malformed-sign": ('{"last":"-+5"}', dict(error="Bitstamp last price is not a number")),
            "negative-range": ('{"last":"-1e2000"}', dict(error="Bitstamp last price must be positive")),
        }
        body, expected = bodies[name]
        result = invoke("--price-evaluate", [dict(id=name, op="parse", source="bitstamp", currency="USD", body=body)])[0]["result"]
        assert result == expected, name + " parser correction"
    elif name == "nested-guard":
        from urllib.parse import quote
        hidden = "https://evil.invalid:443/"
        for _ in range(5): hidden = quote(hidden, safe="")
        bases = ["http://127.0.0.1:19431"]*9
        data = payload(bases, ["convert-amount", "1sat"])
        data["history"] += "/?next=" + hidden
        result = invoke("--price-run", data)
        assert result["status"] == 1 and not result["stdout"] and result["stderr"].startswith("testUrlRefused:"), "nested override fail closed"
    print(name + ": detecting regression passed", flush=True)


@contextmanager
def responder(root, name, body, *, status=200, delay_ms=0, tls=True):
    spec = root / (name + ".json")
    log = root / (name + ".requests")
    events = root / "events.jsonl"
    spec.write_text(json.dumps(dict(entries=[dict(method="GET", path=C.PATHS[C.SOURCES.index(name)],
        responses=[dict(status=status, text=body)], repeat=True)])))
    script = ROOT / "packages/http-curl/test/responder.py"
    # Reuse the real server's matching, HTTP framing, TLS and EOF ownership.
    program = '''import importlib.util,json,os,sys,time
spec=importlib.util.spec_from_file_location("price_responder",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
name,events,delay=sys.argv[2],sys.argv[3],int(sys.argv[4])
original=module.Handler.send_recorded
def event(kind):
    fd=os.open(events,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try: os.write(fd,(json.dumps(dict(source=name,event=kind,time_ns=time.monotonic_ns()))+"\\n").encode())
    finally: os.close(fd)
def recorded(self,response):
    event("start");time.sleep(delay/1000)
    # This measured delay interval is entirely inside the outstanding request.
    # Publish its end before sending, so client completion cannot race the log.
    event("end")
    original(self,response)
module.Handler.send_recorded=recorded
sys.argv=[sys.argv[1],*sys.argv[5:]];module.main()
'''
    args = [sys.executable, "-B", "-c", program, str(script), name, str(events), str(delay_ms),
            str(spec), "--log", str(log)]
    if tls: args += ["--tls", "--cert", str(root / "cert.pem"), "--key", str(root / "key.pem")]
    with (root / (name + ".stderr")).open("wb") as errors:
        child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        handlers = {}
        def interrupted(signum, _frame): raise SystemExit(128 + signum)
        try:
            for signum in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
                handlers[signum] = signal.signal(signum, interrupted)
            assert select.select([child.stdout], [], [], 10)[0], "price responder startup deadline"
            ready = child.stdout.readline().decode().split()
            assert len(ready) == 3 and ready[0] == "READY", "price responder READY"
            port, closed = map(int, ready[1:])
            assert all(0 < p < 65536 and p != 8332 for p in [port, closed]), "owned nondefault ports"
            yield ("https" if tls else "http") + "://127.0.0.1:" + str(port), log, closed
        finally:
            for signum in handlers: signal.signal(signum, signal.SIG_IGN)
            try:
                child.stdin.close()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
                child.stdout.close()
                assert child.returncode == 0, "price responder reaped"
            finally:
                for signum, handler in handlers.items(): signal.signal(signum, handler)


def payload(bases, args):
    return dict(feeds=bases, history=bases[0], rpc=bases[0], args=args)


def success_expected(input_text, amount, price, names, mode=None):
    n = Fraction(amount) / Fraction(price) * 10**11
    msats = (2*n.numerator+n.denominator)//(2*n.denominator)
    if mode == "msats": stdout = str(msats) + "\n"
    elif mode == "sats": stdout = str(msats//1000) + "\n"
    elif mode == "btc":
        # Bitcoin's existing printer removes insignificant fractional zeroes.
        stdout = format(Decimal(msats).scaleb(-11), "f").rstrip("0").rstrip(".") + "\n" if msats else "0\n"
    else: stdout = None
    note = f"[convert-amount] note: input has fractional satoshis ({msats} msat); --as sats floors to {msats//1000} sat\n" if mode == "sats" and msats%1000 else ""
    breadcrumb = f"[price-feed] median BTC/USD = {C.fixed(Fraction(price))} from {len(names)} feeds: {', '.join(names)}\n"
    value = dict(input=input_text, btc=Decimal(msats).scaleb(-11), sats=msats//1000, msats=msats,
                 fiat_source=dict(amount=Decimal(amount), currency="USD", price_per_btc=Decimal(price), feeds=names))
    return stdout, value, breadcrumb + note


def replay():
    assert network.sandbox() or network.isolated(), "price replay requires owned network isolation"
    parent = APP / ".lake/price-replay"
    parent.mkdir(parents=True, exist_ok=True)
    fixtures = json.loads((APP / "test/http/success.json").read_text())
    cases = 0
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        root = Path(temporary)
        home = root / "home"; home.mkdir()
        certificate = network.run_owned(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"), "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True, timeout=30)
        assert certificate.returncode == 0, "owned TLS certificate generation: " + certificate.stderr.decode()
        environment = dict(os.environ, HOME=str(home), SSL_CERT_FILE=str(root / "cert.pem"), PYTHONDONTWRITEBYTECODE="1")
        unrelated = network.run_owned(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / "unrelated-key.pem"), "-out", str(root / "unrelated-ca.pem"),
            "-days", "1", "-subj", "/CN=unrelated-test-CA"], capture_output=True, timeout=30)
        assert unrelated.returncode == 0, "unrelated valid CA generation: " + unrelated.stderr.decode()
        parsed_ca = network.run_owned(["openssl", "x509", "-in", str(root / "unrelated-ca.pem"), "-noout"], capture_output=True, timeout=10)
        assert parsed_ca.returncode == 0, "unrelated CA is a valid certificate"
        def run(bases, args, *, trust="correct"):
            nonlocal cases
            cases += 1
            ca = {"correct":"cert.pem", "unrelated":"unrelated-ca.pem", "missing":"absent-ca.pem"}[trust]
            env = dict(environment, SSL_CERT_FILE=str(root / ca))
            return invoke("--price-run", payload(bases, args), environment=env)
        def launch(stack, values, statuses=None, delays=None):
            return [stack.enter_context(responder(root, name, values[i], status=(statuses or {}).get(i, 200),
                delay_ms=(delays or {}).get(i, 0))) for i, name in enumerate(C.SOURCES)]
        with ExitStack() as stack:
            servers = launch(stack, [json.dumps(fixtures[n]) for n in C.SOURCES], delays={i:1000 for i in range(9)})
            bases = [s[0] for s in servers]
            r = run(bases, ["convert-amount", "100usd"])
            stdout, value, stderr = success_expected("100usd", "100", "95040", C.SOURCES)
            assert r["status"] == 0 and exact_json(r["stdout"]) == value and r["stderr"] == stderr, "nine-feed exact handler JSON"
            assert r["stdout"].endswith("\n"), "existing JSON newline behavior"
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            starts = [e["time_ns"] for e in events if e["event"] == "start"]
            ends = [e["time_ns"] for e in events if e["event"] == "end"]
            assert len(starts) == len(ends) == 9 and max(starts) < min(ends), "actual nine-request overlapping fanout"
            for i, server in enumerate(servers):
                records = [json.loads(line) for line in server[1].read_text().splitlines()]
                assert records == [dict(method="GET", path=C.PATHS[i], body="")], "production path and currency case"
            for trust in ["unrelated", "missing"]:
                r = run(bases, ["convert-amount", "1USD"], trust=trust)
                assert r["status"] == 1 and not r["stdout"] and "tls" in r["stderr"] and "Only 0" in r["stderr"], "TLS trust failure: " + trust
            r = run(bases, ["convert-amount", "100usd"])
            assert r["status"] == 0 and exact_json(r["stdout"]) == value and r["stderr"] == stderr, "correct CA succeeds after trust rejection"
        (root / "events.jsonl").unlink()
        with ExitStack() as stack:
            servers = launch(stack, [json.dumps(C.body(n, 95000)) for n in C.SOURCES])
            bases = [s[0] for s in servers]
            for amount in ["0.000010924999", "0.000010925", "0.000010925001", "0"]:
                for mode in [None, "btc", "sats", "msats"]:
                    args = ["convert-amount", amount + " USD"] + (["--as", mode] if mode else [])
                    r = run(bases, args)
                    stdout, value, stderr = success_expected(amount + " USD", amount, "95000", sorted(C.SOURCES), mode)
                    assert r["status"] == 0 and r["stderr"] == stderr, "fiat scalar breadcrumb/note"
                    assert (r["stdout"] == stdout) if mode else (exact_json(r["stdout"]) == value), "fiat scalar or complete JSON"
            r = run(bases, ["convert-amount", "0.00000001USD"])
            assert r["status"] == 1 and not r["stdout"] and "less than 1 msat" in r["stderr"], "handler tiny refusal"
            for mode in ["btc", "sats", "msats"]:
                before = [s[1].read_bytes() for s in servers]
                r = run(bases, ["convert-amount", "1500msat", "--as", mode])
                assert r["status"] == 0 and "[price-feed]" not in r["stderr"], "unit-only scalar"
                assert before == [s[1].read_bytes() for s in servers], "unit-only zero requests"
        for count in [4, 3, 2, 1, 0]:
            with ExitStack() as stack:
                servers = launch(stack, [json.dumps(fixtures[n]) if i < count else "{}" for i,n in enumerate(C.SOURCES)])
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                assert (r["status"] == 0) == (count >= 3), "feed quorum status"
                assert "no USD quote" in r["stderr"], "missing feed issue context"
                if count < 3:
                    word = "feed" if count == 1 else "feeds"
                    assert not r["stdout"] and f"Only {count} BTC price {word} responded" in r["stderr"], "quorum failure streams"
                else:
                    assert exact_json(r["stdout"])["fiat_source"]["feeds"] == C.SOURCES[:count], "quorum retained source list"
        with ExitStack() as stack:
            statuses = {i:404 for i in range(5,9)} | {0:500}
            servers = launch(stack, [json.dumps(fixtures[n]) for n in C.SOURCES], statuses=statuses, delays={4:9000})
            r = run([s[0] for s in servers], ["convert-amount", "1USD"])
            assert r["status"] == 0 and "timeout" in r["stderr"] and "HTTP 500" in r["stderr"], "delayed/failed feeds retain quorum and structured issues"
            assert all(n + ": no USD quote" in r["stderr"] for n in C.SOURCES[5:]), "four special 404 diagnostics"
        for maximum, warned in [("101.99",False),("102",False),("103",True)]:
            with ExitStack() as stack:
                servers = launch(stack, [json.dumps(C.body(n, ["100","101",maximum][min(i,2)])) if i < 3 else "{}" for i,n in enumerate(C.SOURCES)])
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                assert r["status"] == 0 and ("BTC price feed spread" in r["stderr"]) == warned, "strict exact spread warning boundary"
        # Each response is local and bounded by the existing transport limit.
        # Do not execute the former unbounded parser on the large probes.
        hostile = ['{"last":'+value+'}' for value in ["1e10000000000","1e1000000","1e-1000000"]]
        hostile += ['{"last":'+json.dumps(value)+'}' for value in ["1e10000000000","1e-1000000","0"*1048000+"1"]]
        hostile += ['{"last":'+"1"*1048000+'}', '{"ignored":"\\ud800","last":1}']
        assert len(hostile) == 8, "numeric/malformed replay inventory"
        for body in hostile:
            with ExitStack() as stack:
                values = [json.dumps(fixtures[n]) for n in C.SOURCES]
                values[6] = body
                servers = launch(stack, values)
                before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                names = [n for i,n in enumerate(C.SOURCES) if i != 6]
                _, value, breadcrumb = success_expected("1USD", "1", "95035", names)
                assert r["status"] == 0 and exact_json(r["stdout"]) == value, "offending feed retains exact eight-source median"
                assert r["stderr"].startswith("[price-feed] BTC price feed issues for USD: bitstamp: ") and r["stderr"].endswith(breadcrumb), "offending feed is an issue with ordered eight-source breadcrumb"
                for previous, server in zip(before, servers):
                    assert len(server[1].read_text().splitlines()) == previous + 1, "all nine requests survive hostile response"
        # Exercise complete handler values and streams at the parser boundaries.
        # A valid replacement quote sorts Bitstamp before CoinGecko at 95000;
        # an invalid body removes only Bitstamp, leaving median 95035.
        boundary_rows = [row for row in C.pure_cases() if row["id"].startswith(("bitstamp/depth-", "bitstamp/ignored-"))]
        assert len(boundary_rows) == 26, "whole-body TLS boundary inventory"
        for row in boundary_rows:
            with ExitStack() as stack:
                values = [json.dumps(fixtures[n]) for n in C.SOURCES]
                values[6] = row["body"]
                servers = launch(stack, values)
                before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                accepted = "ok" in row["expected"]
                quotes = [(Fraction(95000 if i == 6 else 95000+i*10), n)
                          for i,n in enumerate(C.SOURCES) if accepted or i != 6]
                ordered = sorted(quotes)
                names = [n for _,n in ordered]
                _, value, breadcrumb = success_expected("1USD", "1", "95030" if accepted else "95035", names)
                issue = "" if accepted else "[price-feed] BTC price feed issues for USD: bitstamp: Invalid Bitstamp JSON\n"
                assert r["status"] == 0 and exact_json(r["stdout"]) == value, row["id"]+" complete handler JSON"
                assert r["stderr"] == issue + breadcrumb, row["id"]+" complete handler stderr"
                assert r["stdout"].endswith("\n"), row["id"]+" handler newline"
                assert all(len(s[1].read_text().splitlines()) == previous + 1 for previous,s in zip(before,servers)), row["id"]+" all nine requests"
        # Structural errors, losing-candidate range checks, and both sides of
        # the retained lexical limit also traverse the guarded actual handler.
        additions = [row for row in C.pure_cases() if row["id"] in {
            "bitstamp/numeric-key-later-1", "bitstamp/key-control-quoted-markers",
            "kraken/losing-USD-overflow400", "kraken/losing-EUR-overflow309",
            "bitstamp/lexical-ignored-exponent-2048", "bitstamp/lexical-ignored-exponent-2049",
            "bitstamp/lexical-ignored-fraction-2048", "bitstamp/lexical-ignored-fraction-2049",
        }]
        assert len(additions) == 8, "new parser TLS boundary inventory"
        for row in additions:
            with ExitStack() as stack:
                slot = C.SOURCES.index(row["source"])
                values = [json.dumps(fixtures[n]) for n in C.SOURCES]
                values[slot] = row["body"]
                servers = launch(stack, values)
                before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                accepted = "ok" in row["expected"]
                quotes = sorted((Fraction(95000 if i == slot else 95000+i*10), n)
                                for i,n in enumerate(C.SOURCES) if accepted or i != slot)
                median = quotes[4][0] if accepted else (quotes[3][0]+quotes[4][0])/2
                _, value, breadcrumb = success_expected("1USD", "1", str(median), [n for _,n in quotes])
                issue = "" if accepted else "[price-feed] BTC price feed issues for USD: "+row["source"]+": "+row["expected"]["error"]+"\n"
                assert r["status"] == 0 and r["stderr"] == issue+breadcrumb, row["id"]+" complete handler status/stderr"
                assert exact_json(r["stdout"]) == value and r["stdout"].endswith("\n"), row["id"]+" complete handler JSON/newline"
                for i,server in enumerate(servers):
                    records = [json.loads(line) for line in server[1].read_text().splitlines()]
                    assert records[before[i]:] == [dict(method="GET", path=C.PATHS[i], body="")], row["id"]+" all nine requests"
        observed = [row for row in C.observed_price_cases() if row["id"] in {
            "kraken/selected-multiple-1e400", "kraken/selected-multiple-1e-400",
            "bitstamp/ordinary-coefficient-number-1024", "bitstamp/ordinary-coefficient-number-1025",
            "bitstamp/ordinary-coefficient-string-1024", "bitstamp/ordinary-coefficient-string-1025",
        }]
        assert len(observed) == 6, "selected extreme and ordinary coefficient TLS inventory"
        for row in observed:
            with ExitStack() as stack:
                slot = C.SOURCES.index(row["source"])
                values = [json.dumps(fixtures[n]) for n in C.SOURCES]
                values[slot] = row["body"]
                servers = launch(stack, values)
                before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                accepted = "ok" in row["expected"]
                selected = (Fraction("1e-400") if row["id"].endswith("1e-400") else
                            Fraction("1e400") if row["id"].endswith("1e400") else Fraction(95000))
                quotes = [dict(source=n, price=str(selected if i == slot else 95000+i*10))
                          for i,n in enumerate(C.SOURCES) if accepted or i != slot]
                aggregate = C.aggregation(quotes)["ok"]
                median = Fraction(int(aggregate["price"]["numerator"]), int(aggregate["price"]["denominator"]))
                _, value, breadcrumb = success_expected("1USD", "1", str(median), aggregate["sources"])
                issue = "" if accepted else "[price-feed] BTC price feed issues for USD: "+row["source"]+": "+row["expected"]["error"]+"\n"
                assert r["status"] == 0 and exact_json(r["stdout"]) == value, row["id"]+" complete handler JSON"
                assert r["stderr"] == aggregate["warning"]+issue+breadcrumb, row["id"]+" complete handler stderr"
                assert r["stdout"].endswith("\n"), row["id"]+" handler newline"
                for i,server in enumerate(servers):
                    records = [json.loads(line) for line in server[1].read_text().splitlines()]
                    assert records[before[i]:] == [dict(method="GET", path=C.PATHS[i], body="")], row["id"]+" all nine requests"
        # Ordinary power-bound outcomes and no matching Kraken suffix traverse
        # the same guarded handler, including their complete no-quote diagnostics.
        remaining = [row for row in C.diagnostic_price_cases() if row["id"] in {
            "diagnostic/bitstamp/power1025-coef1024", "diagnostic/bitstamp/power1024-coef1024",
            "diagnostic/kraken/nowinner-raw-1e-400", "diagnostic/kraken/nowinner-str-1e400",
        }]
        assert len(remaining) == 4, "power and alternate selection TLS inventory"
        for row in remaining:
            with ExitStack() as stack:
                slot = C.SOURCES.index(row["source"])
                values = [json.dumps(fixtures[n]) for n in C.SOURCES]
                values[slot] = row["body"]
                servers = launch(stack, values)
                before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
                r = run([s[0] for s in servers], ["convert-amount", "1USD"])
                selected = row["expected"].get("ok")
                quotes = [dict(source=n, price=str(Fraction(int(selected["numerator"]), int(selected["denominator"]))) if i == slot else str(95000+i*10))
                          for i,n in enumerate(C.SOURCES) if i != slot or selected is not None]
                aggregate = C.aggregation(quotes)["ok"]
                median = Fraction(int(aggregate["price"]["numerator"]), int(aggregate["price"]["denominator"]))
                price = str(Decimal(median.numerator)/Decimal(median.denominator))
                _, value, breadcrumb = success_expected("1USD", "1", price, aggregate["sources"])
                error = row["expected"].get("error", "no USD quote")
                issue = "" if selected is not None else "[price-feed] BTC price feed issues for USD: "+row["source"]+": "+error+"\n"
                assert r["status"] == 0 and exact_json(r["stdout"]) == value, row["id"]+" complete handler JSON"
                assert r["stderr"] == aggregate["warning"]+issue+breadcrumb, row["id"]+" complete handler stderr"
                assert r["stdout"].endswith("\n"), row["id"]+" handler newline"
                for i,server in enumerate(servers):
                    records = [json.loads(line) for line in server[1].read_text().splitlines()]
                    assert records[before[i]:] == [dict(method="GET", path=C.PATHS[i], body="")], row["id"]+" all nine requests"
        # Eight quotes have an even cent median, while the absent ninth feed
        # and wide endpoints force all three stderr components to be nonempty.
        cent_prices = ["100", "94000", "94999", "95000.00", "95000.02", "95001", "96000", "200000"]
        quotes = [dict(source=n, price=p) for n,p in zip(C.SOURCES, cent_prices)]
        aggregate = C.aggregation(quotes)["ok"]
        assert aggregate["price"] == C.ratio(Fraction(9500001,100))
        assert aggregate["sources"] == C.SOURCES[:8] and aggregate["warning"]
        with ExitStack() as stack:
            servers = launch(stack, [json.dumps(C.body(n,cent_prices[i])) if i < 8 else "{}" for i,n in enumerate(C.SOURCES)])
            before = [len(s[1].read_text().splitlines()) if s[1].exists() else 0 for s in servers]
            for index,mode in enumerate([None,"btc","sats","msats"]):
                args = ["convert-amount", "1USD"] + (["--as",mode] if mode else [])
                r = run([s[0] for s in servers], args)
                stdout, value, breadcrumb = success_expected("1USD", "1", "95000.01", aggregate["sources"], mode)
                issue = "[price-feed] BTC price feed issues for USD: gemini: no USD quote\n"
                assert r["status"] == 0, "cent median handler status"
                assert (r["stdout"] == stdout) if mode else (exact_json(r["stdout"]) == value), "cent median complete JSON/scalar"
                assert r["stderr"] == aggregate["warning"]+issue+breadcrumb, "cent median warning/issues/breadcrumb order"
                assert r["stdout"].endswith("\n"), "cent median output newline"
                for i,server in enumerate(servers):
                    records = [json.loads(line) for line in server[1].read_text().splitlines()]
                    assert records[before[i]:] == [dict(method="GET", path=C.PATHS[i], body="")]*(index+1), "cent median all nine requests"
        assert cases == 89, "price TLS replay case inventory"
        print(f"price TLS handler replay: {cases}/89; observed additions: {len(observed)}/6; remaining additions: 8/8; fanout overlaps; trust failure, 8000ms timeout, quorum and spread controls executed", flush=True)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        correction_probe(sys.argv[2]); return 0
    if sys.argv[1:] in [["--inside"], ["--inside-replay"]]:
        assert network.sandbox() or network.isolated()
        parent = APP / ".lake/price-replay"
        parent.mkdir(parents=True,exist_ok=True)
        previous = os.environ.get("HOME")
        with tempfile.TemporaryDirectory(dir=parent) as temporary, chdir(temporary):
            os.environ["HOME"] = temporary
            try:
                if sys.argv[1:] == ["--inside"]: pure()
                replay()
            finally:
                if previous is None: os.environ.pop("HOME",None)
                else: os.environ["HOME"] = previous
        return 0
    if sys.argv[1:] == ["--pure"]:
        pure(); return 0
    if sys.argv[1:] == ["--replay"]:
        return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--inside-replay"], timeout=240)
    assert not sys.argv[1:]
    return network.run_isolated([sys.executable, "-B", str(Path(__file__).resolve()), "--inside"], timeout=240)


if __name__ == "__main__": sys.exit(main())
