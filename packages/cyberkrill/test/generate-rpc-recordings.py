#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Manual capture from an owned, loopback-only disposable regtest node."""
import argparse
import base64
from decimal import Decimal
import hashlib
import hmac
import http.client
import http.server
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "packages/http-curl/test"))
from responder import parse_json, json_text, canonical

REV = "27cad1faba86260b06665a89f0af5134d23525c2"
NIXPKGS = "fe13242281a67641c0102cdb1087f0ebe586c7df"
AUTH = "Basic " + base64.b64encode(b"lck:lck-throwaway").decode()
COOKIE = b"lck:lck-throwaway"
SALT = "a7c8be307154908bd62f3c4a1908de56"
RPCAUTH = "lck:" + SALT + "$" + hmac.new(SALT.encode(), b"lck-throwaway", hashlib.sha256).hexdigest()
SOURCE_LINES = dict(listunspent=496, scantxoutset=534, getblockchaininfo=725,
                    getdescriptorinfo=741, importdescriptors=764, deriveaddresses=835,
                    createpsbt=955, getreceivedbyaddress=1172,
                    walletcreatefundedpsbt=1260, getrawtransaction=1310, getblock=204)
SOURCE_HASHES = {
    "cyberkrill-core/src/bitcoin_rpc.rs": "84e58ce11c94bc70e3c20469a95b8e87c7a1d8d695dcd23d647da5a5db723987",
    "cyberkrill-core/src/frozenkrill.rs": "9ee016c97bd32bc74852c5507a175acb0ff46aeff19a97f384d783065717a9b3",
    "cyberkrill-core/src/dca_report.rs": "d9f4a6fc45f8f492da98595ba5c08c3ea1d446fcb1c5c3db21f1976c60a005fc",
    "cyberkrill/src/main.rs": "184feb3b1de3af7f961ba4f936d2d2137d199686fa4a59079377fbb9cd2ce9ed",
}
SHARED = ["shared/provenance.json", "shared/descriptors.json",
          "shared/frozenkrill-single.json", "shared/frozenkrill-multisig.json", "bitcoin-dir/.cookie"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def definition_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def encoded(value):
    return (json_text(value) + "\n").encode("utf-8")


def selector(value):
    # Match the responder's parsed exact JSON boundary, including bool tags.
    return canonical(parse_json(json_text(value)))


def sats(text):
    import re
    assert re.fullmatch(r"[0-9]+sat", text), "explicit integer satoshi units"
    return int(text[:-3])


def option(row, flag):
    return row["args"][row["args"].index(flag) + 1]


def inventory(path=HERE / "rpc-recording-cases.json"):
    import re
    rows = json.loads(path.read_bytes())
    assert isinstance(rows, list) and rows, "case inventory"
    names = set()
    for row in rows:
        name = row["name"]
        assert re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name), "safe case name"
        assert name not in {"shared", "bitcoin-dir"} | names, "reserved/duplicate case name"
        assert row["recording"] == name + ".json", "case-local recording path"
        assert row["fixture"] in ["single", "multisig"], "declared public fixture"
        assert row["command"] in {"onchain-list-utxos", "onchain-create-psbt",
                                   "onchain-create-funded-psbt", "onchain-move-utxos", "onchain-dca-report"}
        assert all(isinstance(a, str) for a in row["args"]), "case args"
        assert len(row["funding"]) == 4 and all(sats(v) > 0 for v in row["funding"]), "funding units"
        assert len(row["dates"]) == 2 and row["dates"][0] < row["dates"][1], "ordered funding dates"
        for date in row["dates"]: datetime.strptime(date, "%Y-%m-%d")
        names.add(name)
    return rows


def run(args, *, data=None, cwd=None, env=None, timeout=30):
    return subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None,
                          capture_output=True, cwd=cwd, env=env, timeout=timeout, check=True)


def guards(args):
    # Identity is resolved before HOME replacement or namespace entry. No owner-tree IO.
    user = run(["id", "-un"]).stdout.decode().strip()
    passwd = run(["getent", "passwd", user]).stdout.decode().strip().split(":")
    assert len(passwd) == 7 and passwd[5].startswith("/"), "real passwd home"
    home = run(["realpath", "-m", passwd[5] + "/.bitcoin"]).stdout.decode().strip()
    temp = os.environ.get("TMPDIR")
    assert temp and os.path.isabs(temp), "explicit absolute TMPDIR required"
    temp = run(["realpath", "-m", temp]).stdout.decode().strip()
    assert temp != home and not temp.startswith(home + "/"), "refused real-home bitcoin TMPDIR"
    if args.datadir:
        candidate = run(["realpath", "-m", args.datadir]).stdout.decode().strip()
        assert candidate != home and not candidate.startswith(home + "/"), "refused real-home bitcoin datadir"
        assert not os.path.lexists(candidate), "datadir must be fresh"
    else:
        candidate = None
    assert args.network == "regtest", "refused non-regtest network"
    assert args.rpc_host == "127.0.0.1", "refused non-loopback RPC host"
    for port in [args.rpcport, args.port, args.proxyport]:
        assert port is None or (1024 <= port <= 65535 and port not in [8332, 8333, 18332, 18333, 18443, 18444, 38332, 38333]), "refused unsafe/default port"
    explicit = [p for p in [args.rpcport, args.port, args.proxyport] if p is not None]
    assert len(explicit) == len(set(explicit)), "ports must differ"
    return candidate


def address(pubkey):
    # BIP173 witness-v0 encoding of the derived HASH160 (no private serialization).
    program = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    bits = ''.join(f'{b:08b}' for b in program)
    bits += '0' * ((-len(bits)) % 5)
    values = [0] + [int(bits[i:i+5], 2) for i in range(0, len(bits), 5)]
    hrp = "bcrt"
    checksum = 1
    for value in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values + [0]*6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if top >> i & 1: checksum ^= generator
    checksum ^= 1
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + ''.join(alphabet[v] for v in values + [(checksum >> (5*(5-i))) & 31 for i in range(6)])


def public_inputs():
    from mnemonic import Mnemonic
    from bip32 import BIP32
    import base58
    versions = {p: importlib.metadata.version(p) for p in ["mnemonic", "bip32", "coincurve", "base58"]}
    assert versions == dict(mnemonic="0.21", bip32="5.0.0", coincurve="21.0.0", base58="2.1.1"), "derivation tool versions"
    assert importlib.util.find_spec("bip_utils") is None and importlib.util.find_spec("ecdsa") is None, "clean derivation closure"
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert Mnemonic("english").check(phrase), "published mnemonic checksum"
    master = BIP32.from_seed(Mnemonic.to_seed(phrase), network="test")
    fingerprint = hashlib.new("ripemd160", hashlib.sha256(master.get_pubkey_from_path("m")).digest()).digest()[:4].hex()
    paths = ["m/84'/1'/0'", "m/48'/1'/0'/2'", "m/48'/1'/1'/2'", "m/48'/1'/2'/2'"]
    keys = [master.get_xpub_from_path(p) for p in paths]
    for key in keys:
        assert base58.b58decode_check(key)[:4] == bytes.fromhex("043587cf"), "derived public test version"
        assert BIP32.from_xpub(key).get_xpub_from_path("m") == key, "public-only root"
    origins = [f"[{fingerprint}/{p[2:]}]{k}" for p, k in zip(paths, keys)]
    single = f"wpkh({origins[0]}/<0;1>/*)"
    multi = "wsh(sortedmulti(2," + ','.join(o + "/<0;1>/*" for o in origins[1:]) + "))"
    common = dict(wallet="frozenkrill", version=0, script_type="segwit-native", network="regtest")
    singlesig = dict(common, sigtype="singlesig", master_fingerprint=fingerprint,
        singlesig_xpub=keys[0], singlesig_derivation_path=paths[0][2:],
        multisig_xpub=keys[1], multisig_derivation_path=paths[1][2:],
        singlesig_receiving_output_descriptor=single.replace("<0;1>", "0"),
        singlesig_change_output_descriptor=single.replace("<0;1>", "1"),
        multisig_receiving_output_descriptor_key=origins[1] + "/0/*",
        multisig_change_output_descriptor_key=origins[1] + "/1/*",
        receiving_addresses=[dict(address=address(BIP32.from_xpub(keys[0]).get_pubkey_from_path("m/0/0")), derivation_path=paths[0][2:] + "/0/0")],
        change_addresses=[dict(address=address(BIP32.from_xpub(keys[0]).get_pubkey_from_path("m/1/0")), derivation_path=paths[0][2:] + "/1/0")])
    multisig = dict(common, sigtype="2-of-3", receiving_output_descriptor=multi.replace("<0;1>", "0"),
                    change_output_descriptor=multi.replace("<0;1>", "1"), receiving_addresses=[], change_addresses=[])
    provenance = dict(
        sources=[dict(url="https://github.com/douglaz/cyberkrill", revision=REV,
                      paths=["cyberkrill-core/src/bitcoin_rpc.rs", "cyberkrill-core/src/frozenkrill.rs", "cyberkrill-core/src/dca_report.rs", "cyberkrill/src/main.rs"],
                      licence="MIT", declaration="cyberkrill-core/Cargo.toml and cyberkrill/Cargo.toml", changes="Generated public fixtures and captured RPC requests/replies; framing and host metadata removed"),
                 dict(url="https://github.com/planktonlabs/frozenkrill", revision="c6883ec2daf9886f96106815528b7052eecaf5b4",
                      paths=["frozenkrill-core/src/wallet_export.rs:25-55", "frozenkrill-core/src/wallet_description.rs:128-133"], licence="MIT", changes="Reader shape used, no source copied"),
                 dict(url="https://github.com/bitcoin/bips", revision="927b6de9915c9262615a6399de51b200f81e5aa4", paths=["bip-0032.mediawiki", "bip-0039.mediawiki", "bip-0084.mediawiki"], changes="Published mnemonic used for runtime public derivation; no private vector bytes copied")],
        nixpkgs=NIXPKGS, core=dict(version="31.1", runtime="31.1.0", licence="MIT", url="https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1.tar.gz", sha256="50411d5b43c7e4c90099394759eb6c2add6e7c2dbe728840893d638b6fc6afc9"),
        derivation=dict(versions=versions, mnemonic=dict(url="https://github.com/trezor/python-mnemonic", tag="v0.21", licence="MIT", nar_hash="sha256-D1mS/JQhefYmwrShfWR9SdiGsBUM+jmuCkfWix9tDOU="),
                        bip32=dict(url="https://github.com/darosior/python-bip32", tag="5.0", licence="BSD-3-Clause", nar_hash="sha256-QO1gS9bx/eQPaLuB1ZNZuXj4DmeO4/La2hG9NCXjd+4="),
                        proof=dict(bip39_vectors=240, languages=10, bip32_paths=17, invalid_keys=16, bip84_public_vectors=3, public_child_checks=3, kind="Prior offline published-vector prerequisite proof; generation checks fresh public versions only")),
        auth=dict(purpose="Disposable regtest test auth, not a secret", rpcauth=RPCAUTH, authorization=AUTH),
        schema=1)
    descriptors = dict(single=single, multisig=multi, paths=paths, tpubs=keys, fingerprint=fingerprint)
    return {"shared/provenance.json": encoded(provenance), "shared/descriptors.json": encoded(descriptors),
            "shared/frozenkrill-single.json": encoded(singlesig), "shared/frozenkrill-multisig.json": encoded(multisig), "bitcoin-dir/.cookie": COOKIE}


def free_ports(explicit):
    sockets = []
    try:
        ports = []
        for port in explicit:
            sock = socket.socket()
            sock.bind(("127.0.0.1", port or 0))
            sockets.append(sock)
            value = sock.getsockname()[1]
            assert value not in [8332, 8333, 18332, 18333, 18443, 18444, 38332, 38333], "allocated default port"
            ports.append(value)
        return ports
    finally:
        for sock in sockets: sock.close()


def response(status, headers, body):
    # Deterministic transport-only normalization; every JSON field is retained.
    headers = {k.lower(): v for k, v in headers if k.lower() not in
               {"content-length", "transfer-encoding", "connection", "date", "server"}}
    return dict(status=status, headers=headers, text=body.decode("utf-8"))


class Capture:
    def __init__(self, port):
        self.port = port
        self.calls = []

    def call(self, method, params, wallet, authorized=True):
        payload = json_text(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
        command = ["curl", "--disable", "--silent", "--show-error", "--noproxy", "*", "--max-time", "30",
                   "--dump-header", "-", "--header", "Content-Type: application/json", "--data-binary", "@-"]
        if authorized: command += ["--header", "Authorization: " + AUTH]
        command += [f"http://127.0.0.1:{self.port}/wallet/{wallet}"]
        raw = run(command, data=payload, timeout=35).stdout
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        return response(int(lines[0].split()[1]), [line.split(": ", 1) for line in lines[1:]], body)

    def record(self, method, params, wallet):
        reply = self.call(method, params, wallet)
        self.calls.append((method, params, wallet, reply))
        body = parse_json(reply["text"])
        assert reply["status"] == 200, "RPC HTTP status"
        return body.get("result")

    def entries(self):
        entries = {}
        for method, params, wallet, reply in self.calls:
            key = (method, wallet, selector(params))
            if key not in entries:
                unauthorized = self.call(method, params, wallet, authorized=False)
                assert unauthorized["status"] == 401, "real unauthorized response"
                source = "cyberkrill-core/src/" + ("dca_report.rs" if method == "getblock" else "bitcoin_rpc.rs")
                entries[key] = dict(method="POST", path="/wallet/" + wallet,
                    rpc=dict(method=method, params=[params]), authorization=AUTH,
                    unauthorized=unauthorized, responses=[], source=f"{source}:{SOURCE_LINES[method]}")
            entries[key]["responses"].append(reply)
        return list(entries.values())


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = parse_json(body)
        assert request["method"] in SOURCE_LINES, "reference v1 method"
        assert self.path in ["/wallet/single", "/wallet/multisig"], "explicit wallet endpoint"
        assert self.headers["Authorization"] == AUTH, "reference test auth"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.capture.port, timeout=30)
        try:
            connection.request("POST", self.path, body, {"Content-Type": "application/json", "Authorization": AUTH})
            reply = connection.getresponse()
            data = reply.read()
            recorded = response(reply.status, reply.getheaders(), data)
        finally: connection.close()
        self.server.capture.calls.append((request["method"], request["params"], self.path.split('/')[-1], recorded))
        self.send_response(recorded["status"])
        for name, value in recorded["headers"].items(): self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def fallback(capture, row, descriptors, addresses, outpoints):
    wallet = row["fixture"]
    desc = descriptors[wallet]
    def rpc(method, params): return capture.record(method, params, wallet)
    if row["kind"] in ["list", "create", "funded", "overshoot"]:
        # list_unspent_for_descriptor, bitcoin_rpc.rs:735-841. Import errors are retained.
        imports = [desc.replace("<0;1>", str(b)) for b in [0, 1]] if "--wallet-file" in row["args"] else [desc]
        for original in imports:
            checked = rpc("getdescriptorinfo", [original])["descriptor"]
            rpc("importdescriptors", [[dict(desc=checked, timestamp="now", range=[0, 1000], watchonly=True, label="cyberkrill_import")]])
            branches = [original.replace("<0;1>", str(b)) for b in [0, 1]] if "<0;1>" in original else [original]
            for expanded in branches:
                checked = rpc("getdescriptorinfo", [expanded])["descriptor"]
                addrs = rpc("deriveaddresses", [checked, [0, 99]])
                rpc("listunspent", [0, 9999999, addrs])
    selected = outpoints if "{descriptor}" in row["args"] else [outpoints[["{first}", "{second}", "{third}"].index(a)] for a in row["args"] if a in ["{first}", "{second}", "{third}"]]
    inputs = [dict(txid=p["txid"], vout=p["vout"]) for p in selected]
    destination = addresses["single"][0][5]
    output = sats(option(row, "--outputs").split(':')[-1]) if "--outputs" in row["args"] else None
    if row["kind"] == "create": rpc("createpsbt", [inputs, {destination: output / 1e8}, 0, False])
    if row["kind"] == "funded":
        for index in [0, 1]:
            checked = rpc("getdescriptorinfo", [desc.replace("<0;1>", "1").replace('*', str(index))])["descriptor"]
            addr = rpc("deriveaddresses", [checked])[0]
            used = rpc("getreceivedbyaddress", [addr, 0])
            if used == 0: break
        rpc("walletcreatefundedpsbt", [inputs, {destination: output / 1e8}, 0, dict(changeAddress=addr, fee_rate=float(sats(option(row, "--fee-rate"))))])
    if row["kind"] in ["overshoot", "move-f64", "move-success"]:
        chosen = selected
        for p in chosen: rpc("getrawtransaction", [p["txid"], True])
        total = 0.0
        if "--max-amount" in row["args"]:
            cap = sats(option(row, "--max-amount")) / 1e8
            chosen = []
            for p in sorted(selected, key=lambda p: p["sats"], reverse=True):
                if total >= cap: break
                chosen.append(p); total += p["sats"] / 1e8
            total = min(total, cap)
        else: total = sum(p["sats"] / 1e8 for p in chosen)
        fee = sats(option(row, "--fee"))
        floating = total - fee / 1e8
        rpc("createpsbt", [[dict(txid=p["txid"], vout=p["vout"]) for p in chosen], {destination: Decimal(repr(floating))}, 0, False])


def capture_case(job):
    root = Path(job["datadir"])
    # Worker is private to the fresh namespace; no network or owner defaults are reachable.
    assert os.readlink("/proc/self/ns/net") != job["outer_net"], "new network namespace"
    links = run(["ip", "-j", "link"]).stdout
    assert [r["ifname"] for r in json.loads(links)] == ["lo"], "loopback only"
    assert root.is_dir() and (root / "owned").read_text() == job["token"], "owned fresh datadir"
    os.environ["HOME"] = str(root)
    os.chdir(root)
    os.environ.update(PYTHONDONTWRITEBYTECODE="1")
    for key in list(os.environ):
        if key.lower().endswith("_proxy") or key in ["BITCOIN_ARGS", "BITCOIN_DATADIR"]: os.environ.pop(key)
    (root / "bitcoin.conf").write_text("")
    ports = job["ports"]
    common = ["-regtest", f"-datadir={root}", f"-conf={root / 'bitcoin.conf'}", f"-rpcport={ports[0]}"]
    cli_base = ["bitcoin-cli", *common, "-rpcconnect=127.0.0.1", "-rpcuser=lck", "-rpcpassword=lck-throwaway", "-rpcclienttimeout=30"]
    def cli(method, params=None, wallet=None):
        args = cli_base + (["-rpcwallet=" + wallet] if wallet else []) + [method]
        args += [json_text(p) if not isinstance(p, str) else p for p in (params or [])]
        output = run(args, timeout=45).stdout.decode().strip()
        try: return parse_json(output)
        except ValueError: return output
    node_log = open(root / "node.log", "wb")
    node = None
    server = None
    thread = None
    def cancelled(signum, _frame): raise InterruptedError(f"terminated by signal {signum}")
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]: signal.signal(sig, cancelled)
    try:
        for binary, extra in [("bitcoind", [f"-port={ports[1]}"]), ("bitcoin-cli", cli_base[len(common)+1:])]:
            assert "v31.1.0" in run([binary, *common, *extra, "-version"], cwd=root).stdout.decode(), "isolated Core version pin"
        node = subprocess.Popen(["bitcoind", *common, f"-port={ports[1]}", "-daemon=0", "-txindex=1", "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-onion=0", "-listenonion=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcauth=" + RPCAUTH, "-printtoconsole=1"], stdin=subprocess.DEVNULL, stdout=node_log, stderr=node_log)
        print(f"owned node pid={node.pid}", file=sys.stderr, flush=True)
        deadline = time.monotonic() + 45
        while True:
            assert node.poll() is None, "regtest node exited during startup"
            try: info = cli("getblockchaininfo"); break
            except subprocess.CalledProcessError as error:
                assert time.monotonic() < deadline, "regtest startup timeout"
                assert b"Could not connect" in error.stderr or b"Loading" in error.stderr or b"Verifying" in error.stderr, "regtest startup RPC failure"
                time.sleep(0.1)
        assert info["chain"] == "regtest", "chain must be regtest"
        if job.get("fail_after_start"): raise RuntimeError("controlled failure after chain check")
        if job.get("wait_after_start"):
            print("termination checkpoint", file=sys.stderr, flush=True)
            signal.pause()
        descriptors = json.loads(job["shared"]["shared/descriptors.json"])
        for name in SHARED:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(job["shared"][name])
        row = job["cases"][0]
        mocktimes = [int(datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()) for d in row["dates"]]
        cli("setmocktime", [mocktimes[0]])
        cli("createwallet", ["miner", False, False])
        miner = cli("getnewaddress", wallet="miner")
        cli("generatetoaddress", [101, miner], wallet="miner")
        addresses = {}
        for wallet in ["single", "multisig"]:
            cli("createwallet", [wallet, True, True])
            addresses[wallet] = []
            for branch in [0, 1]:
                descriptor = cli("getdescriptorinfo", [descriptors[wallet].replace("<0;1>", str(branch))])["descriptor"]
                imported = cli("importdescriptors", [[dict(desc=descriptor, timestamp="now", active=True, internal=bool(branch), range=[0, 1000])]], wallet)
                assert imported[0]["success"], "public watch-only import"
                addresses[wallet].append(cli("deriveaddresses", [descriptor, [0, 99]]))
            wallet_info = cli("getwalletinfo", wallet=wallet)
            assert wallet_info["private_keys_enabled"] is False, "watch-only private keys disabled"
        singlesig = json.loads(job["shared"]["shared/frozenkrill-single.json"])
        assert singlesig["receiving_addresses"][0]["address"] == addresses["single"][0][0], "independent Core public address"
        funding = {w: [] for w in addresses}
        for index, amount in enumerate(map(sats, row["funding"])):
            for wallet in addresses:
                addr = addresses[wallet][0][index] if index < 3 else addresses[wallet][1][0]
                txid = cli("sendtoaddress", [addr, Decimal(amount) / Decimal(100000000)], "miner")
                funding[wallet].append(dict(txid=txid, sats=amount, address=addr))
            if index == 1: cli("generatetoaddress", [1, miner], "miner"); cli("setmocktime", [mocktimes[1]])
        cli("generatetoaddress", [1, miner], "miner")
        deadline = time.monotonic() + 30
        while not cli("getindexinfo")["txindex"]["synced"]:
            assert time.monotonic() < deadline, "txindex readiness"
            time.sleep(0.1)
        for wallet in funding:
            for outpoint in funding[wallet]:
                tx = cli("getrawtransaction", [outpoint["txid"], True])
                outpoint["vout"] = next(v["n"] for v in tx["vout"] if v["scriptPubKey"].get("address") == outpoint["address"])
        capture = Capture(ports[0])
        server = http.server.HTTPServer(("127.0.0.1", ports[2]), Proxy)
        server.capture = capture
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        captures = {}
        producer = job.get("producer")
        attempts = job.get("attempts", [])
        for row in job["cases"]:
            capture.calls = []
            wallet = row["fixture"]
            substitutions = {"descriptor": descriptors[wallet], "destination": addresses["single"][0][5],
                "wallet": str(root / ("shared/frozenkrill-" + wallet + ".json")),
                "first": f"{funding[wallet][0]['txid']}:{funding[wallet][0]['vout']}",
                "second": f"{funding[wallet][1]['txid']}:{funding[wallet][1]['vout']}",
                "third": f"{funding[wallet][2]['txid']}:{funding[wallet][2]['vout']}"}
            result = None
            if row["kind"] != "dca" and producer != "source-client":
                for attempt in range(2 if producer is None else 1):
                    capture.calls = []
                    args = [a.format(**substitutions) for a in row["args"]]
                    try:
                        proc = subprocess.run([job["reference"], row["command"], *args,
                            "--network", "regtest", "--rpc-url", f"http://127.0.0.1:{ports[2]}/wallet/{wallet}",
                            "--rpc-user", "lck", "--rpc-password", "lck-throwaway"], stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
                        result = dict(status=proc.returncode, stdout=proc.stdout.decode().replace(str(root), "$TMP_ROOT"), stderr=proc.stderr.decode().replace(str(root), "$TMP_ROOT"))
                    except subprocess.TimeoutExpired as error:
                        result = dict(status=124, stdout=(error.stdout or b"").decode().replace(str(root), "$TMP_ROOT"), stderr=(error.stderr or b"").decode().replace(str(root), "$TMP_ROOT"))
                    if producer is None: attempts.append(result)
                    if capture.calls and result["status"] != 124:
                        producer = "reference-proxy"
                        break
                if producer is None:
                    assert producer is None, "reference stopped producing after first case"
                    producer = "source-client"
                    capture.calls = []
            if row["kind"] != "dca" and producer == "source-client":
                fallback(capture, row, descriptors, addresses, funding[wallet])
            if row["kind"] == "dca":
                capture.record("getblockchaininfo", [], wallet)
                for branch in [0, 1]:
                    scan = capture.record("scantxoutset", ["start", [dict(desc=descriptors[wallet].replace("<0;1>", str(branch)), range=[0, 200])]], wallet)
                    for utxo in scan["unspents"]:
                        tx = capture.record("getrawtransaction", [utxo["txid"], True], wallet)
                        capture.record("getblock", [tx["blockhash"]], wallet)
            # Independent integer-satoshi variants use real Core calls, never fabricated responses.
            numeric = []
            for method, params, target, reply in list(capture.calls):
                if method not in ["createpsbt", "walletcreatefundedpsbt"]: continue
                exact = parse_json(json_text(params))
                if row["kind"] == "move-f64":
                    amount = sum(p["sats"] for p in funding[wallet][:3]) - sats(option(row, "--fee"))
                    exact[1] = {addresses["single"][0][5]: Decimal(amount) / Decimal(100000000)}
                    capture.record(method, exact, target)
                    numeric.append(dict(reference=params[1], exact=exact[1], integer_sats=amount))
                elif row["kind"] in ["create", "funded"]:
                    exact[1] = {addresses["single"][0][5]: Decimal(sats(option(row, "--outputs").split(':')[-1])) / Decimal(100000000)}
                    if selector(exact) != selector(params): capture.record(method, exact, target)
            entries = capture.entries()
            assert entries, "nonempty capture"
            captures[row["name"]] = dict(schema=1, case=row["name"],
                binding=dict(definition=digest(definition_bytes(row)), files={name: digest(text.encode()) for name, text in job["shared"].items()}),
                capture=dict(producer="source-client" if row["kind"] == "dca" else producer, source_revision=REV, nixpkgs=NIXPKGS,
                    core="31.1.0", tools=job["tools"], generator_sha256=job["generator_sha256"], reference_sha256=job["reference_sha256"],
                    source_sha256=job["source_sha256"], reference_result=result, first_case_attempts=attempts,
                    funding=funding[wallet], numeric=numeric, wallet_private_keys_enabled=False,
                    entries_sha256=digest(encoded(entries))), entries=entries)
            print(f"captured {row['name']}: {len(entries)} entries", file=sys.stderr, flush=True)
        return captures
    finally:
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]: signal.signal(sig, signal.SIG_IGN)
        if server:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive(), "proxy stopped"
        if node:
            if node.poll() is None:
                node.terminate()
                try: node.wait(timeout=15)
                except subprocess.TimeoutExpired: node.kill(); node.wait(timeout=5)
            assert node.poll() is not None, "node reaped"
            print(f"reaped node pid={node.pid} status={node.returncode}", file=sys.stderr, flush=True)
        node_log.close()


def inside(job):
    captures = {}
    producer = None
    attempts = []
    for row in job["cases"]:
        root = Path(job["datadir"]) / row["name"]
        root.mkdir(mode=0o700)
        (root / "owned").write_text(job["token"])
        result = capture_case({**job, "datadir": str(root), "cases": [row], "producer": producer, "attempts": attempts})
        captures.update(result)
        if row["kind"] != "dca":
            producer = result[row["name"]]["capture"]["producer"]
            attempts = result[row["name"]]["capture"]["first_case_attempts"]
    return captures


def main():
    if sys.argv[1:] == ["--inside"]:
        print(json_text(inside(json.load(sys.stdin))))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--datadir")
    parser.add_argument("--rpcport", type=int)
    parser.add_argument("--port", type=int)
    parser.add_argument("--proxyport", type=int)
    parser.add_argument("--network", default="regtest")
    parser.add_argument("--rpc-host", default="127.0.0.1")
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--reference-source", type=Path)
    parser.add_argument("--fail-after-start", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--wait-after-start", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    candidate = guards(args)
    rows = inventory()
    if args.cases:
        assert len(set(args.cases)) == len(args.cases) and set(args.cases) <= {r["name"] for r in rows}, "declared selected cases"
        rows = [r for r in rows if r["name"] in args.cases]
    shared = public_inputs()
    destination = HERE / "recordings"
    if args.cases:
        for name, data in shared.items():
            assert (destination / name).is_file() and (destination / name).read_bytes() == data, "selected shared drift: " + name
    assert args.reference and args.reference_source, "explicit pinned reference executable and immutable source required"
    source_files = ["cyberkrill-core/src/bitcoin_rpc.rs", "cyberkrill-core/src/frozenkrill.rs", "cyberkrill-core/src/dca_report.rs", "cyberkrill/src/main.rs"]
    assert {p: digest((args.reference_source / p).read_bytes()) for p in source_files} == SOURCE_HASHES, "pinned reference source bytes"
    ports = free_ports([args.rpcport, args.port, args.proxyport])
    root = Path(candidate) if candidate else Path(tempfile.mkdtemp(prefix="rpc-recording-", dir=os.environ["TMPDIR"]))
    if candidate: root.mkdir(mode=0o700)
    token = os.urandom(24).hex()
    worker = None
    old_signals = {}
    interrupted = False
    def cancelled(signum, _frame):
        nonlocal interrupted
        if interrupted: return
        interrupted = True
        if worker and worker.poll() is None: worker.send_signal(signum)
        raise InterruptedError(f"terminated by signal {signum}")
    try:
        (root / "owned").write_text(token)
        print("owned datadir=" + str(root), file=sys.stderr, flush=True)
        job = dict(datadir=str(root), outer_net=os.readlink("/proc/self/ns/net"), token=token, ports=ports,
                   cases=rows, shared={k: v.decode() for k, v in shared.items()}, reference=str(args.reference.resolve()),
                   reference_sha256=digest(args.reference.read_bytes()), source_sha256={p: digest((args.reference_source / p).read_bytes()) for p in source_files},
                   generator_sha256=digest(Path(__file__).read_bytes()), tools={p: importlib.metadata.version(p) for p in ["mnemonic", "bip32", "coincurve", "base58"]},
                   fail_after_start=args.fail_after_start, wait_after_start=args.wait_after_start)
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]: old_signals[sig] = signal.signal(sig, cancelled)
        worker = subprocess.Popen(["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$@"', "capture", sys.executable, "-B", str(Path(__file__).resolve()), "--inside"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
        print(f"owned worker pid={worker.pid}", file=sys.stderr, flush=True)
        output, _ = worker.communicate(json.dumps(job).encode(), timeout=600)
        assert worker.returncode == 0, "isolated capture failed"
        captures = parse_json(output)
        checker = importlib.import_module("rpc-recordings")
        # Stage in memory. Validate all selected outputs before touching publication files.
        blobs = {name + ".json": encoded(captures[name]) for name in captures}
        checker.validate_bundle(rows, blobs, shared)
        safety = importlib.import_module("rpc-recording-safety")
        for name, data in {**shared, **blobs}.items(): safety.portable(name, data)
        publication = blobs if args.cases else {**shared, **blobs}
        staged = []
        try:
            for name, data in publication.items():
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
                with os.fdopen(fd, "wb") as target: target.write(data); target.flush(); os.fsync(target.fileno())
                staged.append((Path(temporary), path))
            for temporary, path in staged: os.replace(temporary, path)
        finally:
            for temporary, _ in staged:
                if temporary.exists(): temporary.unlink()
        print(f"published {len(blobs)} case recordings")
    finally:
        for sig in old_signals: signal.signal(sig, signal.SIG_IGN)
        if worker and worker.poll() is None:
            if not interrupted: worker.terminate()
            try: worker.wait(timeout=25)
            except subprocess.TimeoutExpired: worker.kill(); worker.wait(timeout=5)
        if worker: print(f"reaped worker pid={worker.pid} status={worker.returncode}", file=sys.stderr, flush=True)
        shutil.rmtree(root)
        assert not root.exists(), "owned datadir removed"
        print("removed owned datadir=" + str(root), file=sys.stderr, flush=True)
        for sig, handler in old_signals.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    main()
