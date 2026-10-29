#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Independent BIP370 field-to-JSON oracle; never invokes the app adapter."""
import base64
from decimal import Decimal
import hashlib
import importlib
import json

INPUTS = importlib.import_module("offline-inputs")


def exact_text(value):
    if isinstance(value, Decimal): return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k)+":"+exact_text(v) for k,v in value.items()) + "}"
    if isinstance(value, list): return "["+",".join(exact_text(v) for v in value)+"]"
    return json.dumps(value, ensure_ascii=True)


def address(script, network):
    if script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac" and len(script) == 25:
        payload = bytes([0 if network == "bitcoin" else 111]) + script[3:-2]
    elif script[:2] == b"\xa9\x14" and script[-1:] == b"\x87" and len(script) == 23:
        payload = bytes([5 if network == "bitcoin" else 196]) + script[2:-1]
    else:
        if len(script) not in [22,34] or script[1] != len(script)-2: return None
        if script[0] == 0: version = 0
        elif script[0] == 81 and len(script) == 34: version = 1
        else: return None
        hrp = {"bitcoin":"bc","testnet":"tb","signet":"tb","regtest":"bcrt"}[network]
        return INPUTS.INV.wrap(ds=[version]+INPUTS.INV.symbols(script[2:]), hrp=hrp,
                               variant=1 if version == 0 else 0x2bc830a3)
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw,"big")
    out = ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, digit = divmod(number,58); out = alphabet[digit]+out
    return "1"*(len(raw)-len(raw.lstrip(b"\0")))+out


class Reader:
    def __init__(self, raw): self.raw, self.pos = raw, 0
    def take(self,n):
        data = self.raw[self.pos:self.pos+n]; self.pos += n
        assert len(data) == n
        return data
    def integer(self,n): return int.from_bytes(self.take(n),"little")
    def compact(self):
        tag = self.integer(1)
        return tag if tag < 253 else self.integer({253:2,254:4,255:8}[tag])
    def vector(self): return self.take(self.compact())


def transaction(raw):
    reader = Reader(raw)
    version = int.from_bytes(reader.take(4),"little",signed=True)
    n = reader.compact()
    witness = n == 0 and reader.raw[reader.pos:reader.pos+1] == b"\x01"
    if witness: reader.take(1); n = reader.compact()
    inputs=[]
    for index in range(n):
        txid = reader.take(32)[::-1].hex(); vout = reader.integer(4)
        reader.vector()
        inputs.append(dict(index=index,txid=txid,vout=vout,sequence=reader.integer(4)))
    outputs=[]
    for index in range(reader.compact()):
        value = reader.integer(8); script = reader.vector()
        outputs.append((value,script))
    if witness:
        for _ in inputs:
            for _ in range(reader.compact()): reader.vector()
    locktime = reader.integer(4)
    assert reader.pos == len(raw)
    return version,inputs,outputs,locktime


def expected(row):
    groups = INPUTS.WIRE.maps(base64.b64decode(row["args"][1],validate=True))
    global_map = dict(groups[0])
    assert int.from_bytes(global_map[b"\xfb"],"little") == 2
    def number(group,key,default=None):
        data = group.get(bytes([key]))
        return default if data is None else int.from_bytes(data,"little")
    count_in = Reader(global_map[b"\x04"]).compact()
    count_out = Reader(global_map[b"\x05"]).compact()
    assert len(groups) == 1+count_in+count_out
    input_maps = [dict(g) for g in groups[1:1+count_in]]
    constrained = [g for g in input_maps if b"\x11" in g or b"\x12" in g]
    if not constrained: locktime = number(global_map,3,0)
    elif all(b"\x12" in g for g in constrained): locktime = max(number(g,18) for g in constrained)
    elif all(b"\x11" in g for g in constrained): locktime = max(number(g,17) for g in constrained)
    else: locktime = None
    if "locktime" in row: assert row["locktime"] == locktime, "independent locktime vs published pin"
    if locktime is None: return None
    version = int.from_bytes(global_map[b"\x02"],"little",signed=True)
    net = "bitcoin"
    inputs=[]; all_values=True; total_in=0
    for index,g in enumerate(input_maps):
        vout=number(g,15)
        result=dict(index=index,txid=g[b"\x0e"][::-1].hex(),vout=vout,sequence=number(g,16,2**32-1))
        value=None
        if b"\x01" in g: value = int.from_bytes(g[b"\x01"][:8],"little")
        elif b"\x00" in g:
            outs=transaction(g[b"\x00"])[2]
            if vout < len(outs): value=outs[vout][0]
        if value is None: all_values=False
        else:
            result.update(value_sats=value,value_btc=Decimal(value)/10**8)
            total_in=(total_in+value) % 2**64
        signatures=sum(key[:1] == b"\x02" for key in g)
        if signatures: result["signatures"]=signatures
        inputs.append(result)
    outputs=[]; total_out=0
    for index,group in enumerate(groups[1+count_in:]):
        g=dict(group); value=number(g,3); script=g[b"\x04"]
        outputs.append(dict(index=index,value_sats=value,value_btc=Decimal(value)/10**8,
                            script_pubkey=script.hex(),address=address(script,net)))
        total_out=(total_out+value) % 2**64
    return dict(network=net,version=version,locktime=locktime,input_count=count_in,output_count=count_out,
                inputs=inputs,outputs=outputs,total_input_value=total_in if all_values else None,
                total_output_value=total_out,fee=max(0,total_in-total_out) if all_values else None)
