#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Synthetic vectors and independent rational expectations for price feeds."""
import json
from decimal import Decimal, localcontext, ROUND_HALF_EVEN
from fractions import Fraction
from cases import APP

SOURCES = ["coingecko", "coinbase", "blockchain.info", "kraken", "fedi", "cex.io", "bitstamp", "yadio", "gemini"]
LABELS = ["CoinGecko", "Coinbase", "Blockchain.info", "Kraken", "Fedi", "CEX.IO", "Bitstamp", "Yadio", "Gemini"]
FIELDS = ["CoinGecko price", "Coinbase rate", "Blockchain.info last price", "Kraken close price", "Fedi rate", "CEX.IO last price", "Bitstamp last price", "Yadio rate", "Gemini last price"]
PATHS = ["/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", "/v2/exchange-rates?currency=BTC", "/ticker", "/0/public/Ticker?pair=XBTUSD", "/latest", "/api/ticker/BTC/USD", "/api/v2/ticker/btcusd", "/convert/1/BTC/USD", "/v1/pubticker/btcusd"]


def ratio(value):
    value = Fraction(value)
    return dict(numerator=str(value.numerator), denominator=str(value.denominator))


def fixed(value):
    with localcontext() as context:
        context.prec = max(100, len(str(abs(value.numerator))) + len(str(value.denominator)) + 3)
        return format((Decimal(value.numerator) / Decimal(value.denominator)).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN), ".2f")


def body(source, value):
    return {
        "coingecko": {"bitcoin": {"usd": value}}, "coinbase": {"data": {"rates": {"USD": value}}},
        "blockchain.info": {"USD": {"last": value}}, "kraken": {"result": {"PAIR": {"c": [value]}}},
        "fedi": {"prices": {"BTC/USD": {"rate": value}}}, "cex.io": {"last": value},
        "bitstamp": {"last": value}, "yadio": {"rate": value}, "gemini": {"last": value},
    }[source]


def pure_cases():
    rows = []
    def add(name, op, expected, **fields):
        rows.append(dict(id=name, op=op, expected=expected, **fields))
    fixtures = json.loads((APP / "test/http/success.json").read_text())
    for index, source in enumerate(SOURCES):
        def parse(name, value, expected, currency="USD"):
            add(source + "/" + name, "parse", expected, source=source, currency=currency,
                body=value if isinstance(value, str) else json.dumps(value))
        parse("success", fixtures[source], dict(ok=ratio(95000 + index*10)))
        parse("missing", {}, dict(ok=None))
        parse("malformed", "{", dict(error="Invalid " + LABELS[index] + " JSON"))
        for name, value, expected in [
            ("numeric-string", "9.5e+4", dict(ok=ratio(95000))),
            ("leading-dot", ".5", dict(ok=ratio("0.5"))),
            ("trailing-dot", "5.", dict(ok=ratio(5))),
            ("negative", -1, dict(error=FIELDS[index] + " must be positive")),
            ("negative-string", "-1", dict(error=FIELDS[index] + " must be positive")),
            ("infinity", "+inf", dict(error=FIELDS[index] + " must be positive")),
            ("nan", "NaN", dict(error=FIELDS[index] + " must be positive")),
            ("zero", "0", dict(error=FIELDS[index] + " must be positive")),
            ("null", None, dict(error=FIELDS[index] + " is not a number")),
            ("array", [], dict(error=FIELDS[index] + " is not a number")),
            ("boolean", True, dict(error=FIELDS[index] + " is not a number")),
            ("text", "wat", dict(error=FIELDS[index] + " is not a number")),
        ]:
            parse(name, body(source, value), expected)
        for status in [404, 429, 500]:
            expected = dict(ok=None) if status == 404 and index >= 5 else dict(error=f"{LABELS[index]} returned an unsuccessful status: HTTP {status}")
            add(f"{source}/http-{status}", "response", expected, source=source, status=status, body="{")
    specials = [
        ("kraken/errors", "kraken", {"error": ["disabled"], "result": {"P": {"c": [0]}}}, None),
        ("kraken/multiple", "kraken", {"result": {"ZUSD": {"c": [30]}, "AUSD": {"c": [20]}, "EUR": {"c": [10]}}}, 20),
        ("kraken/no-suffix", "kraken", {"result": {"A": {"c": [20]}, "B": {"c": [10]}}}, None),
        ("kraken/no-close", "kraken", {"result": {"A": {"c": []}, "meta": 3}}, None),
        ("kraken/extra-fields", "kraken", {"result": {"meta": {"note": "ignored"}, "WHAT": {"c": [17]}}}, 17),
        ("cex.io/error-null", "cex.io", {"error": None, "last": 17}, None),
        ("yadio/error-null", "yadio", {"error": None, "rate": 17}, None),
        ("gemini/error-case", "gemini", {"result": "ErRoR", "last": 17}, None),
        ("gemini/nonstring", "gemini", {"result": None, "last": 17}, 17),
    ]
    for name, source, value, expected in specials:
        add(name, "parse", dict(ok=ratio(expected) if expected is not None else None), source=source, currency="USD", body=json.dumps(value))
    add("kraken/invalid-unselected", "parse", dict(error="Kraken close price must be positive"), source="kraken", currency="USD",
        body=json.dumps({"result": {"AUSD": {"c": [20]}, "ZOTHER": {"c": [0]}}}))
    add("fedi/orientation", "parse", dict(ok=ratio(475200)), source="fedi", currency="BRL", body=json.dumps(fixtures["fedi"]))
    add("fedi/repeating", "parse", dict(ok=ratio(Fraction(95040, 7))), source="fedi", currency="EUR", body=json.dumps({"prices": {"BTC/USD": {"rate": 95040}, "EUR/USD": {"rate": 7}}}))
    add("fedi/invalid-leg", "parse", dict(error="Fedi rate must be positive"), source="fedi", currency="BRL", body=json.dumps({"prices": {"BTC/USD": {"rate": 95000}, "BRL/USD": {"rate": 0}}}))
    add("fedi/missing-leg", "parse", dict(ok=None), source="fedi", currency="EUR", body=json.dumps(fixtures["fedi"]))
    valid = ["100usd", " 1 EUR ", "1,000 USD", "12,345,678.90USD", "1,23,45,678.90INR", "123,45,678INR", "0USD", "00.000usd", "1e3USD", "1E-3USD", "1.2e+5USD", "1,234.5e2USD", "1,234.e2USD", "\u00a01usd\u2003", "1 USD", "1\tUSD"]
    for index, value in enumerate(valid):
        trimmed = value.strip()
        currency = trimmed[-3:].upper()
        amount = Fraction(trimmed[:-3].strip().replace(",", ""))
        add(f"grammar/valid-{index}", "grammar", dict(ok=dict(amount=ratio(amount), currency=currency)), input=value)
    invalid = ["+1USD", "-1USD", ".5USD", "5.USD", "1,23USD", "1234,567USD", "1,234,56USD", "1.2,3USD", "1,,000USD", "1.2.3USD", "1_000USD", "1 000USD", "1eUSD", "1e+USD", "1e309USD", "NaNUSD", "infUSD", "infinityUSD", "USD", "1US", "1USDT", "1U5D", "1\u00dcSD", "1btc", "1sat", "-bad1usd", "1,23,456,789INR"]
    for index, value in enumerate(invalid):
        add(f"grammar/invalid-{index}", "grammar", dict(error_contains="invalidFiat:"), input=value)
    for amount, expected in [("0.000010924999", 11), ("0.000010925", 12), ("0.000010925001", 12), ("0", 0), ("100", 105263158)]:
        add("convert/" + amount, "convert", dict(ok=expected), amount=amount, price="95000", mode="msat")
    for amount in ["0.001424524999", "0.001424525", "0.001424525001", "0.001899524999", "0.001899525", "0.001899525001"]:
        n = Fraction(amount) / 95000 * 10**11
        msat = (2*n.numerator + n.denominator) // (2*n.denominator)
        for mode in ["msat", "whole", "floor"]:
            expected = msat if mode == "msat" else ((msat+500)//1000 if mode == "whole" else msat//1000)*1000
            add("precision/" + amount + "/" + mode, "convert", dict(ok=expected), amount=amount, price="95000", mode=mode)
    for name, amount, price, mode, error in [
        ("tiny", "0.00000001", "95000", "msat", "less than 1 msat"),
        ("tiny-whole", "0.000010925", "95000", "whole", "lessThanOneSat:"),
        ("tiny-floor", "0.000010925", "95000", "floor", "lessThanOneSat:"),
        ("zero-price", "1", "0", "msat", "Invalid BTC price"),
        ("overflow", "18446744073709551616", "100000000000", "msat", "outside the supported range"),
        ("whole-overflow", "18446744073709551615", "100000000000", "whole", "outside the supported range"),
    ]:
        add("convert/" + name, "convert", dict(error_contains=error), amount=amount, price=price, mode=mode)
    add("convert/currency", "convert", dict(error_contains="currency mismatch"), amount="1", price="95000", mode="msat", currency="EUR")
    add("convert/max", "convert", dict(ok=2**64-1), amount=str(2**64-1), price="100000000000", mode="msat")
    for count in [9, 4, 3, 2, 1, 0]:
        quotes = [dict(source=SOURCES[i], price=str(95000+i*10)) for i in range(count)]
        add("aggregate/" + str(count), "aggregate", aggregation(quotes), quotes=quotes)
    for name, values in [("ties", [100, 100, 100]), ("below-spread", ["100", "101", "101.99"]), ("exact-spread", [100, 101, 102]), ("above-spread", [100, 101, 103])]:
        # Fraction receives the literal decimal spelling, never a binary float.
        quotes = [dict(source=source, price=str(price)) for source, price in zip(["z", "a", "m"], values)]
        add("aggregate/" + name, "aggregate", aggregation(quotes), quotes=quotes)
    add("median/empty", "median", None, values=[])
    add("median/even", "median", ratio("2.5"), values=["4", "1", "3", "2"])
    add("display/zero", "display", dict(fixed="0.00", json=0), value="0e-50")
    add("display/tie-even", "display", dict(fixed="1.00", json=Decimal("1.005")), value="1.005")
    add("display/tie-odd", "display", dict(fixed="1.02", json=Decimal("1.015")), value="1.015")
    add("display/tiny", "display", dict(fixed="0.00", json=Decimal("1e-100")), value="1e-100")
    msats = Fraction(7,95040) * 10**11
    msats = (2*msats.numerator+msats.denominator)//(2*msats.denominator)
    add("fedi/repeating-output", "cross-output", dict(input="1EUR", btc=Decimal(msats).scaleb(-11), sats=msats//1000, msats=msats,
        fiat_source=dict(amount=1,currency="EUR",price_per_btc=Decimal("13577.142857142857142857142857"),feeds=[])),
        input="1EUR",btc_rate="95040",fiat_rate="7",body=json.dumps({"prices":{"BTC/USD":{"rate":95040},"EUR/USD":{"rate":7}}}))
    add("fedi/tiny-repeating-output", "cross-output", dict(input="1e-30EUR",btc=3,sats=300000000,msats=300000000000,
        fiat_source=dict(amount=Decimal("1e-30"),currency="EUR",price_per_btc=Decimal("0."+"0"*30+"3"*24),feeds=[])),
        input="1e-30EUR",btc_rate="1e-30",fiat_rate="3",body=json.dumps({"prices":{"BTC/USD":{"rate":"1e-30"},"EUR/USD":{"rate":3}}}))
    # Exact decimal boundaries: independent rational expectations, with the
    # complete reference outcomes captured by the same pure-function route.
    for spelling in ["0e10001", "0e-10001", "0e10000000000", "1e-400", "1e-1024"]:
        add("grammar/boundary-"+spelling, "grammar", dict(ok=dict(amount=ratio(0 if spelling.startswith("0e") else Fraction(spelling)),currency="USD")), input=spelling+"USD")
    for spelling in ["1e-1025", "1e-10000", "1e-10001"]:
        add("grammar/boundary-"+spelling, "grammar", dict(error_contains="invalidFiat:"), input=spelling+"USD")
    for size in [1024,1025]:
        spelling = "0"*(size-1)+"1"
        expected = dict(ok=dict(amount=ratio(1),currency="USD")) if size == 1024 else dict(error_contains="invalidFiat:")
        add("grammar/coefficient-"+str(size),"grammar",expected,input=spelling+"USD")
    for spelling in ["1e-400", "1e-1024"]:
        add("convert/boundary-"+spelling,"convert",dict(error_contains="less than 1 msat"),amount=spelling,price="95000",mode="msat")
    for spelling in ["1e309", "1e400", "1e-400", "1e1024", "1e-1024", "1e1025", "1e-1025"]:
        for string in [True,False]:
            expected = (dict(ok=ratio(Fraction(spelling))) if spelling not in ["1e1025","1e-1025"] else
                        dict(error="Bitstamp last price is not a number" if string else "Invalid Bitstamp JSON"))
            add("bitstamp/boundary-"+("string-" if string else "number-")+spelling,"parse",expected,
                source="bitstamp",currency="USD",body='{"last":'+(json.dumps(spelling) if string else spelling)+'}')
    for size in [1024,1025]:
        spelling="0."+"0"*(size-2)+"1"
        for string in [True,False]:
            expected = dict(ok=ratio(Fraction(spelling))) if size==1024 else dict(error="Bitstamp last price is not a number" if string else "Invalid Bitstamp JSON")
            add("bitstamp/coefficient-"+("string-" if string else "number-")+str(size),"parse",expected,
                source="bitstamp",currency="USD",body='{"last":'+(json.dumps(spelling) if string else spelling)+'}')
    for name,ignored,valid in [("high",r"\ud800",False),("low",r"\udc00",False),("wrong-low",r"\ud800\u0041",False),
                               ("pair",r"\ud800\udc00",True),("last-pair",r"\udbff\udfff",True),("escaped",r"\\ud800",True)]:
        add("bitstamp/surrogate-"+name,"parse",dict(ok=ratio(1)) if valid else dict(error="Invalid Bitstamp JSON"),
            source="bitstamp",currency="USD",body='{"ignored":"'+ignored+'","last":1}')
    for name,raw,expected in [
        ("ignored",b'{"ignored":"\xff","last":1}',dict(ok=ratio(1))),
        ("structure",b'{\xff"last":1}',dict(error="Invalid Bitstamp JSON")),
        ("missing",b'{"ignored":"\xff"}',dict(ok=None)),
        ("number",b'{"last":1\xff}',dict(error="Invalid Bitstamp JSON")),
    ]:
        add("bitstamp/raw-"+name,"response",expected,source="bitstamp",status=200,body="",bytes=list(raw))
    # Whole-body validity includes ignored containers and numeric tokens.
    for kind in ["array", "object"]:
        for depth in [125, 126, 127, 128, 200]:
            ignored = "["*depth+"0"+"]"*depth if kind == "array" else '{"x":'*depth+"0"+"}"*depth
            add(f"bitstamp/depth-{kind}-{depth}", "parse",
                dict(ok=ratio(95000)) if depth <= 126 else dict(error="Invalid Bitstamp JSON"),
                source="bitstamp", currency="USD", body='{"last":95000,"ignored":'+ignored+'}')
    add("bitstamp/depth-quoted", "parse", dict(ok=ratio(95000)), source="bitstamp", currency="USD",
        body=json.dumps(dict(last=95000, ignored='[{'*200+'\\"'+']}'*200)))
    for spelling in ["1e-1024", "1e-1025", "1e-5000", "1e308", "1e400", "0e5000", "0e-5000", "0e10001", "0e-10001", "-0e5000"]:
        add("bitstamp/ignored-"+spelling, "parse",
            dict(error="Invalid Bitstamp JSON") if spelling == "1e400" else dict(ok=ratio(95000)),
            source="bitstamp", currency="USD", body='{"ignored":'+spelling+',"last":95000}')
    add("bitstamp/ignored-long-fraction", "parse", dict(ok=ratio(95000)), source="bitstamp", currency="USD",
        body='{"ignored":0.'+'0'*1100+'1,"last":95000}')
    for spelling in ["0e1024", "0e5000", "0e-5000", "0e10001", "0e-10001", "0e10000000000", "-0e5000"]:
        add("bitstamp/zero-number-"+spelling, "parse", dict(error="Bitstamp last price must be positive"),
            source="bitstamp", currency="USD", body='{"last":'+spelling+'}')
    for spelling in ["-+5", "-+0", "--0", "+-0", "++5", "--5", "-1e2000", "-1e-2000", "-1e1024", "-1e-1024", "-0", "-0.0", "+0", "-5", "+5", "5", "-1e", "-inf", "-NaN"]:
        malformed = spelling in ["-+5", "-+0", "--0", "+-0", "++5", "--5", "-1e"]
        expected = dict(ok=ratio(5)) if spelling in ["+5", "5"] else dict(error="Bitstamp last price "+("is not a number" if malformed else "must be positive"))
        add("bitstamp/sign-"+spelling, "parse", expected, source="bitstamp", currency="USD", body=json.dumps(dict(last=spelling)))
    for name,btc,fiat in [("overflow", "1e300", "1e-300"), ("underflow", "1e-300", "1e300"),
                          ("large-control", "1e150", "1e-150"), ("small-control", "1e-150", "1e150")]:
        add("fedi/cross-"+name, "parse", dict(ok=ratio(Fraction(btc)/Fraction(fiat))), source="fedi", currency="EUR",
            body=json.dumps({"prices":{"BTC/USD":{"rate":btc},"EUR/USD":{"rate":fiat}}}))
    for spelling, valid in [("1.7976931348623157e308", True), ("1.7976931348623159e308", False),
                             ("-1.7976931348623159e308", False), ("-1e308", True)]:
        add("bitstamp/ignored-finite-"+spelling, "parse", dict(ok=ratio(95000)) if valid else dict(error="Invalid Bitstamp JSON"),
            source="bitstamp", currency="USD", body='{"ignored":'+spelling+',"last":95000}')
    for name, raw, expected in [
        ("selected-before-ignored", '{"last":95000,"ignored":1e-5000}', dict(ok=ratio(95000))),
        ("distinct-number-identities", '{"last":1e400,"ignored":1e400}', dict(error="Invalid Bitstamp JSON")),
        ("invalid-selected-and-ignored", '{"last":"wat","ignored":1e400}', dict(error="Invalid Bitstamp JSON")),
        ("overwritten-number", '{"last":1e400,"last":95000}', dict(error="Invalid Bitstamp JSON")),
    ]:
        add("bitstamp/"+name, "parse", expected, source="bitstamp", currency="USD", body=raw)
    for spelling in ["01", "1.", "1.e2", "1e", "1e+-2", "--1"]:
        add("bitstamp/json-syntax-"+spelling, "parse", dict(error="Invalid Bitstamp JSON"), source="bitstamp", currency="USD",
            body='{"last":'+spelling+'}')
    for spelling in ["n0", "s5"]:
        add("bitstamp/encoding-"+spelling, "parse", dict(error="Bitstamp last price is not a number"), source="bitstamp", currency="USD",
            body=json.dumps(dict(last=spelling)))
    add("cex.io/error-ignored-overflow", "parse", dict(error="Invalid CEX.IO JSON"), source="cex.io", currency="USD",
        body='{"error":null,"last":1e400}')
    for name, source, currency, raw, label in [
        ("bitstamp/negative-number-overflow", "bitstamp", "USD", '{"last":-1e400}', "Bitstamp"),
        ("fedi/missing-leg-overflow", "fedi", "EUR", '{"prices":{"BTC/USD":{"rate":1e400}}}', "Fedi"),
        ("kraken/invalid-candidate-overflow", "kraken", "USD", '{"result":{"AUSD":{"c":[1e400]},"ZUSD":{"c":["wat"]}}}', "Kraken"),
    ]:
        add(name, "parse", dict(error="Invalid "+label+" JSON"), source=source, currency=currency, body=raw)
    # Unquoted keys are invalid in every object position. Quoted numeric and
    # marker-like keys/strings remain disjoint from encoded numeric identities.
    for spelling in ["1", "-1", "1.5", "1e2"]:
        for position, raw in [
            ("first", '{'+spelling+':2,"last":95000}'),
            ("later", '{"last":95000,'+spelling+' \t:2}'),
            ("nested", '{"last":95000,"ignored":{'+spelling+':2}}'),
            ("array", '{"last":95000,"ignored":[{'+spelling+':2}]}'),
        ]:
            add("bitstamp/numeric-key-"+position+"-"+spelling,"parse",dict(error="Invalid Bitstamp JSON"),
                source="bitstamp",currency="USD",body=raw)
    add("bitstamp/numeric-key-only","parse",dict(error="Invalid Bitstamp JSON"),
        source="bitstamp",currency="USD",body='{1:2}')
    for name, raw in [
        ("quoted-number", '{"last":95000,"1":2}'),
        ("quoted-markers", '{"last":95000,"n0":"s5","s5":"n0"}'),
        ("nested-markers", '{"last":95000,"ignored":[{"1":2,"n0":"s5"}]}'),
    ]:
        add("bitstamp/key-control-"+name,"parse",dict(ok=ratio(95000)),source="bitstamp",currency="USD",body=raw)
    # Losing Kraken candidates must be validated even when another pair wins.
    # Only the selected price receives the exact numeric-token exemption.
    for suffix in ["USD", "EUR"]:
        for name, spelling, string in [
            ("overflow309", "1e309", False), ("overflow400", "1e400", False),
            ("underflow", "1e-400", False), ("string-overflow", "1e400", True),
            ("string-underflow", "1e-400", True),
            ("large-control", "1e308", False), ("small-control", "1e-300", False),
        ]:
            raw = '{"result":{"AUSD":{"c":[20]},"Z'+suffix+'":{"c":['+(json.dumps(spelling) if string else spelling)+']}}}'
            expected = dict(error="Invalid Kraken JSON") if name.startswith("overflow") else dict(ok=ratio(20))
            add("kraken/losing-"+suffix+"-"+name,"parse",expected,source="kraken",currency="USD",body=raw)
    add("fedi/missing-leg-underflow","parse",dict(ok=None),source="fedi",currency="EUR",
        body='{"prices":{"BTC/USD":{"rate":1e-400}}}')
    # Actual lexical neighbors, independent of the exact arithmetic magnitude
    # limit. These bodies remain structurally valid at both token lengths.
    for size in [2048, 2049]:
        for kind, token in [("exponent", "0e"+"0"*(size-2)), ("fraction", "0."+"0"*(size-2))]:
            assert len(token) == size
            for selected in [False, True]:
                expected = (dict(error="Invalid Bitstamp JSON") if size > 2048
                            else dict(error="Bitstamp last price must be positive") if selected else dict(ok=ratio(95000)))
                raw = '{"last":'+token+'}' if selected else '{"last":95000,"ignored":'+token+'}'
                add("bitstamp/lexical-"+("selected-" if selected else "ignored-")+kind+"-"+str(size),"parse",expected,
                    source="bitstamp",currency="USD",body=raw)
    for spelling, valid in [("1.7976931348623158e308", True), ("17976931348623158e292", True),
                             ("1.79769313486231581e308", False)]:
        add("bitstamp/finite-neighbor-"+spelling,"parse",dict(ok=ratio(95000)) if valid else dict(error="Invalid Bitstamp JSON"),
            source="bitstamp",currency="USD",body='{"last":95000,"ignored":'+spelling+'}')
    rows.extend(observed_price_cases())
    rows.extend(remaining_price_cases(rows))
    return rows


def observed_price_cases():
    """Selected extremes and ordinary-value limits with independent exact values."""
    rows = []
    def add(name, source, raw, expected, currency="USD"):
        rows.append(dict(id=name, op="parse", source=source, currency=currency,
                         body=raw, expected=expected))
    # Replace an authored string sentinel only at the selected field. This
    # preserves each source's consumed shape while supplying a raw JSON number.
    for source in ["coingecko", "coinbase", "blockchain.info", "cex.io", "yadio", "gemini"]:
        template = json.dumps(body(source, "SELECTED_NUMBER"))
        assert template.count('"SELECTED_NUMBER"') == 1
        for token in ["1e400", "1e-400", "1e20", "1e-20"]:
            add(source+"/selected-number-"+token, source,
                template.replace('"SELECTED_NUMBER"', token), dict(ok=ratio(Fraction(token))))
    for token in ["1e400", "1e-400", "1e20", "1e-20"]:
        for shape in ["single", "multiple"]:
            raw = ('{"result":{"ANY":{"c":['+token+']}}}' if shape == "single" else
                   '{"result":{"AUSD":{"c":['+token+']},"ZEUR":{"c":[5]}}}')
            add("kraken/selected-"+shape+"-"+token, "kraken", raw, dict(ok=ratio(Fraction(token))))
        for currency in ["USD", "EUR"]:
            raw = '{"prices":{"BTC/USD":{"rate":'+token+'}' + (',"EUR/USD":{"rate":2}' if currency == "EUR" else '')+'}}'
            add("fedi/selected-"+currency+"-"+token, "fedi", raw,
                dict(ok=ratio(Fraction(token)/(2 if currency == "EUR" else 1))), currency)
    for token in ["1e400", "1e-400"]:
        add("fedi/missing-leg-string-"+token, "fedi",
            json.dumps({"prices":{"BTC/USD":{"rate":token}}}), dict(ok=None), "EUR")
    # Coefficient counts exclude the decimal point, unlike token lengths.
    for size in [1024, 1025]:
        token = "95000."+"0"*(size-5)
        assert len(token.replace(".", "")) == size and len(token) == size+1
        for string in [False, True]:
            expected = dict(ok=ratio(95000)) if size == 1024 else dict(error=
                "Bitstamp last price is not a number" if string else "Invalid Bitstamp JSON")
            add("bitstamp/ordinary-coefficient-"+("string-" if string else "number-")+str(size),
                "bitstamp", '{"last":'+(json.dumps(token) if string else token)+'}', expected)
        unit = "1."+"0"*(size-1)
        assert len(unit.replace(".", "")) == size
        add("bitstamp/unit-coefficient-"+str(size), "bitstamp", '{"last":'+unit+'}',
            dict(ok=ratio(1)) if size == 1024 else dict(error="Invalid Bitstamp JSON"))
        leading = "0"*(size-5)+"95000"
        assert len(leading) == size
        add("bitstamp/leading-coefficient-"+str(size), "bitstamp", json.dumps(dict(last=leading)),
            dict(ok=ratio(95000)) if size == 1024 else dict(error="Bitstamp last price is not a number"))
        add("fedi/ordinary-coefficient-"+str(size), "fedi",
            '{"prices":{"BTC/USD":{"rate":'+token+'},"EUR/USD":{"rate":2}}}',
            dict(ok=ratio(47500)) if size == 1024 else dict(error="Invalid Fedi JSON"), "EUR")
    for size in [1024, 1025, 1101]:
        token = "1."+"0"*(size-1)
        assert len(token.replace(".", "")) == size
        add("kraken/losing-coefficient-"+str(size), "kraken",
            '{"result":{"AUSD":{"c":[20]},"ZEUR":{"c":['+token+']}}}',
            dict(ok=ratio(20)) if size == 1024 else dict(error="Invalid Kraken JSON"))
    for size in [2048, 2049]:
        token = "95000e"+"0"*(size-6)
        assert len(token) == size and len(token.split("e")[0]) == 5
        for string in [False, True]:
            add("bitstamp/nonzero-lexical-"+("string-" if string else "number-")+str(size),
                "bitstamp", '{"last":'+(json.dumps(token) if string else token)+'}',
                dict(ok=ratio(95000)) if string or size == 2048 else dict(error="Invalid Bitstamp JSON"))
        fraction = "0."+"1"*(size-2)
        assert len(fraction) == size
        add("bitstamp/nonzero-lexical-ignored-fraction-"+str(size), "bitstamp",
            '{"last":95000,"ignored":'+fraction+'}',
            dict(ok=ratio(95000)) if size == 2048 else dict(error="Invalid Bitstamp JSON"))
    assert len(rows) == 61, "observed price addition inventory"
    assert len({row["id"] for row in rows}) == 61, "unique observed price identities"
    return rows


def aggregation(quotes):
    if len(quotes) < 3:
        word = "feed" if len(quotes) == 1 else "feeds"
        return dict(error=f"Only {len(quotes)} BTC price {word} responded for USD; need at least 3 to compute a manipulation-resistant median")
    ordered = sorted((Fraction(q["price"]), q["source"]) for q in quotes)
    middle = len(ordered)//2
    median = ordered[middle][0] if len(ordered)%2 else (ordered[middle-1][0]+ordered[middle][0])/2
    lo, hi = ordered[0], ordered[-1]
    spread = hi[0]/lo[0]-1
    warning = f"[price-feed] BTC price feed spread for USD is {fixed(spread*100)}% ({lo[1]}={fixed(lo[0])}, {hi[1]}={fixed(hi[0])}); using median BTC/USD={fixed(median)}\n" if spread > Fraction(1,50) else ""
    sources = [q[1] for q in ordered]
    return dict(ok=dict(price=ratio(median), sources=sources, warning=warning,
        breadcrumb=f"[price-feed] median BTC/USD = {fixed(median)} from {len(quotes)} feeds: {', '.join(sources)}\n"))


def diagnostic_price_cases():
    """Closed parser/CLI inventory; expectations follow decimal digits and paths."""
    rows = []
    templates = {
        "coingecko": '{"bitcoin":{"usd":%s}}',
        "coinbase": '{"data":{"rates":{"USD":%s}}}',
        "blockchain.info": '{"USD":{"last":%s}}', "cex.io": '{"last":%s}',
        "yadio": '{"rate":%s}', "gemini": '{"last":%s}',
        "kraken": '{"result":{"ANY":{"c":[%s]}}}',
        "fedi": '{"prices":{"BTC/USD":{"rate":%s}}}', "bitstamp": '{"last":%s}',
    }
    def add(name, source, raw, expected, currency="USD"):
        rows.append(dict(id=name, op="parse", source=source, currency=currency, body=raw, expected=expected))
    long95 = "95000."+"0"*1020
    for source, template in templates.items():
        label, field = LABELS[SOURCES.index(source)], FIELDS[SOURCES.index(source)]
        for name, token, expected in [
            ("num-coef1025", long95, dict(error="Invalid "+label+" JSON")),
            ("str-coef1025", json.dumps(long95), dict(error=field+" is not a number")),
            ("str-1e400", '"1e400"', dict(ok=ratio(10**400))),
            ("str-1e-400", '"1e-400"', dict(ok=ratio(Fraction(1,10**400)))),
            ("num-lex2049", "95000e"+"0"*2043, dict(error="Invalid "+label+" JSON")),
        ]:
            add("diagnostic/"+source+"/"+name, source, template % token, expected)
    for name, token, string, expected in [
        ("power1025-coef1024", "95000."+"0"*1019+"e-6", False, dict(error="Invalid Bitstamp JSON")),
        ("power1025-coef1024-string", "95000."+"0"*1019+"e-6", True, dict(error="Bitstamp last price is not a number")),
        ("power1024-coef1024", "95000."+"0"*1019+"e-5", False, dict(ok=ratio(Fraction(95,100)))),
        ("int-power1025", "1"+"0"*1023+"e-1025", False, dict(error="Invalid Bitstamp JSON")),
    ]:
        add("diagnostic/bitstamp/"+name, "bitstamp", '{"last":'+(json.dumps(token) if string else token)+'}', expected)
    for name, btc, fiat, expected in [
        ("eurleg-raw-1e400", "95000", "1e400", dict(ok=ratio(Fraction(95000,10**400)))),
        ("eurleg-raw-1e-400", "95000", "1e-400", dict(ok=ratio(95000*10**400))),
        ("eurleg-str-1e400", "95000", '"1e400"', dict(ok=ratio(Fraction(95000,10**400)))),
        ("eurleg-coef1025", "95000", "2."+"0"*1024, dict(error="Invalid Fedi JSON")),
        ("btcleg-str-coef1025", json.dumps(long95), "2", dict(error="Fedi rate is not a number")),
        ("missing-raw-coef1025", long95, None, dict(error="Invalid Fedi JSON")),
        ("missing-str-coef1025", json.dumps(long95), None, dict(error="Fedi rate is not a number")),
    ]:
        raw = '{"prices":{"BTC/USD":{"rate":'+btc+'}'+ (',"EUR/USD":{"rate":'+fiat+'}' if fiat else '')+'}}'
        add("diagnostic/fedi/"+name, "fedi", raw, expected, "EUR")
    one = "1."+"0"*1100
    for name, raw, expected in [
        ("losing-str-coef1101", '{"result":{"AUSD":{"c":[20]},"ZEUR":{"c":['+json.dumps(one)+']}}}', dict(error="Kraken close price is not a number")),
        ("nowinner-raw-1e-400", '{"result":{"A":{"c":[1e-400]},"B":{"c":[5]}}}', dict(ok=None)),
        ("nowinner-str-1e400", '{"result":{"A":{"c":["1e400"]},"B":{"c":[5]}}}', dict(ok=None)),
        ("nowinner-raw-coef1101", '{"result":{"A":{"c":['+one+']},"B":{"c":[5]}}}', dict(error="Invalid Kraken JSON")),
        ("winner-num-coef1025", '{"result":{"AUSD":{"c":['+long95+']},"ZEUR":{"c":[5]}}}', dict(error="Invalid Kraken JSON")),
        ("losing-lex2049", '{"result":{"AUSD":{"c":[20]},"ZEUR":{"c":[1e'+"0"*2047+']}}}', dict(error="Invalid Kraken JSON")),
    ]:
        add("diagnostic/kraken/"+name, "kraken", raw, expected)
    for name, source, raw, expected in [
        ("cex-error-long-coef", "cex.io", '{"error":"x","last":'+long95+'}', dict(ok=None)),
        ("gemini-error-long-lex", "gemini", '{"result":"error","last":95000e'+"0"*2043+'}', dict(error="Invalid Gemini JSON")),
        ("bitstamp-ignored-coef-long-ok", "bitstamp", '{"ignored":'+long95+',"last":95000}', dict(ok=ratio(95000))),
        ("coingecko-ignored-lex2049", "coingecko", '{"ignored":0.'+"1"*2047+',"bitcoin":{"usd":95000}}', dict(error="Invalid CoinGecko JSON")),
    ]:
        add("diagnostic/"+name, source, raw, expected)
    assert len(rows) == 66, "closed diagnostic parser inventory"
    for name, token, expected in [
        ("power1025-value001", "1"+"0"*1023+"e-1025", None),
        ("power1025-value0095", "95000."+"0"*1019+"e-6", None),
        ("power1024-control", "95000."+"0"*1019+"e-5", Fraction(95,100)),
        ("coef1025-ordinary", long95, None),
        ("coef1024-ordinary", "95000."+"0"*1019, Fraction(95000)),
    ]:
        result = dict(error_contains="invalidFiat:") if expected is None else dict(ok=dict(amount=ratio(expected), currency="USD"))
        rows.append(dict(id="diagnostic/cli-"+name, op="grammar", input=token+"USD", expected=result))
    assert len(rows) == 71, "closed diagnostic parser/CLI inventory"
    return rows


def case_input(row):
    """Compare input identities without treating JSON whitespace as coverage."""
    if row["op"] == "parse":
        try:
            value = json.loads(row["body"], parse_int=lambda s:("number",s), parse_float=lambda s:("number",s))
        except json.JSONDecodeError:
            return row["op"], row["source"], row["currency"], row["body"]
        return row["op"], row["source"], row["currency"], json.dumps(value, sort_keys=True)
    assert row["op"] == "grammar"
    return row["op"], row["input"]


def precision_price_cases():
    rows = []
    for name, value, string in [
        ("long-string", "95000.123456789012345678", True),
        ("long-number", "95000.123456789012345678", False),
        ("small-string", "0.10000000000000001", True),
        ("integer", "9007199254740993", False),
        ("integer-neighbor", "9007199254740992", False),
    ]:
        rows.append(dict(id="precision-price/"+name, op="parse", source="bitstamp", currency="USD",
                         body='{"last":'+(json.dumps(value) if string else value)+'}', expected=dict(ok=ratio(Fraction(value)))))
    for name, middle in [("cent", ["95000.00", "95000.02"]),
                         ("cent-below", ["95000.00", "95000.00"]),
                         ("cent-above", ["95000.02", "95000.02"])]:
        quotes = [dict(source=n, price=p) for n,p in zip("abcd", ["94000", *middle, "96000"])]
        rows.append(dict(id="aggregate/"+name, op="aggregate", quotes=quotes, expected=aggregation(quotes), capture_breadcrumb=True))
    assert len(rows) == 8, "ordinary precision and cent median inventory"
    return rows


def remaining_price_cases(existing):
    existing_inputs = {case_input(row):row for row in existing if row["op"] in ["parse", "grammar"]}
    diagnostics, reused = [], []
    for row in diagnostic_price_cases():
        previous = existing_inputs.get(case_input(row))
        if previous is None: diagnostics.append(row)
        else:
            assert previous["expected"] == row["expected"], "reused diagnostic independent expectation"
            reused.append(previous["id"])
    assert len(reused) == 5 and len(set(reused)) == 5, "reuse five existing Bitstamp authorities"
    assert len(diagnostics) == 66, "61 new parser and five CLI inputs"
    return diagnostics + precision_price_cases()
