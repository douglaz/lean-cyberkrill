# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Synthetic process-result checks, never presented as reference captures."""
from copy import deepcopy
import json
from compare import Comparator, differences, exact_json


def result(stdout="", stderr="", status=0):
    return dict(stdout=stdout, stderr=stderr, status=status)


def selftest():
    checks = []

    def good(name, fn):
        fn()
        checks.append(name)

    def bad(name, fn, reason):
        try:
            fn()
        except (AssertionError, ValueError) as error:
            assert reason in str(error), f"harness wrong detecting assertion: {name}"
        else:
            raise AssertionError(f"harness accepted altered actual result: {name}")
        checks.append(name)

    case = dict(id="synthetic-exact", mode="json")
    ref = result('{"n":9007199254740992,"other":"kept"}')
    port = result('{"other":"kept","n":9007199254740993}')
    entry = dict(case=case["id"], field='stdout["n"]', kind="number",
                 reference="9007199254740992", port="9007199254740993", rationale="synthetic")

    def compared(actual=port, entries=None, finish=True):
        c = Comparator([entry] if entries is None else entries)
        c.compare(case, ref, actual)
        if finish:
            c.finish()

    good("pinned exact numeric difference", compared)
    good("object order and whitespace", lambda: Comparator().compare(case, ref, result(' {"other":"kept", "n":9007199254740992.0} ')))
    bad("missing amount entry", lambda: compared(entries=[]), "unlisted difference")
    bad("wrong pinned number", lambda: compared(result('{"n":9007199254740994,"other":"kept"}')), "wrong pinned values")
    bad("unrelated field", lambda: compared(result('{"n":9007199254740993,"other":"changed"}')), "unlisted difference")
    bad("extra field", lambda: compared(result('{"n":9007199254740993,"other":"kept","extra":0}')), "field set")
    bad("unused amount entry", lambda: compared(ref), "unused amount entries")
    bad("success exit", lambda: compared({**port, "status": 1}), "success status")
    bad("wrong stream", lambda: compared({**port, "stderr": "warning\n"}), "unlisted difference")
    bad("numeric string", lambda: compared(result('{"n":"9007199254740993","other":"kept"}')), "number type")
    bad("boolean vs integer", lambda: Comparator().compare(case, result('{"n":1}'), result('{"n":true}')), "unlisted difference")
    bad("nonfinite JSON", lambda: exact_json('{"n":NaN}'), "nonfinite")
    scalar = dict(id="synthetic-scalar", mode="scalar")
    good("exact scalar", lambda: Comparator().compare(scalar, result("1\n"), result("1\n")))
    bad("scalar newline", lambda: Comparator().compare(scalar, result("1\n"), result("1")), "unlisted difference")
    scalar_entry = dict(case=scalar["id"], field="stdout", kind="string", reference="1\n", port="2\n")
    def scalar_compare(actual):
        c = Comparator([scalar_entry]); c.compare(scalar, result("1\n"), actual); c.finish()
    good("pinned scalar", lambda: scalar_compare(result("2\n")))
    bad("wrong scalar pin", lambda: scalar_compare(result("2")), "wrong pinned values")
    for error in ["feeUnitRequired", "unsupportedUrlForm", "unsupportedScheme"]:
        refusal = dict(id="synthetic-" + error, mode="failure")
        e = dict(case=refusal["id"], reference_status=0, port_status=1, error=error,
                 reference_stdout='{"synthetic":true}\n', reference_stderr="",
                 port_stderr=error + ": synthetic refusal\n")
        r = result(e["reference_stdout"])
        actual = result(stderr=e["port_stderr"], status=1)
        def refused(p=actual, reference=r, entries=None, finish=True):
            c = Comparator(refusals=[e] if entries is None else entries)
            c.compare(refusal, reference, p)
            if finish: c.finish()
        good(error + " named refusal", refused)
        bad(error + " missing entry", lambda: refused(entries=[]), "success status")
        bad(error + " wrong identity", lambda: refused({**actual, "stderr": "otherError: synthetic refusal\n"}), "refusal error identity")
        bad(error + " wrong port status", lambda: refused({**actual, "status": 2}), "refusal port status")
        bad(error + " wrong reference status", lambda: refused(reference={**r, "status": 1}), "refusal reference status")
        bad(error + " wrong stdout", lambda: refused({**actual, "stdout": e["port_stderr"]}), "refusal stdout")
        bad(error + " changed reference", lambda: refused(reference={**r, "stdout": "changed\n"}), "refusal reference stdout")
        bad(error + " unused entry", lambda: Comparator(refusals=[e]).finish(), "unused refusal entries")
    bad("ordinary failure success JSON", lambda: Comparator().compare(dict(id="failure", mode="failure"), result(stderr="error\n", status=1), result('{}\n', status=1)), "ordinary failure")
    from regressions import collision, line_endings
    for stream in ["stdout", "stderr"]:
        for label, ending in [("CRLF", b"\r\n"), ("CR", b"\r")]:
            good(f"subprocess {stream} {label}", lambda: line_endings(stream, ending))
    for kind in ["dotted", "bracket"]:
        good(kind + " leaf collision", lambda: collision(kind))
    def escaped_array():
        key = 'a"\\\n'
        field = 'stdout[' + json.dumps(key) + '][0]'
        c = Comparator([dict(case=case["id"], field=field, kind="number", reference="1", port="2")])
        c.compare(case, result(json.dumps({key: [1]})), result(json.dumps({key: [2]})))
        c.finish()
    good("escaped key and array pin", escaped_array)
    good("stream versus object member", lambda: assert_paths())
    stderr_entry = dict(case=scalar["id"], field="stderr", kind="string", reference="old\n", port="new\n")
    def stderr_compare(actual):
        c = Comparator([stderr_entry])
        c.compare(scalar, result("1\n", "old\n"), actual)
        c.finish()
    good("pinned stderr", lambda: stderr_compare(result("1\n", "new\n")))
    bad("wrong stderr pin", lambda: stderr_compare(result("1\n", "new\r\n")), "wrong pinned values")
    bad("unused stderr pin", lambda: stderr_compare(result("1\n", "old\n")), "unused amount entries")
    assert len(checks) == 52
    print("harness synthetic checks: 52/52")
    return checks


def assert_paths():
    assert differences({"stderr": 1}, {"stderr": 2})[0][0] == 'stdout["stderr"]'
    assert differences("old", "new", "stderr")[0][0] == "stderr"


if __name__ == "__main__":
    selftest()
    from importlib import import_module
    lightning = import_module("lightning")
    lightning.COMPARE.selftest(lightning.captures())
    import_module("revisions").selftest()
