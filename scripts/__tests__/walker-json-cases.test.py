#!/usr/bin/env python3
"""card 5e3c31c5: the walker JSON reader of the python twin (email_extract._walker_json_loads).

The corpus is scripts/hooks/walker-json-cases.json: each row says whether the reader must accept the
text. The JS reader (parseWalkerJson in scripts/email-send-gate.mjs) runs the same rows in
src/__tests__/walker-json-cases.test.ts. Until N2 adds the python reader the block is SKIPPED and says so.

Run: python3 -I <thisfile>   Exit 0 = all pass (skips are reported, not counted as passes).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
HOOKS = os.path.join(ROOT, "scripts", "hooks")
sys.path.insert(0, HOOKS)
import email_extract as ee  # noqa: E402

with open(os.path.join(HOOKS, "walker-json-cases.json"), encoding="utf-8") as _fh:
    ROWS = json.load(_fh)["rows"]

failed = []
passed = 0
skipped = 0


def check(name, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed.append(name)
        print(f"  FAIL {name} {detail}", file=sys.stderr)


def row_text(r):
    if "template" in r:
        return r["template"] % (r["repeat"] * r["count"])
    return r["text"]


reader = getattr(ee, "_walker_json_loads", None)
if reader is None:
    skipped = len(ROWS)
    print(f"SKIPPED {skipped} corpus rows: email_extract._walker_json_loads does not exist yet")
else:
    for r in ROWS:
        text = row_text(r)
        try:
            out = reader(text)
            got, err = True, ""
        except ValueError as e:
            got, out, err = False, None, type(e).__name__
        check(f"{'accepts' if r['accept'] else 'rejects'}: {r['label']}", got is r["accept"], f"got accept={got} {err}")
        if r.get("count", 0) >= 4301 and got:
            # the huge integer is parsed without int(): a float on every Python version, no digit-limit ValueError
            big = out["a"] if isinstance(out, dict) else None
            check(f"huge integer is a float: {r['label']}", isinstance(big, float), f"type {type(big).__name__}")

print(f"\n{passed} passed, {len(failed)} failed, {skipped} skipped")
if failed:
    print(f"FAILED: {failed}", file=sys.stderr)
    sys.exit(1)
