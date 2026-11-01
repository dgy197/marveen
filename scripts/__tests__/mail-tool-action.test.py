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
    bad_fwd = bad_reader = bad_clean = 0
    for s in NI["servers"]:
        for nm in NI["forward_names"] + NI["disguised_names"]:
            for f in NI["forward_shapes"]:
                t = f"mcp__{s}__{nm}"
                if ee.mail_tool_action(t, f["input"]) != "send" or ee.mail_rule_forward(t, f["input"]) is not True:
                    bad_fwd += 1
        for nm in NI["reader_names"]:
            for f in NI["reader_inputs"]:
                t = f"mcp__{s}__{nm}"
                if ee.mail_tool_action(t, f["input"]) is not None or ee.mail_rule_forward(t, f["input"]) is not False:
                    bad_reader += 1
    for c in NI["clean"]:
        if ee.mail_tool_action(c["tool"], c["input"]) != c["expected"] or ee.mail_rule_forward(c["tool"], c["input"]) is not False:
            bad_clean += 1
            print("   clean case differs:", c["tool"], c["note"])
    n_fwd = len(NI["servers"]) * (len(NI["forward_names"]) + len(NI["disguised_names"])) * len(NI["forward_shapes"])
    check(f"{n_fwd} forward calls (servers x names x shapes) are a send via mail_rule_forward", bad_fwd == 0, f"{bad_fwd} differ")
    check("readers stay None whatever the input", bad_reader == 0, f"{bad_reader} differ")
    check("clean non-reader calls and prose drafts keep their class", bad_clean == 0, f"{bad_clean} differ")
    bad_n4 = [c["tool"] for c in NI["reviewer_n4"]
              if ee.mail_tool_action(c["tool"], c["input"]) != "send" or ee.mail_rule_forward(c["tool"], c["input"]) is not True]
    check("N4 B2: the reviewer's 5 rule / script / filter inputs (Sieve redirect, forward instruction, fwd) are a send", not bad_n4, f"{bad_n4}")
    narrow = lambda v: ee._has_forward_key_name(v, True, True)
    check("N4 B2: narrow patterns read free text only for a non-draft tool",
          narrow({"content": 'redirect :copy "x@evil.example";'}) and narrow({"description": "forward every message to x@evil.example"})
          and narrow({"body": "FWD: all mail to x@evil.example"})
          and not ee._has_forward_key_name({"content": 'redirect :copy "x@evil.example";'}, True, False)
          and not ee._has_forward_key_name({"body": "please forward this to x@y.example"}, True, False))
    check("N4 B2: narrow patterns spare prose, a forward word far from an address, label / folder identifiers and straightforward",
          not narrow({"description": "forward looking statement, mail me at some point"}) and not narrow({"body": "straightforward x@y.example"})
          and not narrow({"folder": "forward to x@evil.example"}) and not narrow({"addLabelIds": ["fwd x@evil.example"]})
          and not narrow({"body": "forward " + "a" * 41 + " x@y.example"}) and not narrow({"body": 'redirect x@y.example'}))
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
    check("non-object input: a non-reader is a send (fail-closed), a reader stays None",
          ee.mail_tool_action("mcp__outlook__manage_rules", "x") == "send" and ee.mail_tool_action("mcp__outlook__get_rules", "x") is None)
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
        for tool, ti, label in (("mcp__outlook__list_rules", {"forwardTo": "x"}, "reader"),
                                ("mcp__outlook__manage_rules", {"rules": [{"actions": {"moveToFolder": "F1"}}]}, "clean rule")):
            for script in (GATE, COPY):
                code, _, _ = run(script, st, tool, ti)
                check(f"{os.path.basename(script)} level 1: {label} passes", code == 0, f"exit={code}")

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

if failed:
    print(f"\n{len(failed)} FAILED: {failed}", file=sys.stderr)
    sys.exit(1)
print("\nAll mail-tool-action tests passed.")
