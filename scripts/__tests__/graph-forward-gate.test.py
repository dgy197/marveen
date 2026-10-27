#!/usr/bin/env python3
"""graph-forward (Brainy 2958, N2): the mail gates on the Graph CLI's `forward`.

What this file proves, on the REAL hooks (subprocesses, hermetic temp stores,
a temp outbox root through GRAPH_MAIL_OUTBOX_DIR, no live DB, log or network):
  - D1/D2 and E2: the Python recipient and message-id validators on the shared
    vectors (scripts/hooks/graph-forward-cases.json), the TypeScript twins run
    the same vectors in src/__tests__/graph-mail-forward*.test.ts;
  - B1-B5 and KA1-KA5: every forward command vector, accepted and refused, at
    level 1, at level 3 and at level 2 with a LIVE standing recipient -- a
    refused one is refused at every level, whatever the list or an approval says;
  - KB1-KB10: the comment-file reader (root, link, FIFO, size, strict UTF-8,
    the closed code-point list), the FIFO under a 5 s timeout;
  - C1-C9 and KC1-KC7: the anchor (by hand and the shared KG7 anchors), the
    extra envelope keys outside it, approval binding to message id, subject,
    comment and recipient, send vs forward, one-shot use, the deny summary
    without the full comment, the standing trace, level 1, and the approval
    helper refusing a forward;
  - B6 and KD1-KD3: the copy gate audits the comment (inline or the whole file,
    through the one reader) and never the forwarded subject.
r3 (Brainy 3092, 3094) adds the graph-mail WHITELIST: every Bash command that mentions
graph-mail is classified first (email_extract.classify_graph_mail) and refused at every level
unless it is the strict CLI form or a read-only head (cat grep head tail wc ls). The shared
vectors are scripts/hooks/graph-mail-grammar-cases.json (198 rows, each through both real
gates at levels 1, 2 with a live standing recipient, and 3), plus: B1 and X1 by name, the
send --body-file reader on the KB vectors, the body file's text as the audited and anchored
text, the import-failure fail-closed branch, and the LF rule.
The send paths are pinned byte for byte by the N0 golden (harness gen_golden.py
--compare, outside the repo); the conformance of the KA6 classifier cases runs in
src/__tests__/send-invocation-conformance.test.ts.

Run: python3 -I <thisfile>   Exit 0 = all pass.
"""
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
HOOKS = os.path.join(REPO, "scripts", "hooks")
GATE = os.path.join(HOOKS, "email-approval-gate.py")
COPY = os.path.join(HOOKS, "outgoing-copy-gate.py")
HELPER = os.path.join(REPO, "scripts", "approval-envelope.py")
PY = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
NOW_S = "CAST(strftime('%s','now') AS INTEGER)"
CLI = "scripts/graph-mail.ts"
MID = "AAMkAGFmZXN0MDEyMzQ1Njc4OQ=="
MID_B = "AAMkAGFmZXN0MDEyMzQ1Njc4OB=="
SUBJ = "Ajánlatkérés: Teszt utca 5."
EM_DASH = chr(0x2014)
# Ports a test must never hand to a gate as its dashboard port (the live dashboard,
# the live CDP browser and the other live loopback services).
FORBIDDEN_PORTS = {3420, 4010, 11434, 18800, 18899, 18997}

with open(os.path.join(HOOKS, "graph-forward-cases.json"), encoding="utf-8") as _fh:
    V = json.load(_fh)

failed = []
passed = [0]


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if not ok and detail else ""))
    if ok:
        passed[0] += 1
    else:
        failed.append(name)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TD = os.path.realpath(tempfile.mkdtemp(prefix="gf-n2-test."))
ROOT = os.path.join(TD, "outbox")
os.mkdir(ROOT, 0o700)
os.chmod(ROOT, 0o700)
os.environ["GRAPH_MAIL_OUTBOX_DIR"] = ROOT
sys.path.insert(0, HOOKS)
EX = load("email_extract_n2", os.path.join(HOOKS, "email_extract.py"))
GATE_MOD = load("email_approval_gate_n2", GATE)


def write(path, data: bytes, mode=0o600):
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)
    return hashlib.sha256(data).hexdigest()


FIXTURE = b"Szia!"  # the KG fixture: {ROOT}/a.txt holds "Szia!", the vectors carry its sha256
FIXTURE_SHA = write(os.path.join(ROOT, "a.txt"), FIXTURE)
write(os.path.join(ROOT, "b.txt"), FIXTURE)
check("KG fixture: sha256 of 'Szia!' is the hex the vectors carry",
      FIXTURE_SHA == "92d1f492eaa9f4b21df5d20eacb1dd1a67047f5d2b63d0c8ee8142d1e528901d")


def fwd_cmd(to="kovacs@fireeng.hu", mid=MID, subj=SUBJ, comment=None, cfile=None, sha=None, runner="npx tsx"):
    src = f"--comment '{comment}'" if comment is not None else f"--comment-file {cfile} --comment-sha256 {sha}"
    return f"{runner} {CLI} forward --id {mid} --to {to} {src} --orig-subject '{subj}'"


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def make_store(name, level=2, standing=(), live=()):
    store = os.path.join(TD, "stores", name)
    os.makedirs(store)
    with open(os.path.join(store, "autonomy-config.json"), "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "categories": [{"key": "email_send", "level": level, "maxLevel": 3}]}, fh)
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
    for addr in live:
        con.execute(
            "INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at,"
            f" resolved_at, resolved_by, content_hash) VALUES (hex(randomblob(6)), 'marveen',"
            f" 'email_standing_recipient', 'elesites', 'approved', {NOW_S}-60, {NOW_S}, 'gazda', ?)",
            (hashlib.sha256(addr.strip().lower().encode("utf-8")).hexdigest(),))
    con.commit()
    con.close()
    if standing:
        with open(os.path.join(store, "email-standing-recipients.json"), "w", encoding="utf-8") as fh:
            json.dump({"recipients": list(standing)}, fh)
    return store


def approve(store, anchor):
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    con.execute(
        "INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at,"
        " resolved_at, resolved_by, content_hash, consumed_at) VALUES (hex(randomblob(6)), 'marveen',"
        f" 'email_send', 'Tovabbitas teszt', 'approved', {NOW_S}-60, {NOW_S}, 'gazda', ?, NULL)", (anchor,))
    con.commit()
    con.close()


def consumed_state(store):
    """consumed_at of every email_send approval row, as a list."""
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    try:
        return [r[0] for r in con.execute("SELECT consumed_at FROM approvals WHERE category='email_send'")]
    finally:
        con.close()


def run(hook, store, payload, extra=None, timeout=30):
    env = dict(os.environ, EMAIL_APPROVAL_GATE_STORE=store, EMAIL_APPROVAL_WINDOW_S="1800",
               OUTGOING_COPY_GATE_RULES=os.path.join(TD, "no-rules", "rules.json"),
               GRAPH_MAIL_OUTBOX_DIR=ROOT, WEB_PORT="9")
    env.update(extra or {})
    assert int(env["WEB_PORT"]) not in FORBIDDEN_PORTS, "a gate may never be pointed at a live port"
    t0 = time.monotonic()
    try:
        p = subprocess.run([PY, "-I", hook], input=json.dumps(payload).encode("utf-8"),
                           capture_output=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timeout", "", "", time.monotonic() - t0
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), time.monotonic() - t0


def gate(store, cmd, extra=None, timeout=30):
    return run(GATE, store, bash(cmd), extra, timeout)[:3]


def copy_gate(cmd, extra=None, timeout=30):
    return run(COPY, os.path.join(TD, "stores"), bash(cmd), extra, timeout)[:3]


def anchor_of(err):
    m = re.search(r"Tartalom-horgony \(sha256; [^)]*\): ([0-9a-f]{64})", err)
    return m.group(1) if m else None


def daily_log_stub(received):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            received.append(json.loads(self.rfile.read(n).decode("utf-8")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    assert srv.server_address[1] not in FORBIDDEN_PORTS
    return srv


print("D1/D2, E2: the Python validators on the shared vectors")
rec = V["recipients"]
check(f"recipients: all {len(rec['accept'])} accepted", all(EX.forward_recipient_ok(a) for a in rec["accept"]))
bad = [a for a in rec["reject"] if EX.forward_recipient_ok(a)]
check(f"recipients: all {len(rec['reject'])} refused", not bad, repr(bad[:3]))
check(f"ids: all {len(V['ids']['accept'])} accepted", all(EX.graph_message_id_ok(i) for i in V["ids"]["accept"]))
bad = [i for i in V["ids"]["reject"] if EX.graph_message_id_ok(i)]
check(f"ids: all {len(V['ids']['reject'])} refused", not bad, repr(bad[:3]))
check("validators refuse non-strings", not EX.forward_recipient_ok(None) and not EX.graph_message_id_ok(5))

print("KA4: the --comment-file path, on the shared vectors")
for c in V["comment_file_paths"]:
    path = c["path"].replace("{ROOT}", ROOT)
    got = "ok" if EX.forward_comment_name(path, ROOT) else "deny"
    check(f"path [{c['expect']}] {c['name']}", got == c["expect"], f"got {got} for {path!r}")
check("KF1: a root string outside ^/[A-Za-z0-9._/-]+$ refuses every path",
      EX.forward_comment_name("/tmp/x y/a.txt", "/tmp/x y") is None
      and EX.forward_comment_name("rel/a.txt", "rel") is None)

print("KB3-KB9: the reader on the shared content vectors")
for i, c in enumerate(V["comment_file_contents"]):
    if "text" in c:
        data = c["text"].encode("utf-8")
    elif "bytes_hex" in c:
        data = bytes.fromhex(c["bytes_hex"])
    else:
        pre = c["prefix_text"].encode("utf-8")
        data = pre + b"a" * (c["total_bytes"] - len(pre))
    if len(data) != c["byte_len"] or hashlib.sha256(data).hexdigest() != c["sha256"]:
        check(f"content vector {c['name']} rebuilds to its byte_len and sha256", False)
        continue
    path = os.path.join(ROOT, f"content-{i}.txt")
    write(path, data)
    text, reason = EX.read_forward_comment_file(path, c["sha256"])
    got = "ok" if reason is None else "deny"
    check(f"content [{c['expect']}] {c['name']}", got == c["expect"], f"got {got}: {reason}")
    if c["expect"] == "ok":
        check(f"  KB9: no normalisation, the text is the bytes ({c['name']})", text.encode("utf-8") == data)
        if "text" in c:
            check(f"  the text equals the vector's text ({c['name']})", text == c["text"])
    else:
        check(f"  the reason does not quote the bytes ({c['name']})",
              not any(len(w) > 3 and w in (reason or "") for w in data.decode("utf-8", "replace").split()))

path = os.path.join(ROOT, "hash.txt")
write(path, "Szia Andi! Ez egy titkos jelölő: KB5MARKER.".encode("utf-8"))
text, reason = EX.read_forward_comment_file(path, FIXTURE_SHA)
check("KB5: a hash mismatch refuses, names both 16-char prefixes and not the content",
      text is None and FIXTURE_SHA[:16] in reason and "KB5MARKER" not in reason, reason)
for bad_hex in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, FIXTURE_SHA + " "):
    text, reason = EX.read_forward_comment_file(os.path.join(ROOT, "a.txt"), bad_hex)
    check(f"KA3: --comment-sha256 {bad_hex[:6]}... ({len(bad_hex)}) refused before reading", text is None)

print("KB1-KB3, KF2: file kinds and the root (the gate under a 5 s timeout)")
L3 = make_store("kinds-l3", level=3)


def kind_case(name, expect, root, cfile, sha=FIXTURE_SHA, timeout=5):
    """The reader in-process, then the real gate and the real copy gate as subprocesses."""
    env_root = {"GRAPH_MAIL_OUTBOX_DIR": root}
    old = os.environ.get("GRAPH_MAIL_OUTBOX_DIR")
    os.environ["GRAPH_MAIL_OUTBOX_DIR"] = root
    try:
        text, reason = EX.read_forward_comment_file(cfile, sha)
    finally:
        os.environ["GRAPH_MAIL_OUTBOX_DIR"] = old
    got = "ok" if reason is None else "deny"
    check(f"kind [{expect}] {name}: the reader", got == expect, f"got {got}: {reason}")
    cmd = fwd_cmd(cfile=cfile, sha=sha)
    code, _, err, secs = run(GATE, L3, bash(cmd), env_root, timeout)
    want = 0 if expect == "ok" else 2
    check(f"kind [{expect}] {name}: the approval gate at level 3 exits {want} within {timeout} s",
          code == want, f"exit={code} {secs:.1f}s err={err[:200]!r}")
    code, _, err, secs = run(COPY, L3, bash(cmd), env_root, timeout)
    check(f"kind [{expect}] {name}: the copy gate exits {want} within {timeout} s",
          code == want, f"exit={code} {secs:.1f}s err={err[:200]!r}")
    return reason


kinds = {c["kind"]: c for c in V["comment_file_kinds"]}
k_root = os.path.join(TD, "kinds")
os.mkdir(k_root)


def fresh_root(tag):
    r = os.path.join(k_root, tag)
    os.mkdir(r, 0o700)
    os.chmod(r, 0o700)
    return r


r = fresh_root("regular")
write(os.path.join(r, "a.txt"), FIXTURE)
kind_case(kinds["regular"]["name"], "ok", r, os.path.join(r, "a.txt"))
r = fresh_root("symlink-in")
write(os.path.join(r, "real.txt"), FIXTURE)
os.symlink(os.path.join(r, "real.txt"), os.path.join(r, "a.txt"))
kind_case(kinds["symlink_inside"]["name"], "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("symlink-out")
write(os.path.join(k_root, "outside.txt"), FIXTURE)
os.symlink(os.path.join(k_root, "outside.txt"), os.path.join(r, "a.txt"))
kind_case(kinds["symlink_outside"]["name"], "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("hardlink")
write(os.path.join(r, "a.txt"), FIXTURE)
os.link(os.path.join(r, "a.txt"), os.path.join(r, "b.txt"))
reason = kind_case(kinds["hardlink"]["name"], "deny", r, os.path.join(r, "a.txt"))
check("  hardlink: the reason names nlink", "nlink=2" in (reason or ""), reason)
r = fresh_root("directory")
os.mkdir(os.path.join(r, "a.txt"))
kind_case(kinds["directory"]["name"], "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("fifo")
subprocess.run(["mkfifo", os.path.join(r, "a.txt")], check=True)
reason = kind_case(kinds["fifo"]["name"], "deny", r, os.path.join(r, "a.txt"), timeout=kinds["fifo"].get("timeout_s", 5))
check("  FIFO: refused as not a regular file (no read was attempted)", "nem rendes fajl" in (reason or ""), reason)
real = fresh_root("root-real")
write(os.path.join(real, "a.txt"), FIXTURE)
link = os.path.join(k_root, "root-link")
os.symlink(real, link)
reason = kind_case(kinds["root_symlink"]["name"], "deny", link, os.path.join(link, "a.txt"))
check("  root symlink: the reason says so", "symlink" in (reason or ""), reason)
r = fresh_root("root-0775")
write(os.path.join(r, "a.txt"), FIXTURE)
os.chmod(r, 0o775)
reason = kind_case(kinds["root_mode_0775"]["name"], "deny", r, os.path.join(r, "a.txt"))
check("  root 0775: the reason names the mode", "0o775" in (reason or ""), reason)
missing = os.path.join(k_root, "root-missing")
reason = kind_case(kinds["root_missing"]["name"], "deny", missing, os.path.join(missing, "a.txt"))
check("  KF2: the reason says the outbox is missing and how to create it",
      "hianyzik" in (reason or "") and "0700" in (reason or ""), reason)
check("  KF2: no gate created the missing root", not os.path.exists(missing))
parent_real = os.path.join(k_root, "parent-real")
os.mkdir(parent_real, 0o700)
inner = os.path.join(parent_real, "outbox")
os.mkdir(inner, 0o700)
write(os.path.join(inner, "a.txt"), FIXTURE)
os.symlink(parent_real, os.path.join(k_root, "parent-link"))
via = os.path.join(k_root, "parent-link", "outbox")
reason = kind_case(kinds["root_under_symlink_parent"]["name"], "deny", via, os.path.join(via, "a.txt"))
check("  symlinked parent: the reason names the realpath", "realpath" in (reason or ""), reason)

print("B1-B5, KA1-KA5: every forward command vector through the real approval gate")
STAND = ("kovacs@fireeng.hu", "kovacs.bela@fireeng.hu")
L1 = make_store("cmds-l1", level=1)
L2S = make_store("cmds-l2-standing", level=2, standing=STAND, live=STAND)
vectors = [("gate_commands", c) for c in V["gate_commands"]] + \
          [("comment_file_gate_commands", c) for c in V["comment_file_gate_commands"]]
for sec, c in vectors:
    cmd = c["cmd"].replace("{ROOT}", ROOT)
    tag = f"[{c['expect']}] {c['rule']} {c['name']}"
    in_proc = EX.parse_forward_command(cmd)[0] is not None and EX.is_forward_invocation(cmd)
    check(f"{sec} {tag}: the parser agrees", in_proc == (c["expect"] == "rules-ok"),
          f"reason={EX.parse_forward_command(cmd)[1]}")
    c3, _, e3 = gate(L3, cmd)
    c2, o2, e2 = gate(L2S, cmd)
    c1, _, e1 = gate(L1, cmd)
    if c["expect"] == "deny":
        check(f"{sec} {tag}: exit 2 at level 3, at level 2 with a live standing recipient, and at level 1",
              (c3, c2, c1) == (2, 2, 2) and "Graph-mail kapu (graph-mail parancs)" in e3,
              f"exits={(c3, c2, c1)} err3={e3[:160]!r}")
    else:
        check(f"{sec} {tag}: level 3 allows, live standing allows with the forward trace, level 1 denies",
              (c3, c2, c1) == (0, 0, 2) and "tovabbitas jovahagyas nelkul" in o2 and "szint 1" in e1,
              f"exits={(c3, c2, c1)} err3={e3[:200]!r} err2={e2[:200]!r}")

print("is_forward_invocation: what is and what is not a forward")
for cmd, want in (
        (fwd_cmd(comment="Szia!"), True),
        (f"bash -c \"{fwd_cmd(comment='Szia!')}\"", True),
        (f"X=1 {fwd_cmd(comment='Szia!')}", True),
        (f"npx tsx {CLI} FORWARD --id {MID}", True),
        (f"npx tsx {CLI} fo''rward --id {MID}", True),
        (f"npx tsx {CLI} $'forward' --id {MID}", True),
        (f"bash <<'EOF'\n{fwd_cmd(comment='Szia!')}\nEOF", True),
        (f"npx tsx {CLI} forward --comment 'unbalanced", True),
        (f"npx tsx {CLI} send --to a@fireeng.hu --subject 'Re' --body 'forward this please'", False),
        ("echo forward", False),
        (f"cat {CLI}", False),
        # GS1/GR2 edges, and r3: the meaning is `kind in (forward, deny)`, so a graph-mail
        # command the whitelist refuses (an operator, a pipe, a wrapper, a head that is not
        # the strict CLI form or one of the read-only six) is "a forward" for the callers too
        (f"npx tsx {CLI} list --top 3; echo forward", True),
        (f"npx tsx {CLI} send --to a@fireeng.hu --subject Re --body x", False),
        (f"npx tsx {CLI} send --to a@fireeng.hu --body x", True),  # no --subject: refused
        (f"npx tsx {CLI} verify", False),
        (f"npx tsx {CLI} show --id {MID}", False),
        (f"npx tsx {CLI}; echo hi", True),
        (f"cat {CLI} | head -3", True),
        (f"git add {CLI} && git commit -m x", True),
        (f"npx tsx {CLI} --top 5 list", True),
        (f"npx tsx {CLI} reply --id {MID}", True),
        (f"echo 'npx tsx {CLI} forward --id {MID}'", True),
        (f"echo 'npx tsx {CLI} forward --id {MID}' | bash", True),
        (f"eval \"npx tsx {CLI} forward --id {MID}\"", True),
        (f"python3 -c \"import os; os.system('npx tsx {CLI} forward')\"", True),
        (f"python3 - <<'PY'\nimport os\nos.system('npx tsx {CLI} forward')\nPY", True),
        (f"env X=1 bash -c \"npx tsx {CLI} fo{{r,r}}ward --id {MID}\"", True)):
    check(f"is_forward_invocation={want}: {cmd[:70]!r}", EX.is_forward_invocation(cmd) == want)

print("GS1, GR2: a verb the shell assembles is a forward; a send that only quotes the forward is a send")
with open(os.path.join(HOOKS, "graph-forward-gs1-cases.json"), encoding="utf-8") as _fh:
    G = json.load(_fh)
L1G = make_store("gs1-l1", level=1)
L3G = make_store("gs1-l3", level=3)
L2G = make_store("gs1-l2-standing", level=2, standing=STAND, live=STAND)
check(f"GS1 vector list is whole ({len(G['gs1'])} forms) and GR2 list is whole ({len(G['gr2'])})",
      len(G["gs1"]) >= 20 and len(G["gr2"]) >= 4)
stub_dir = os.path.join(TD, "stub")
os.mkdir(stub_dir)
stub = os.path.join(stub_dir, "graph-mail.ts")
with open(stub, "w", encoding="utf-8") as fh:
    fh.write('#!/bin/bash\nprintf "argv0=%s\\n" "$1" >> "$STUB_OUT"\n')
os.chmod(stub, 0o700)
write(os.path.join(stub_dir, "forward"), b"")  # a file for the glob forms to match
SHELLS = [s for s in ("/bin/bash", "/bin/zsh") if os.path.exists(s)]
check("the shell proof has bash", "/bin/bash" in SHELLS)
if "/bin/zsh" not in SHELLS:
    print("  [SKIP] /bin/zsh is not present: the zsh proof of the brace form did not run")
for c in G["gs1"]:
    cmd = c["cmd"]
    tag = f"GS1 {c['name']}"
    check(f"{tag}: is_forward_invocation is True", EX.is_forward_invocation(cmd) is True)
    fields, reason = EX.parse_forward_command(cmd)
    check(f"{tag}: the strict reader refuses it (nothing extractable)", fields is None and bool(reason), str(reason))
    env = EX.collect_email_envelope("Bash", {"command": cmd})
    check(f"{tag}: the envelope is a refusal with no forward key and no decoy text",
          env.get("unreadable_reason") and "forward" not in env and env.get("text") == "", repr(env)[:200])
    c3, _, e3 = gate(L3G, cmd)
    c2, _, e2 = gate(L2G, cmd)
    c1, _, e1 = gate(L1G, cmd)
    check(f"{tag}: exit 2 at level 3, level 2 with a live standing recipient, and level 1",
          (c3, c2, c1) == (2, 2, 2) and "Graph-mail kapu (graph-mail parancs)" in e3 and "Graph-mail kapu (graph-mail parancs)" in e2,
          f"exits={(c3, c2, c1)} err3={e3[:160]!r}")
    cc, _, ce = copy_gate(cmd)
    check(f"{tag}: the copy gate blocks it", cc == 2, f"exit={cc} err={ce[:160]!r}")
    if c["argv0"]:
        shell_cmd = cmd.replace("npx tsx scripts/graph-mail.ts", "./graph-mail.ts")
        for sh in SHELLS:
            out_file = os.path.join(TD, "stub-out.txt")
            if os.path.exists(out_file):
                os.remove(out_file)
            subprocess.run([sh, "-c", shell_cmd], cwd=stub_dir, capture_output=True, timeout=20,
                           env=dict(os.environ, STUB_OUT=out_file))
            got = open(out_file, encoding="utf-8").read().strip() if os.path.exists(out_file) else "(CLI not run)"
            check(f"{tag}: {sh} really hands the CLI argv[2] = {c['argv0']}", got == f"argv0={c['argv0']}", got)
for c in G["gr2"]:
    cmd = c["cmd"]
    tag = f"GR2 {c['name']}"
    check(f"{tag}: not a forward invocation", EX.is_forward_invocation(cmd) is False)
    env = EX.collect_email_envelope("Bash", {"command": cmd})
    check(f"{tag}: the send envelope (recipient kovacs, no forward key, readable)",
          env.get("to") == ["kovacs@fireeng.hu"] and "forward" not in env and not env.get("unreadable_reason"), repr(env)[:200])
    c3, _, e3 = gate(L3G, cmd)
    c1, _, e1 = gate(L1G, cmd)
    c2, o2, e2 = gate(L2G, cmd)
    check(f"{tag}: judged as a send (level 3 passes, level 1 denies on the level, standing passes as a send)",
          c3 == 0 and c1 == 2 and "szint 1" in e1 and "Graph-mail kapu (graph-mail parancs)" not in e1
          and c2 == 0 and "tovabbitas jovahagyas nelkul" not in o2, f"exits={(c3, c1, c2)} e1={e1[:160]!r} e2={e2[:160]!r}")
code, _, _ = gate(L3, f"npx tsx {CLI} FORWARD --id {MID} --to kovacs@fireeng.hu --comment 'Szia!' "
                      f"--orig-subject 'T'")
check("an upper-case FORWARD is judged by the forward rules (refused at level 3)", code == 2, f"exit={code}")

print("C1, KC1-KC2, KG7: the anchor")
canon = ('{"cc":[],"forward":{"message_id":"' + MID + '","subject":"' + SUBJ + '"},"text":"Szia!",'
         '"to":["kovacs@fireeng.hu"]}')
by_hand = hashlib.sha256(canon.encode("utf-8")).hexdigest()
env_inline = EX.collect_email_envelope("Bash", {"command": fwd_cmd(comment="Szia!")})
env_file = EX.collect_email_envelope("Bash", {"command": fwd_cmd(cfile=os.path.join(ROOT, "a.txt"), sha=FIXTURE_SHA)})
check("C1: the anchor of an inline forward equals the hand-computed sha256 of the canonical JSON",
      GATE_MOD.content_anchor(env_inline) == by_hand, GATE_MOD.content_anchor(env_inline))
check("KC1: the same text from a file gives the same anchor",
      GATE_MOD.content_anchor(env_file) == by_hand)
check("KC2: the envelope carries comment_source/comment_sha256/comment_file",
      env_file.get("comment_source") == "file" and env_file.get("comment_sha256") == FIXTURE_SHA
      and env_file.get("comment_file") == "a.txt" and env_inline.get("comment_source") == "inline")
twin = dict(env_file, comment_source="inline", comment_sha256="0" * 64, comment_file="x.txt")
check("KC2: envelopes that differ only in those keys have the same anchor",
      GATE_MOD.content_anchor(twin) == GATE_MOD.content_anchor(env_file))
check("E6 probe contract: FORWARD_COMMENT_FILE == 1 and the forward field carries id and subject",
      EX.FORWARD_COMMENT_FILE == 1 and env_inline["forward"] == {"message_id": MID, "subject": SUBJ})
send_env = EX.collect_email_envelope("Bash", {"command": f"npx tsx {CLI} send --to kovacs@fireeng.hu --subject X --body Y"})
check("C2: a send envelope has no forward key", "forward" not in send_env and "comment_source" not in send_env)
for c in V["forward_anchors"]:
    env = {"to": [c["to"]], "cc": [], "bcc": [], "text": c["text"],
           "forward": {"message_id": c["id"], "subject": c["subject"]}}
    check(f"KG7 {c['name']}: content_anchor equals the vector's anchor", GATE_MOD.content_anchor(env) == c["anchor"])
L2 = make_store("anchor-l2", level=2)
for c in V["forward_anchors"]:
    data = c["text"].encode("utf-8")
    name = "kg7-" + hashlib.sha256(c["name"].encode()).hexdigest()[:8] + ".txt"
    sha = write(os.path.join(ROOT, name), data)
    code, _, err = gate(L2, fwd_cmd(to=c["to"], mid=c["id"], subj=c["subject"], cfile=os.path.join(ROOT, name), sha=sha))
    check(f"KG7 {c['name']}: the real gate's level-2 deny carries the same anchor (file form)",
          code == 2 and anchor_of(err) == c["anchor"], f"exit={code} anchor={anchor_of(err)}")
    if "'" not in c["text"] and c["source"] == "inline":
        code, _, err = gate(L2, fwd_cmd(to=c["to"], mid=c["id"], subj=c["subject"], comment=c["text"]))
        check(f"KG7 {c['name']}: and so does the inline form", code == 2 and anchor_of(err) == c["anchor"])

print("C3-C6, KC4, KC6: approvals bind to the exact forward; the deny summary")
store = make_store("c3", level=2)
cmd_a = fwd_cmd(comment="Szia Andi! Kérlek, nézd meg.")
code, _, err = gate(store, cmd_a)
anchor_a = anchor_of(err)
check("C6: an unapproved forward is denied with its anchor and the forwarded letter in the summary",
      code == 2 and anchor_a and f"Tovabbitott level: {SUBJ} | id: {MID[:16]}..." in err
      and "NINCS jovahagyas" in err and "A jovahagyast a CLI fogyasztja el" in err, err[:400])
check("C6: the anchor line names what a forward's anchor covers", "tovabbitott level azonositoja es targya" in err)
approve(store, anchor_a)
for label, cmd in (("another message id", fwd_cmd(mid=MID_B, comment="Szia Andi! Kérlek, nézd meg.")),
                   ("another subject", fwd_cmd(subj=SUBJ + " ", comment="Szia Andi! Kérlek, nézd meg.")),
                   ("another comment", fwd_cmd(comment="Szia Andi! Kérlek, nézd meg!")),
                   ("another recipient", fwd_cmd(to="nagy@fireeng.hu", comment="Szia Andi! Kérlek, nézd meg.")),
                   ("a send with the same recipient and text",
                    f"npx tsx {CLI} send --to kovacs@fireeng.hu --subject Teszt --body 'Szia Andi! Kérlek, nézd meg.'")):
    code, _, err = gate(store, cmd)
    check(f"C3/C4: the approval of forward A does not authorise {label} (verdict none)",
          code == 2 and "NINCS jovahagyas" in err, f"exit={code} err={err[:160]!r}")
code, out, err = gate(store, cmd_a)
check("C3: the approved forward itself passes (cli-send-enforce: the hook only peeks)",
      code == 0 and "megvan" in out, err[:200])
check("C3: and the hook did NOT consume the approval", consumed_state(store) == [None])
code, out, err = gate(store, cmd_a)
check("C5: the same forward again still passes the hook: the CLI is the one consumer",
      code == 0 and "megvan" in out and consumed_state(store) == [None], err[:200])

store = make_store("c4", level=2)
send = f"npx tsx {CLI} send --to kovacs@fireeng.hu --subject Teszt --body 'Szia Andi! Kérlek, nézd meg.'"
code, _, err = gate(store, send)
check("C4: the send's own deny has its (send) anchor", code == 2 and anchor_of(err), err[:200])
approve(store, anchor_of(err))
code, _, err = gate(store, cmd_a)
check("C4: a send approval with the same recipient and text does not authorise the forward",
      code == 2 and "NINCS jovahagyas" in err, err[:200])

store = make_store("kc6", level=2)
kc6 = os.path.join(ROOT, "kc6.txt")
sha6 = write(kc6, "Szia Andi!\nKérlek, nézd meg.\n".encode("utf-8"))
code, _, err = gate(store, fwd_cmd(cfile=kc6, sha=sha6))
approve(store, anchor_of(err))
kc6b = os.path.join(ROOT, "kc6b.txt")
sha6b = write(kc6b, "Szia Andi!\nKérlek, nézd meg!\n".encode("utf-8"))
code, _, err = gate(store, fwd_cmd(cfile=kc6b, sha=sha6b))
check("KC6: one byte changed in the file (new hash) is another forward, not approved", code == 2 and "NINCS" in err)
code, _, err = gate(store, fwd_cmd(cfile=kc6, sha=sha6))
check("KC6: the approved file forward passes (peek)", code == 0, err[:200])
code, _, err = gate(store, fwd_cmd(cfile=kc6, sha=sha6))
check("KC6: and is not consumed by the hook", code == 0 and consumed_state(store) == [None], err[:200])

marker = "KC4JELOLO"
long_text = ("Szia Andi! Gyuri most úton van, ezért továbbítom neked ezt a levelet. " * 4)[:230] + marker + " vége.\n"
assert long_text.index(marker) > 200
lp = os.path.join(ROOT, "kc4.txt")
lsha = write(lp, long_text.encode("utf-8"))
store = make_store("kc4", level=2)
for label, cmd in (("file", fwd_cmd(cfile=lp, sha=lsha)), ("inline", fwd_cmd(comment=long_text.rstrip("\n")))):
    code, _, err = gate(store, cmd)
    check(f"KC4 ({label}): the deny never shows the comment past its first 120 characters",
          code == 2 and marker not in err and "Szoveg eleje: Szia Andi!" in err, err[:300])
    shown = "fajl kc4.txt" if label == "file" else "inline"
    text = long_text if label == "file" else long_text.rstrip("\n")
    sha = lsha if label == "file" else hashlib.sha256(text.encode("utf-8")).hexdigest()
    check(f"KC4 ({label}): the summary names the source, the sha256 prefix, the length and the lines",
          f"Komment: {shown} | sha256: {sha[:16]} | {len(text)} karakter, 1 sor | Szoveg eleje:" in err, err[:500])

print("C7, KC5: the standing path for a forward, and its trace")
received = []
srv = daily_log_stub(received)
port = str(srv.server_address[1])
store = make_store("kc5", level=2, standing=("kovacs@fireeng.hu",), live=("kovacs@fireeng.hu",))
with open(os.path.join(store, ".dashboard-token"), "w") as fh:
    fh.write("test-token-not-a-secret")
ftext = "Szia Kovács!\nGyuri most úton van, kérlek, nézd meg.\n"
fp = os.path.join(ROOT, "kc5.txt")
fsha = write(fp, ftext.encode("utf-8"))
icomment = "Szia Kovács! Kérlek, nézd meg."
for src, cmd, text, sha in (
        ("file", fwd_cmd(cfile=fp, sha=fsha), ftext, fsha),
        ("inline", fwd_cmd(comment=icomment), icomment, hashlib.sha256(icomment.encode("utf-8")).hexdigest())):
    before = len(received)
    code, out, err = gate(store, cmd, {"WEB_PORT": port})
    check(f"C7 ({src}): a live standing recipient lets the forward through", code == 0 and "tovabbitas" in out, err[:200])
    check(f"KC5 ({src}): the hook leaves NO trace (the CLI authorizer writes it, once)",
          not os.path.exists(os.path.join(store, "email-standing-sends.log")) and len(received) == before
          and "a CLI irja" in out, out[:200])
srv.shutdown()
store = make_store("c7-notlive", level=2, standing=("kovacs@fireeng.hu",))
code, _, err = gate(store, fwd_cmd(comment="Szia! Kérlek, nézd meg."))
check("C7: a standing but NOT live recipient does not let the forward through", code == 2 and "NINCS ELESITVE" in err, err[:200])

print("C8, C9: level 1; the approval helper refuses a forward")
code, _, err = gate(L1, fwd_cmd(comment="Szia! Kérlek, nézd meg."))
check("C8: level 1 denies a valid forward", code == 2 and "szint 1" in err)
# The helper exists only where the approval-envelope local patch is applied (live tree);
# develop does not ship it. A missing file must not read as a pass: python -I on it exits
# 2 with an empty stdout, which is exactly what the check below expects.
if not os.path.exists(HELPER):
    print("  [SKIP] C9/KC7: scripts/approval-envelope.py not present in this tree (live-tree-only helper)")
else:
    for label, cmd in (("inline", fwd_cmd(comment="Szia! Kérlek, nézd meg.")),
                       ("file", fwd_cmd(cfile=os.path.join(ROOT, "a.txt"), sha=FIXTURE_SHA))):
        p = subprocess.run([PY, "-I", HELPER, "--agent", "brainy"], input=json.dumps(bash(cmd)).encode("utf-8"),
                           capture_output=True, env=dict(os.environ, GRAPH_MAIL_OUTBOX_DIR=ROOT), timeout=30)
        check(f"C9/KC7 ({label}): approval-envelope.py exits 2 with an empty stdout on a forward",
              p.returncode == 2 and p.stdout == b"", f"exit={p.returncode} out={p.stdout[:120]!r}")

print("B6, KD1-KD3: the copy gate")
for c in V["copy_gate"]:
    code, _, err = copy_gate(c["cmd"])
    want = 0 if c["expect"] == "pass" else 2
    check(f"copy_gate [{c['expect']}] {c['name']}", code == want, f"exit={code} err={err[:200]!r}")
for i, c in enumerate(V["comment_file_copy_gate"]):
    r = fresh_root(f"kd-{i}")
    sha = write(os.path.join(r, "a.txt"), c["text"].encode("utf-8"))
    cmd = c["cmd"].replace("{ROOT}", r)
    if sha not in cmd:
        check(f"comment_file_copy_gate {c['name']}: the vector's hash matches its text", False)
        continue
    code, _, err = copy_gate(cmd, {"GRAPH_MAIL_OUTBOX_DIR": r})
    want = 0 if c["expect"] == "pass" else 2
    check(f"comment_file_copy_gate [{c['expect']}] {c['name']}", code == want, f"exit={code} err={err[:200]!r}")
text, reason = EX.collect_bash_body(fwd_cmd(cfile=os.path.join(ROOT, "kc5.txt"), sha=fsha))
check("KD2: collect_bash_body on a file forward is exactly the file's text", reason is None and text == ftext)
text, reason = EX.collect_bash_body(fwd_cmd(comment="Szia!") + " < /etc/hosts")
check("KD2: a forward's `<` is a refusal, the general branches never read the path",
      text == "" and reason and "hosts" not in reason and "localhost" not in text, reason)
code, _, err = copy_gate(fwd_cmd(cfile=os.path.join(ROOT, "kc5.txt"), sha=FIXTURE_SHA))
check("KD1: a hash mismatch blocks on the copy gate, with the reader's reason (r3: the grammar reads the file, "
      "so an unreadable comment file is a refusal of the command itself)",
      code == 2 and "TILTVA" in err and "sha256" in err, err[:200])
ok_comment = "Szia Andi! Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm!"
code, _, err = copy_gate(fwd_cmd(comment=ok_comment, subj=f"Tovabbitas {EM_DASH} surgos -- level"))
check("B6: an em dash and an accentless word in the forwarded subject do not block", code == 0, err[:200])
emd = os.path.join(ROOT, "emd.txt")
sha = write(emd, f"Szia Andi! Gyuri most úton van {EM_DASH} kérlek, nézd meg.\n".encode("utf-8"))
code, _, err = copy_gate(fwd_cmd(cfile=emd, sha=sha))
check("KD1: an em dash in the file blocks", code == 2 and "GONDOLATJEL" in err, err[:200])

print("r3 (Brainy 3092, 3094): the graph-mail whitelist, every vector through the real hooks")
MARK = "Graph-mail kapu (graph-mail parancs)"
with open(os.path.join(HOOKS, "graph-mail-grammar-cases.json"), encoding="utf-8") as _fh:
    GM = json.load(_fh)
by_kind = {}
for c in GM["cases"]:
    by_kind[c["expect"]] = by_kind.get(c["expect"], 0) + 1
check(f"grammar vector list is whole ({len(GM['cases'])} rows: {by_kind})",
      len(GM["cases"]) >= 190 and all(by_kind.get(k, 0) >= 3 for k in ("deny", "read", "send", "forward", "none"))
      and by_kind["deny"] >= 120)
WL_STAND = ("kovacs@fireeng.hu", "a@fireeng.hu")
WL1 = make_store("wl-l1", level=1)
WL3 = make_store("wl-l3", level=3)
WL2 = make_store("wl-l2-standing", level=2, standing=WL_STAND, live=WL_STAND)
for c in GM["cases"]:
    cmd = c["cmd"].replace("{ROOT}", ROOT).replace("{REPO}", REPO)
    tag = f"[{c['expect']}{'/' + c['gate'] if c.get('gate') else ''}] {c['rule']} {c['name']}"
    kind, _fields, why = EX.classify_graph_mail(cmd)
    check(f"grammar {tag}: classify_graph_mail says {c['expect']}", kind == c["expect"], f"got {kind}: {why}")
    check(f"grammar {tag}: is_forward_invocation = (kind in forward, deny)",
          EX.is_forward_invocation(cmd) == (kind in ("forward", "deny")))
    if c["expect"] == "none":
        continue
    c3, _, e3 = gate(WL3, cmd)
    c2, o2, e2 = gate(WL2, cmd)
    c1, _, e1 = gate(WL1, cmd)
    cc, _, ce = copy_gate(cmd)
    if c["expect"] == "deny":
        check(f"grammar {tag}: denied at level 3, at level 2 with a live standing recipient, and at level 1; the copy gate blocks it",
              (c3, c2, c1, cc) == (2, 2, 2, 2) and "TILTVA" in ce
              and ((MARK in e3 and MARK in e2 and MARK in e1 and "nem egyetlen, szigoru alaku parancs" in ce)
                   or ("script-ut" in e3 and "script-ut" in e2 and "script-ut" in e1 and "script-ut" in ce)),  # B4 runs first
              f"exits={(c3, c2, c1, cc)} e3={e3[:200]!r} ce={ce[:120]!r}")
        check(f"grammar {tag}: no envelope is built for it",
              EX.collect_email_envelope("Bash", {"command": cmd}).get("unreadable_reason") is not None)
    elif c["expect"] == "read":
        check(f"grammar {tag}: both gates let it through at every level",
              (c3, c2, c1, cc) == (0, 0, 0, 0), f"exits={(c3, c2, c1, cc)} e1={e1[:160]!r} ce={ce[:160]!r}")
    elif c.get("gate") == "deny":
        check(f"grammar {tag}: the grammar passes it, level 2 and the copy gate refuse on reading the file",
              c2 == 2 and "nem horgonyozhato" in e2 and MARK not in e2 and cc == 2 and "nem tudtam megvizsgalni" in ce,
              f"c2={c2} e2={e2[:200]!r} cc={cc} ce={ce[:160]!r}")
    else:
        check(f"grammar {tag}: goes on to the level flow (level 3 passes, level 1 denies on the LEVEL), the copy gate audits it clean",
              c3 == 0 and c1 == 2 and "szint 1" in e1 and MARK not in e1 and cc == 0,
              f"exits={(c3, c1, cc)} e1={e1[:160]!r} ce={ce[:200]!r}")

print("r3: B1 and X1 pinned by name, and the golden-run bypasses never reach a standing recipient")
b1 = next(c for c in GM["cases"] if c["rule"] == "B1")["cmd"]
check("B1 is the exact comment-hidden forward: a quote opened in a comment line, the forward on the next line",
      b1.startswith("# --body decoy '\n") and b1.endswith("\n# '") and "forward --id" in b1 and "kovacs@fireeng.hu" in b1)
check("B1 and X1 are denied by both gates",
      all(gate(WL2, c["cmd"])[0] == 2 and copy_gate(c["cmd"])[0] == 2 for c in GM["cases"] if c["rule"] in ("B1", "X1")))

print("r3 B3/Q2/B4 (Brainy): reader head pinned, CLI path pinned, glob or quote in a script path denied by both gates")
check("Q2: the repo-absolute CLI path is derived from the hook file's place and passes",
      EX.classify_graph_mail(f"npx tsx {REPO}/scripts/graph-mail.ts list")[0] == "read"
      and EX.classify_graph_mail(f"tsx {REPO}/scripts/graph-mail.ts show --id {MID}")[0] == "read",
      REPO)
check("Q2: another repo-absolute-looking path is denied",
      EX.classify_graph_mail("npx tsx /Users/x/other/scripts/graph-mail.ts list")[0] == "deny"
      and EX.classify_graph_mail(f"npx tsx {REPO}/x/scripts/graph-mail.ts list")[0] == "deny")
B4_DENY = [
    "npx tsx scripts/graph-mai?.ts send --to evil@evil.com --subject s --body b",
    "npx tsx scripts/gr*.ts send --to evil@evil.com --subject s --body b",
    "npx tsx scripts/*-mail.ts send --to evil@evil.com --subject s --body b",
    "npx tsx scripts/graph-mai?.ts forward --id X --to evil@evil.com --comment c --orig-subject t",
    "tsx 'scripts/graph-mail.ts' send --to evil@evil.com --subject s --body b",
    'tsx "scripts/graph-mail.ts" list',
    "node scripts/gr[a]ph-mail.ts",
    "npx tsx scripts/graph-mai{l,}.ts send --to evil@evil.com --subject s --body b",
    "/usr/local/bin/tsx scripts/g*.ts list",
    "bun scripts/g*.mts list",
    "deno run scripts/g?.cjs",
    "node scripts/$X.js",
    "node scripts/g\\raph.mjs",
    "A=1 npx tsx scripts/g*.ts list",
    "npx tsx scripts/other?.ts --x y",  # not keyed on the name or the verb
]
B4_OK = [
    "npx tsx scripts/graph-mail.ts list",
    "npx tsx scripts/graph-mail.ts verify",
    "npx tsx scripts/other.ts --x y",
    "node -e console.log(1)",
    "node scripts/plain.js --flag",
    "ls scripts/*.ts",  # the head is not a script runner
    "echo scripts/g*.ts",
]
for cmd in B4_DENY:
    r = EX.script_path_meta_reason(cmd)
    check(f"B4 shared function denies: {cmd[:70]}", bool(r), "no reason")
    c3, _, e3 = gate(WL3, cmd)
    c2, _, e2 = gate(WL2, cmd)
    c1, _, e1 = gate(WL1, cmd)
    cc, _, ce = copy_gate(cmd)
    check(f"B4 both gates exit 2 at level 3, level 2 (live standing recipient), level 1 and in the copy gate: {cmd[:60]}",
          (c3, c2, c1, cc) == (2, 2, 2, 2) and "script-ut" in e3 and "script-ut" in e2 and "script-ut" in e1
          and "script-ut" in ce, f"exits={(c3, c2, c1, cc)} e3={e3[:160]!r} ce={ce[:160]!r}")
for cmd in B4_OK:
    check(f"B4 leaves it alone: {cmd[:60]}", EX.script_path_meta_reason(cmd) is None)
for cmd in ("npx tsx scripts/graph-mail.ts list", "npx tsx scripts/other.ts --x y", "node -e console.log(1)"):
    c3, _, e3 = gate(WL3, cmd)
    cc, _, ce = copy_gate(cmd)
    check(f"B4 does not change the old verdict for: {cmd}", (c3, cc) == (0, 0), f"exits={(c3, cc)} e3={e3[:120]!r}")
print("r3: send --body-file is read by the ONE strict reader (same rules as the comment file), on the shared vectors")
for i, c in enumerate(V["comment_file_contents"]):
    if "text" in c:
        data = c["text"].encode("utf-8")
    elif "bytes_hex" in c:
        data = bytes.fromhex(c["bytes_hex"])
    else:
        pre = c["prefix_text"].encode("utf-8")
        data = pre + b"a" * (c["total_bytes"] - len(pre))
    path = os.path.join(ROOT, f"body-{i}.txt")
    write(path, data)
    t_body, r_body = EX.read_graph_body_file(path, c["sha256"])
    t_comm, r_comm = EX.read_forward_comment_file(path, c["sha256"])
    check(f"body-file content [{c['expect']}] {c['name']}: same verdict as the comment file",
          (r_body is None) == (c["expect"] == "ok") and (r_body is None) == (r_comm is None) and t_body == t_comm,
          f"body={r_body} comment={r_comm}")
    if r_body:
        check(f"  the body-file reason says torzs-fajl and --body-sha256 where it names them ({c['name']})",
              "komment" not in r_body and "--comment" not in r_body, r_body)
for c in V["comment_file_paths"]:
    path = c["path"].replace("{ROOT}", ROOT)
    cmd = f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {path} --body-sha256 {FIXTURE_SHA}"
    got = EX.classify_graph_mail(cmd)[0]
    if re.fullmatch(r"[A-Za-z0-9._/@+=,:%-]+", path):
        check(f"body-file path [{c['expect']}] {c['name']}: the same shape rule as --comment-file",
              got == ("send" if c["expect"] == "ok" else "deny"), f"got {got}")


def body_kind_case(name, expect, root, cfile, sha=FIXTURE_SHA, timeout=5):
    """The strict reader in-process, then the copy gate and level 2 (live standing recipient) as subprocesses."""
    old = os.environ.get("GRAPH_MAIL_OUTBOX_DIR")
    os.environ["GRAPH_MAIL_OUTBOX_DIR"] = root
    try:
        text, reason = EX.read_graph_body_file(cfile, sha)
    finally:
        os.environ["GRAPH_MAIL_OUTBOX_DIR"] = old
    got = "ok" if reason is None else "deny"
    check(f"body-file kind [{expect}] {name}: the reader", got == expect, f"got {got}: {reason}")
    cmd = f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {cfile} --body-sha256 {sha}"
    want = 0 if expect == "ok" else 2
    code, _, err, secs = run(COPY, WL3, bash(cmd), {"GRAPH_MAIL_OUTBOX_DIR": root}, timeout)
    check(f"body-file kind [{expect}] {name}: the copy gate exits {want} within {timeout} s", code == want,
          f"exit={code} {secs:.1f}s err={err[:200]!r}")
    code, _, err, secs = run(GATE, WL2, bash(cmd), {"GRAPH_MAIL_OUTBOX_DIR": root}, timeout)
    check(f"body-file kind [{expect}] {name}: level 2 with a live standing recipient exits {want} within {timeout} s",
          code == want, f"exit={code} {secs:.1f}s err={err[:200]!r}")
    return reason


r = fresh_root("body-regular")
write(os.path.join(r, "a.txt"), FIXTURE)
body_kind_case("regular file", "ok", r, os.path.join(r, "a.txt"))
r = fresh_root("body-symlink-in")
write(os.path.join(r, "real.txt"), FIXTURE)
os.symlink(os.path.join(r, "real.txt"), os.path.join(r, "a.txt"))
body_kind_case("symlink inside the outbox", "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("body-symlink-out")
write(os.path.join(k_root, "outside-body.txt"), FIXTURE)
os.symlink(os.path.join(k_root, "outside-body.txt"), os.path.join(r, "a.txt"))
body_kind_case("symlink to a file outside", "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("body-hardlink")
write(os.path.join(r, "a.txt"), FIXTURE)
os.link(os.path.join(r, "a.txt"), os.path.join(r, "b.txt"))
reason = body_kind_case("hard-linked file", "deny", r, os.path.join(r, "a.txt"))
check("  hardlink: the reason names nlink", "nlink=2" in (reason or ""), reason)
r = fresh_root("body-directory")
os.mkdir(os.path.join(r, "a.txt"))
body_kind_case("a directory", "deny", r, os.path.join(r, "a.txt"))
r = fresh_root("body-fifo")
subprocess.run(["mkfifo", os.path.join(r, "a.txt")], check=True)
reason = body_kind_case("FIFO (no read is attempted)", "deny", r, os.path.join(r, "a.txt"))
check("  FIFO: refused as not a regular file", "nem rendes fajl" in (reason or ""), reason)
r = fresh_root("body-0775")
write(os.path.join(r, "a.txt"), FIXTURE)
os.chmod(r, 0o775)
body_kind_case("group-writable outbox root", "deny", r, os.path.join(r, "a.txt"))
body_kind_case("missing outbox root", "deny", os.path.join(k_root, "body-root-missing"),
               os.path.join(k_root, "body-root-missing", "a.txt"))

print("r3: the body-file text is what is audited and anchored; the lax JSON reader never runs on a graph-mail command")
bf_inline = EX.collect_email_envelope("Bash", {"command": f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body 'Szia!'"})
bf_file = EX.collect_email_envelope("Bash", {"command": f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt "
                                                         f"--body-file {os.path.join(ROOT, 'a.txt')} --body-sha256 {FIXTURE_SHA}"})
check("the envelope of a body-file send is the subject and the file text, LF-joined, in command order",
      bf_file["text"] == "Teszt\nSzia!" and bf_file["to"] == ["a@fireeng.hu"] and not bf_file["unreadable_reason"], repr(bf_file))
check("KC1 analogue: the same text inline and from a file gives the same anchor",
      GATE_MOD.content_anchor(bf_file) == GATE_MOD.content_anchor(bf_inline))
json_text = '{"body": "ez nem a levél", "subject": "masik"}'
jp = os.path.join(ROOT, "json-body.txt")
jsha = write(jp, json_text.encode("utf-8"))
jenv = EX.collect_email_envelope("Bash", {"command": f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {jp} --body-sha256 {jsha}"})
check("a JSON body file is the raw text, never the decoded 'body' field of the wget-style lax reader",
      jenv["text"] == "Teszt\n" + json_text and not jenv["unreadable_reason"], repr(jenv)[:200])
jenv_wrong = EX.collect_email_envelope("Bash", {"command": f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {jp} --body-sha256 {'0' * 64}"})
check("a wrong --body-sha256 is an unreadable letter on the envelope path", bool(jenv_wrong["unreadable_reason"]) and jenv_wrong["text"] != "Teszt\n" + json_text)
long_body = ("Szia Andi! " * 2000)[:9000]
lp2 = os.path.join(ROOT, "long-body.txt")
lsha2 = write(lp2, long_body.encode("utf-8"))
code, _, err = gate(make_store("wl-body-l2", level=2), f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {lsha2}")
check("level 2 with no approval: the deny carries the anchor of subject + file text", code == 2 and anchor_of(err), err[:200])
store = make_store("wl-body-approved", level=2)
code, _, err = gate(store, f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {lsha2}")
approve(store, anchor_of(err))
code, out, err = gate(store, f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {lsha2}")
check("the approved body-file send passes (peek)", code == 0 and "megvan" in out, err[:200])
code, _, err = gate(store, f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {lsha2}")
check("and is not consumed by the hook", code == 0 and consumed_state(store) == [None], err[:200])
changed = long_body[:-1] + "!"
sha_changed = write(lp2, changed.encode("utf-8"))
code, _, err = gate(store, f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {sha_changed}")
check("a changed file (new hash) is another letter: not approved", code == 2 and "NINCS jovahagyas" in err)
code, _, err = gate(store, f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {lp2} --body-sha256 {lsha2}")
check("the old hash against the changed file is refused on reading", code == 2 and "sha256" in err and "nem horgonyozhato" in err, err[:200])
emd_body = os.path.join(ROOT, "emd-body.txt")
emd_sha = write(emd_body, f"Szia Andi! Kérlek {EM_DASH} nézd meg.\n".encode("utf-8"))
code, _, err = copy_gate(f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {emd_body} --body-sha256 {emd_sha}")
check("the copy gate audits the body FILE text (an em dash in the file blocks)", code == 2 and "GONDOLATJEL" in err, err[:200])
ok_body = os.path.join(ROOT, "ok-body.txt")
ok_sha = write(ok_body, "Szia Andi! Kérlek, nézd meg.\n".encode("utf-8"))
code, _, err = copy_gate(f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body-file {ok_body} --body-sha256 {ok_sha}")
check("and a clean body file passes the copy gate", code == 0, err[:200])

print("r3: an extractor that does not load is a deny for a graph-mail mention (fail-closed), and only for a mention")
broken = os.path.join(TD, "broken-hooks")
os.mkdir(broken)
for name in ("email-approval-gate.py", "outgoing-copy-gate.py"):
    with open(os.path.join(HOOKS, name), "rb") as src_fh, open(os.path.join(broken, name), "wb") as dst_fh:
        dst_fh.write(src_fh.read())
with open(os.path.join(broken, "email_extract.py"), "w", encoding="utf-8") as fh:
    fh.write("def broken(:\n")
for label, hook in (("approval gate", os.path.join(broken, "email-approval-gate.py")),
                    ("copy gate", os.path.join(broken, "outgoing-copy-gate.py"))):
    for cmd in (f"npx tsx {CLI} verify", f"cat {CLI}", f"npx tsx {CLI} list --top 3",
                f"npx tsx {CLI} send --to a@fireeng.hu --subject Teszt --body Szia", f"ls -la; echo graph-mail",
                "cat scripts/GRAPH-MAIL.ts"):  # the upper-case mention is a mention too (case-blind test in the stub)
        code, _, err, _ = run(hook, WL3, bash(cmd))
        check(f"broken extractor, {label}: {cmd[:56]!r} is denied", code == 2 and "TILTVA" in err, f"exit={code} err={err[:200]!r}")
    code, _, err, _ = run(hook, WL3, bash("echo hello"))
    check(f"broken extractor, {label}: a command that does not mention graph-mail is not affected", code == 0, f"exit={code} err={err[:200]!r}")
    # B4: a script-runner command naming a script file is refused too (no mention needed), a non-runner is not
    code, _, err, _ = run(hook, WL3, bash("npx tsx scripts/graph-mai?.ts list"))
    check(f"broken extractor, {label}: B4 refuses a script-runner command with a glob in the script path", code == 2, f"exit={code} err={err[:200]!r}")
    code, _, err, _ = run(hook, WL3, bash("echo scripts/graph-mai?.ts"))
    check(f"broken extractor, {label}: B4 fallback leaves a non-runner command alone", code == 0, f"exit={code} err={err[:200]!r}")

print("r3: the strict forward reader no longer takes a newline, in either form")
lf_inline = fwd_cmd(comment="Szia!\nMasik sor.")
check("an inline comment with an LF is refused by the strict reader, the grammar and both gates",
      EX.parse_forward_command(lf_inline)[0] is None and EX.classify_graph_mail(lf_inline)[0] == "deny"
      and gate(WL3, lf_inline)[0] == 2 and gate(WL2, lf_inline)[0] == 2 and copy_gate(lf_inline)[0] == 2)
lf_file = os.path.join(ROOT, "lf-comment.txt")
lf_sha = write(lf_file, "Szia Andi!\nMasik sor.\n".encode("utf-8"))
check("a MULTI-LINE comment FILE is still fine (the LF is in the file, not in the command)",
      EX.classify_graph_mail(fwd_cmd(cfile=lf_file, sha=lf_sha))[0] == "forward")

print()
print(f"{passed[0]} passed, {len(failed)} failed")
if failed:
    print(f"{len(failed)} FAILED: {failed}", file=sys.stderr)
    sys.exit(1)
print("All graph-forward-gate tests passed.")
