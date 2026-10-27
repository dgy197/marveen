#!/usr/bin/env python3
"""cli-send-enforce N1 + N3: the CLI-side authorizer (scripts/hooks/email_send_authorize.py)
and the hook's graph-mail branch, which only PEEKS.

N1 -- the authorizer decides on a temp DB, never the live store:
  allow / none / pending / consumed / expired; strictly single use; several parallel
  PROCESSES on one approval give exactly one allow; peek writes nothing; level 1/2/3;
  a missing/corrupt config is level 1; a missing/locked/incomplete DB, a bad window and a
  corrupt standing file fail closed; the standing list (live or not, trace written once, an
  unwritable trace refuses); a failing copy QA does not consume; paths cannot be moved by
  the environment (EMAIL_APPROVAL_GATE_STORE is ignored by the stdin/stdout entry point).
N3 -- the hook on a graph-mail send: allowed against an approved row, consumed_at stays NULL,
  no standing trace; the MCP send_email path still consumes.

Test isolation: temp DB/store only (never store/, the dashboard, the Vault or the keychain);
WEB_PORT=1 and an own loopback stub for the daily-log POST; an in-process socket guard
refuses every non-loopback connect and the live ports 18800/18899 BEFORE connect() (self-tested
below). Test-only path injection: the tests call email_send_authorize.run(req, paths=...) or
set the module's _ROOT; the production stdin/stdout entry point has neither.

Run: python3 <thisfile>   Exit 0 = all pass.
"""
import hashlib
import importlib.util
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(os.path.dirname(HERE), "hooks")
GATE = os.path.join(HOOKS, "email-approval-gate.py")
HELPER = os.path.join(HOOKS, "email_send_authorize.py")
PY = sys.executable
FORBIDDEN_PORTS = (18800, 18899)
NOW_S = "CAST(strftime('%s','now') AS INTEGER)"

TD = tempfile.mkdtemp(prefix="send-authorize-test.")
os.environ["WEB_PORT"] = "1"
os.environ["OUTGOING_COPY_GATE_RULES"] = os.path.join(TD, "no-rules.json")
os.environ.pop("EMAIL_APPROVAL_GATE_STORE", None)
os.environ.pop("EMAIL_APPROVAL_WINDOW_S", None)

failed = []
passed = 0


def check(name, ok, detail=""):
    global passed
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if not ok and detail else ""))
    if ok:
        passed += 1
    else:
        failed.append(name)


# --- loopback-only socket guard (in-process), self-tested -------------------
_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host, port = address[0], address[1]
    if host not in ("127.0.0.1", "::1", "localhost") or int(port) in FORBIDDEN_PORTS:
        raise PermissionError(f"socket guard: connect to {address!r} refused")
    return _real_connect(self, address)


socket.socket.connect = _guarded_connect
for banned in (("192.0.2.1", 80), ("127.0.0.1", 18800), ("127.0.0.1", 18899)):
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(banned)
        check(f"socket guard refuses {banned}", False, "connect went through")
    except PermissionError:
        check(f"socket guard refuses {banned}", True)
    except OSError as exc:
        check(f"socket guard refuses {banned}", False, repr(exc))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


H = load(HELPER, "email_send_authorize_under_test")

_n = [0]


def make_store(level=2, config="ok", schema="full", standing=None, live=(), max_level=None):
    _n[0] += 1
    store = os.path.join(TD, f"s{_n[0]}")
    os.makedirs(store)
    cfg = os.path.join(store, "autonomy-config.json")
    if config == "ok":
        cat = {"key": "email_send", "level": level}
        if max_level is not None:
            cat["maxLevel"] = max_level
        with open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "categories": [cat]}, fh)
    elif config == "corrupt":
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write("{not json")
    elif config == "nocategory":
        with open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "categories": []}, fh)
    if schema != "nodb":
        con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
        cols = ["id TEXT PRIMARY KEY", "agent_id TEXT", "category TEXT NOT NULL",
                "action_description TEXT", "status TEXT NOT NULL DEFAULT 'pending'",
                "requested_at INTEGER", "resolved_at INTEGER", "resolved_by TEXT"]
        if schema != "nohash":
            cols.append("content_hash TEXT")
        if schema != "noconsumed":
            cols.append("consumed_at INTEGER")
        if schema == "full":
            cols += ["consumed_by TEXT", "consumed_ref TEXT"]
        con.execute(f"CREATE TABLE approvals ({', '.join(cols)})")
        if schema == "full":
            con.execute("""CREATE TABLE approval_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, approval_id TEXT NOT NULL,
              event TEXT NOT NULL CHECK(event IN ('consumed','consume_refused','consumed_backfill')),
              reason TEXT, actor TEXT, ref TEXT,
              created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)))""")
        for addr in live:
            con.execute(
                "INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at,"
                f" resolved_at, resolved_by, content_hash) VALUES (hex(randomblob(6)), 'x',"
                f" 'email_standing_recipient', 'elesites', 'approved', {NOW_S}-60, {NOW_S}, 'gazda', ?)",
                (hashlib.sha256(addr.strip().lower().encode("utf-8")).hexdigest(),))
        con.commit()
        con.close()
    if standing is not None:
        with open(os.path.join(store, "email-standing-recipients.json"), "w", encoding="utf-8") as fh:
            if isinstance(standing, str):
                fh.write(standing)
            else:
                json.dump({"recipients": list(standing)}, fh)
    return store


def paths_of(store):
    return {"db": os.path.join(store, "claudeclaw.db"),
            "config": os.path.join(store, "autonomy-config.json"),
            "standing": os.path.join(store, "email-standing-recipients.json"),
            "log": os.path.join(store, "email-standing-sends.log"),
            "store": store}


TEXT = "Teszt tárgy\nKedves Ügyfelünk! Törzs."


def req(mode="consume", kind="send", to=("a@b.hu",), text=TEXT, ref="ref-1", **extra):
    r = {"mode": mode, "tool": "graph-mail", "kind": kind, "to": list(to), "cc": [], "bcc": [],
         "text": text, "ref": ref}
    if kind == "forward":
        r["forward"] = {"message_id": "AAMkAGFmZXN0MDEyMzQ1Njc4OQ==", "subject": "Ajánlatkérés: Teszt utca 5."}
    r.update(extra)
    return r


def anchor_for(r):
    env, _, _ = H.build_env(r)
    return H._load_gate().content_anchor(env)


def approve(store, anchor, resolved_ago=0, status="approved", consumed=None):
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    cur = con.execute(
        "INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at,"
        " resolved_at, resolved_by, content_hash, consumed_at) VALUES (hex(randomblob(6)), 'x',"
        f" 'email_send', 'teszt', ?, {NOW_S}-{resolved_ago}-60,"
        f" CASE WHEN ?='pending' THEN NULL ELSE {NOW_S}-{resolved_ago} END, 'gazda', ?, ?)",
        (status, status, anchor, consumed))
    row = con.execute("SELECT id FROM approvals WHERE rowid=?", (cur.lastrowid,)).fetchone()
    con.commit()
    con.close()
    return row[0]


def rows(store, sql="SELECT consumed_at, consumed_by, consumed_ref FROM approvals WHERE category='email_send'"):
    con = sqlite3.connect(os.path.join(store, "claudeclaw.db"))
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def decide(store, r, **kw):
    return H.run(r, paths_of(store))


# ============================================================================
print("N1: allow / none / pending / consumed / expired, single use")
store = make_store()
r = req()
anchor = anchor_for(r)
res = decide(store, r)
check("no approval -> refuse none, with the anchor", res["decision"] == "refuse" and res["reason"] == "none"
      and res["anchor"] == anchor, res)
aid = approve(store, anchor)
res = decide(store, r)
check("approved + matching + in window -> allow", res["decision"] == "allow" and res["reason"] == "approval"
      and res["approval_id"] == aid, res)
st = rows(store)
check("consumed_at set, consumed_by='graph-mail', consumed_ref = the request ref",
      len(st) == 1 and st[0][0] is not None and st[0][1:] == ("graph-mail", "ref-1"), st)
ev = rows(store, "SELECT approval_id, event, actor, ref FROM approval_events")
check("one approval_events row 'consumed' with the consumer", ev == [(aid, "consumed", "graph-mail", "ref-1")], ev)
res = decide(store, r)
check("the same letter again -> refuse consumed (strictly single use, no refund)",
      res["decision"] == "refuse" and res["reason"] == "consumed", res)
check("a refused repeat writes no second event", len(rows(store, "SELECT 1 FROM approval_events")) == 1)

store = make_store()
approve(store, anchor, status="pending")
res = decide(store, r)
check("a pending approval -> refuse pending", res["reason"] == "pending" and res["decision"] == "refuse", res)
store = make_store()
approve(store, anchor, resolved_ago=1900)
res = decide(store, r)
check("an approval resolved 1900 s ago -> refuse expired", res["reason"] == "expired", res)
store = make_store()
approve(store, anchor_for(req(to=("other@b.hu",))))
check("an approval for another recipient does not authorise (none)", decide(store, r)["reason"] == "none")
store = make_store()
approve(store, anchor)
check("a send approval does not authorise the same text as a forward",
      decide(store, req(kind="forward"))["reason"] == "none")
check("a bcc changes the anchor (none)", decide(store, req(bcc=["x@b.hu"]))["reason"] == "none")
att = [{"name": "a.pdf", "sha256": "ab" * 32, "size": 3}]
check("an attachment changes the anchor (none)", decide(store, req(attachments=att))["reason"] == "none")
store = make_store()
r_att = req(attachments=att, html_sha256="cd" * 32)
approve(store, anchor_for(r_att))
check("the same attachment + html digest is the approved letter", decide(store, r_att)["decision"] == "allow")
check("anchor of the helper equals the gate's content_anchor on the same envelope",
      anchor_for(r_att) == H._load_gate().content_anchor(
          {"to": ["a@b.hu"], "cc": [], "bcc": [], "text": TEXT, "html_sha256": "cd" * 32, "attachments": att}))

# ============================================================================
print("N1: peek writes nothing")
store = make_store()
aid = approve(store, anchor)
before = rows(store, "SELECT * FROM approvals")
res = decide(store, req(mode="peek"))
check("peek on an approved letter -> allow with the approval id", res["decision"] == "allow" and res["approval_id"] == aid, res)
check("peek: the approvals table is byte for byte unchanged", rows(store, "SELECT * FROM approvals") == before)
check("peek: no approval_events row", rows(store, "SELECT 1 FROM approval_events") == [])
res = decide(store, req(mode="peek"))
check("peek twice: still allow (nothing was spent)", res["decision"] == "allow")
check("peek with no approval -> refuse none", decide(make_store(), req(mode="peek"))["reason"] == "none")

# ============================================================================
print("N1: parallel PROCESSES on one approval -> exactly one allow")
store = make_store()
approve(store, anchor)
driver = os.path.join(TD, "driver.py")
with open(driver, "w", encoding="utf-8") as fh:
    fh.write(
        "import importlib.util, json, sys\n"
        f"spec = importlib.util.spec_from_file_location('h', {HELPER!r})\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "print(json.dumps(m.run(json.loads(sys.argv[1]), json.loads(sys.argv[2]))))\n")
env = dict(os.environ, WEB_PORT="1", OUTGOING_COPY_GATE_RULES=os.path.join(TD, "no-rules.json"))
procs = [subprocess.Popen([PY, "-I", driver, json.dumps(req(ref=f"p{i}")), json.dumps(paths_of(store))],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for i in range(8)]
verdicts = []
for p in procs:
    out, err = p.communicate(timeout=60)
    verdicts.append(json.loads(out.decode()) if out.strip() else {"decision": "crash", "reason": err.decode()[:200]})
allows = [v for v in verdicts if v["decision"] == "allow"]
check("8 processes, one approval: exactly one allow", len(allows) == 1, [v["reason"] for v in verdicts])
check("the 7 others are refused as consumed", sorted(v["reason"] for v in verdicts if v["decision"] != "allow")
      == ["consumed"] * 7, [v["reason"] for v in verdicts])
check("one consumed event, one consumed row", len(rows(store, "SELECT 1 FROM approval_events")) == 1
      and len([x for x in rows(store) if x[0] is not None]) == 1)

# ============================================================================
print("N1: levels")
store = make_store(level=1)
approve(store, anchor)
res = decide(store, r)
check("level 1 -> refuse level1, approval untouched", res["reason"] == "level1" and rows(store)[0][0] is None, res)
store = make_store(level=3)
approve(store, anchor)
res = decide(store, r)
check("level 3 -> allow without consuming", res["decision"] == "allow" and res["reason"] == "level3"
      and rows(store)[0][0] is None, res)
res = decide(make_store(level=3), r)
check("level 3 -> allow even with no approval", res["decision"] == "allow")
check("maxLevel caps the level (level 3 + maxLevel 2 -> needs an approval)",
      decide(make_store(level=3, max_level=2), r)["reason"] == "none")
check("level 2 is the default path (none without approval)", decide(make_store(level=2), r)["reason"] == "none")

# ============================================================================
print("N1: fail-closed config / DB / window / standing")
store = make_store(config="missing")
approve(store, anchor)
res = decide(store, r)
check("autonomy-config missing -> level 1 refusal, never an allow", res["decision"] == "refuse"
      and res["reason"] == "level1" and rows(store)[0][0] is None, res)
store = make_store(config="corrupt")
approve(store, anchor)
res = decide(store, r)
check("autonomy-config corrupt -> level 1 refusal", res["reason"] == "level1" and rows(store)[0][0] is None, res)
check("a readable config without the email_send category is level 2 (as for the hook)",
      decide(make_store(config="nocategory"), r)["reason"] == "none")
res = decide(make_store(schema="nodb"), r)
check("DB missing -> refuse db_unavailable", res["decision"] == "refuse" and res["reason"] == "db_unavailable", res)
for sch in ("noconsumed", "nohash"):
    res = decide(make_store(schema=sch), r)
    check(f"approvals table without {'consumed_at' if sch == 'noconsumed' else 'content_hash'} -> db_unavailable",
          res["decision"] == "refuse" and res["reason"] == "db_unavailable", res)
store = make_store()
approve(store, anchor)
lock = sqlite3.connect(os.path.join(store, "claudeclaw.db"), isolation_level=None)
lock.execute("BEGIN EXCLUSIVE")
res = decide(store, r)
lock.execute("ROLLBACK")
lock.close()
check("DB locked (busy_timeout elapsed) -> db_unavailable, approval not consumed",
      res["decision"] == "refuse" and res["reason"] == "db_unavailable" and rows(store)[0][0] is None, res)
os.environ["EMAIL_APPROVAL_WINDOW_S"] = "abc"
store = make_store()
approve(store, anchor)
res = decide(store, r)
check("EMAIL_APPROVAL_WINDOW_S not an integer -> config_invalid", res["reason"] == "config_invalid"
      and rows(store)[0][0] is None, res)
os.environ["EMAIL_APPROVAL_WINDOW_S"] = "999999"
store = make_store()
approve(store, anchor, resolved_ago=3600)
check("a huge EMAIL_APPROVAL_WINDOW_S cannot widen the window beyond 1800 s (expired)",
      decide(store, r)["reason"] == "expired")
os.environ["EMAIL_APPROVAL_WINDOW_S"] = "60"
store = make_store()
approve(store, anchor, resolved_ago=120)
check("a smaller EMAIL_APPROVAL_WINDOW_S narrows it (expired at 120 s)", decide(store, r)["reason"] == "expired")
os.environ.pop("EMAIL_APPROVAL_WINDOW_S")
check("no recipient -> refuse no_recipient", decide(make_store(), req(to=()))["reason"] == "no_recipient")
check("empty text -> refuse no_text", decide(make_store(), req(text="  \n"))["reason"] == "no_text")
store = make_store(standing="{broken json")
approve(store, anchor)
res = decide(store, r)
check("standing file corrupt: no standing right, the approval path decides (allow here), note carries the fault",
      res["decision"] == "allow" and res["reason"] == "approval" and "nem olvashato" in (res.get("note") or ""), res)
res = decide(make_store(standing="{broken json"), r)
check("standing file corrupt + no approval -> refuse none", res["reason"] == "none", res)

# ============================================================================
print("N1: the standing list")
received = []


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        received.append(json.loads(self.rfile.read(n).decode("utf-8")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
assert port not in FORBIDDEN_PORTS
ADDR = "kovacs@fireeng.hu"


def standing_store(live=True, **kw):
    s = make_store(standing=[ADDR], live=(ADDR,) if live else (), **kw)
    with open(os.path.join(s, ".dashboard-token"), "w") as fh:
        fh.write("test-token-not-a-secret")
    return s


sreq = req(to=(ADDR,), text="Értesítő\nSzia! Új irat érkezett.")
os.environ["WEB_PORT"] = str(port)
store = standing_store()
res = decide(store, sreq)
check("live standing recipient, level 2, no approval -> allow 'standing'", res["decision"] == "allow"
      and res["reason"] == "standing" and res["standing"] == ADDR and res["owner_gap"] is None, res)
log = open(os.path.join(store, "email-standing-sends.log"), encoding="utf-8").read().strip().splitlines()
check("the local standing log has exactly one line, owner notified ok",
      len(log) == 1 and "gazda-ertesites=ok" in log[0] and ADDR in log[0], log)
check("the daily-log POST happened exactly once", len(received) == 1, received)
res = decide(store, sreq)
check("a second send to the standing recipient writes a second line (one trace per authorised send)",
      len(open(os.path.join(store, "email-standing-sends.log"), encoding="utf-8").read().strip().splitlines()) == 2
      and len(received) == 2)
n0 = len(received)
store = standing_store()
res = decide(store, dict(sreq, mode="peek"))
check("peek on a standing recipient -> allow, but NO log and NO daily-log POST",
      res["decision"] == "allow" and res["reason"] == "standing" and not os.path.exists(os.path.join(store, "email-standing-sends.log"))
      and len(received) == n0, res)
store = standing_store(live=False)
res = decide(store, sreq)
check("listed but not activated -> refuse standing_not_live, nothing written",
      res["decision"] == "refuse" and res["reason"] == "standing_not_live"
      and not os.path.exists(os.path.join(store, "email-standing-sends.log")) and len(received) == n0, res)
store = standing_store()
os.mkdir(os.path.join(store, "email-standing-sends.log"))  # the log path is a directory: not writable
res = decide(store, sreq)
check("unwritable trace -> refuse trace_unwritable", res["decision"] == "refuse" and res["reason"] == "trace_unwritable", res)
store = standing_store()
os.remove(os.path.join(store, "claudeclaw.db"))
res = decide(store, sreq)
check("standing activation not verifiable (DB gone) -> refuse db_unavailable", res["reason"] == "db_unavailable", res)
store = standing_store()
approve(store, anchor_for(req(to=(ADDR, "b@b.hu"), text=sreq["text"])))
res = decide(store, req(to=(ADDR, "b@b.hu"), text=sreq["text"]))
check("two recipients are never a standing send: the approval path decides", res["reason"] == "approval", res)
res = decide(standing_store(), dict(sreq, cc=["c@b.hu"]))
check("a cc defeats the standing right (none)", res["reason"] == "none", res)
# a forward to the standing recipient: the trace carries the forward facts
store = standing_store()
fq = req(kind="forward", to=(ADDR,), text="Szia! Kérlek, nézd meg.", comment_source="inline",
         comment_sha256=hashlib.sha256("Szia! Kérlek, nézd meg.".encode()).hexdigest())
n0 = len(received)
res = decide(store, fq)
line = open(os.path.join(store, "email-standing-sends.log"), encoding="utf-8").read().strip().splitlines()[-1]
body = received[-1]["content"] if len(received) > n0 else ""
check("forward to a live standing recipient -> allow", res["decision"] == "allow" and res["reason"] == "standing", res)
for part in ("tovabbitas engedelyezve jovahagyas nelkul", f"komment-sha256={fq['comment_sha256']}",
             "tovabbitott-targy='Ajánlatkérés: Teszt utca 5.'", "gazda-ertesites=ok"):
    check(f"forward trace (local log) has {part[:36]!r}", part in line, line[:300])
check("forward trace (daily log) names the forwarded letter and does not claim it went out",
      "Tovabbitott level: Ajánlatkérés: Teszt utca 5." in body and "Level ment ki" not in body, body[:300])
os.environ["WEB_PORT"] = "1"
store = standing_store()
res = decide(store, sreq)
check("dashboard unreachable: still allow, the gap is reported (owner_gap) and logged",
      res["decision"] == "allow" and res["owner_gap"]
      and "NEM MENT KI" in open(os.path.join(store, "email-standing-sends.log"), encoding="utf-8").read(), res)
srv.shutdown()

# ============================================================================
print("N1: copy QA before consumption")
em = "Teszt tárgy\nKedves Ügyfelünk — törzs."
store = make_store()
approve(store, anchor_for(req(text=em)))
res = decide(store, req(text=em))
check("an em dash fails QA: refuse qa_failed, the approval is NOT consumed",
      res["decision"] == "refuse" and res["reason"] == "qa_failed" and "GONDOLATJEL" in (res["detail"] or "")
      and rows(store)[0][0] is None, res)
store = make_store(level=3)
check("QA also runs at level 3 (refuse qa_failed)", decide(store, req(text=em))["reason"] == "qa_failed")
store = standing_store()
res = decide(store, req(to=(ADDR,), text=em))
check("QA before the standing path too: no trace is written", res["reason"] == "qa_failed"
      and not os.path.exists(os.path.join(store, "email-standing-sends.log")), res)
rules = os.path.join(TD, "bad-rules.json")
with open(rules, "w") as fh:
    fh.write("{nope")
os.environ["OUTGOING_COPY_GATE_RULES"] = rules
store = make_store()
approve(store, anchor)
res = decide(store, r)
check("a rules file that exists but is invalid refuses (qa_failed), nothing consumed",
      res["reason"] == "qa_failed" and rows(store)[0][0] is None, res)
os.environ["OUTGOING_COPY_GATE_RULES"] = os.path.join(TD, "no-rules.json")

# ============================================================================
print("N1: the stdin/stdout entry point")
store = make_store()
approve(store, anchor)
p = subprocess.run([PY, "-I", HELPER], input=json.dumps(req()).encode(), capture_output=True,
                   env=dict(os.environ, EMAIL_APPROVAL_GATE_STORE=store, WEB_PORT="1"), timeout=60)
out = json.loads(p.stdout.decode())
check("EMAIL_APPROVAL_GATE_STORE does not move the decision: refuse, exit 2, the temp row stays unconsumed",
      p.returncode == 2 and out["decision"] == "refuse" and rows(store)[0][0] is None, (p.returncode, out))
check("the repo-root store is what the entry point read (level1 / db_unavailable / none), never allow",
      out["reason"] in ("level1", "db_unavailable", "none"), out)
for label, data in (("not JSON", b"{oops"), ("not an object", b"[1]"), ("empty", b"")):
    p = subprocess.run([PY, "-I", HELPER], input=data, capture_output=True, timeout=60)
    out = json.loads(p.stdout.decode())
    check(f"stdin {label} -> exit 2, refuse bad_request", p.returncode == 2 and out["reason"] == "bad_request", (p.returncode, out))
for label, bad in (("mode", req(mode="x")), ("tool", dict(req(), tool="mail")), ("kind", req(kind="reply")),
                   ("to type", dict(req(), to="a@b.hu")), ("text type", dict(req(), text=5)),
                   ("forward missing", dict(req(kind="forward"), forward=None)),
                   ("forward on a send", dict(req(), forward={"message_id": "x", "subject": "y"})),
                   ("attachment shape", dict(req(), attachments=[{"name": "a"}]))):
    res = H.run(bad, paths_of(make_store()))
    check(f"bad request ({label}) -> refuse bad_request", res["decision"] == "refuse" and res["reason"] == "bad_request", res)
# the real main(): allow -> exit 0, refuse -> exit 2, exactly one JSON line, via the module's _ROOT
root = os.path.join(TD, "fakeroot")
os.makedirs(os.path.join(root, "store"))
fs = make_store()
for name in os.listdir(fs):
    os.rename(os.path.join(fs, name), os.path.join(root, "store", name))
approve(os.path.join(root, "store"), anchor)
H._ROOT = root


def run_main(r):
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(r)), io.StringIO()
    try:
        code = H.main()
        return code, sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out


code, out = run_main(req())
check("main(): allow -> exit 0 and one JSON line", code == 0 and json.loads(out)["decision"] == "allow"
      and out.count("\n") == 1, (code, out))
code, out = run_main(req())
check("main(): the repeat -> exit 2 (consumed)", code == 2 and json.loads(out)["reason"] == "consumed", (code, out))

# ============================================================================
print("N3: the hook on a graph-mail send only peeks; the MCP path still consumes")
CLI = "scripts/graph-mail.ts"
GM_TEXT_BODY = "Szia Andi! Kérlek, nézd meg."


def run_hook(store, payload):
    e = dict(os.environ, EMAIL_APPROVAL_GATE_STORE=store, EMAIL_APPROVAL_WINDOW_S="1800", WEB_PORT="1",
             OUTGOING_COPY_GATE_RULES=os.path.join(TD, "no-rules.json"))
    p = subprocess.run([PY, "-I", GATE], input=json.dumps(payload).encode(), capture_output=True, env=e, timeout=60)
    return p.returncode, p.stdout.decode(), p.stderr.decode()


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def anchor_of(err):
    import re
    m = re.search(r"Tartalom-horgony \(sha256; [^)]*\): ([0-9a-f]{64})", err)
    return m.group(1) if m else None


cmd = f"npx tsx {CLI} send --to kovacs@fireeng.hu --subject Teszt --body '{GM_TEXT_BODY}'"
store = make_store()
code, _, err = run_hook(store, bash(cmd))
a = anchor_of(err)
check("graph-mail send, no approval -> deny with the anchor, wording says the CLI consumes",
      code == 2 and a and "NINCS jovahagyas" in err and "A jovahagyast a CLI fogyasztja el" in err, err[:300])
approve(store, a)
code, out, err = run_hook(store, bash(cmd))
check("graph-mail send, approved -> the hook allows", code == 0 and "megvan" in out, (code, out, err[:200]))
check("... and consumed_at stays NULL", rows(store)[0][0] is None)
code, out, err = run_hook(store, bash(cmd))
check("... a second identical call still passes the hook (the CLI is the consumer)",
      code == 0 and rows(store)[0][0] is None)
check("... and the hook wrote no approval_events row", rows(store, "SELECT 1 FROM approval_events") == [])
# the old classifier: ANY mention of graph-mail (any case) never consumes
store = make_store()
approve(store, a)
for label, c in (("upper-case mention in a send", cmd.replace("graph-mail", "GRAPH-MAIL")),
                 ("the CLI as bash -c payload", f"bash -c \"{cmd}\""),
                 ("env-prefixed", f"X=1 {cmd}")):
    code, out, err = run_hook(store, bash(c))
    check(f"{label}: the hook never consumes (exit {code})", rows(store)[0][0] is None, err[:200])
# standing: the hook writes no trace for graph-mail
store = standing_store()
code, out, err = run_hook(store, bash(cmd))
check("graph-mail send to a live standing recipient: allow, NO standing log written by the hook",
      code == 0 and "a CLI irja" in out and not os.path.exists(os.path.join(store, "email-standing-sends.log")), (code, out, err[:200]))
# MCP send_email regression: still consumes
mcp = {"tool_name": "mcp__server-gmail-autoauth-mcp__send_email",
       "tool_input": {"to": ["a@b.hu"], "subject": "Teszt tárgy", "body": "Kedves Ügyfelünk! Törzs."}}
store = make_store()
code, _, err = run_hook(store, mcp)
am = anchor_of(err)
approve(store, am)
code, out, err = run_hook(store, mcp)
check("MCP send_email, approved -> allow and CONSUMED (consumed_by = the hook)",
      code == 0 and "felhasznalva" in out and rows(store)[0][0] is not None
      and rows(store)[0][1] == "email-approval-gate", (code, out, err[:200], rows(store)))
check("... and an approval_events row 'consumed' by the hook",
      [e[0] for e in rows(store, "SELECT event FROM approval_events")] == ["consumed"])
code, _, err = run_hook(store, mcp)
check("MCP send_email, the same call again -> denied as consumed", code == 2 and "MAR FEL LETT HASZNALVA" in err)

# ============================================================================
# S2 (card efa58ad2): --to/--cc/--bcc accept ONLY bare address lists, on BOTH sides
# ============================================================================
print("S2: bare recipient lists")
EXT = load(os.path.join(HOOKS, "email_extract.py"), "email_extract_s2")
VECT = json.load(open(os.path.join(HOOKS, "graph-bare-recipient-cases.json"), encoding="utf-8"))
check("vectors: every valid list passes bare_address_list_ok",
      all(EXT.bare_address_list_ok(v) for v in VECT["valid"]),
      [v for v in VECT["valid"] if not EXT.bare_address_list_ok(v)])
check("vectors: every invalid list is refused by bare_address_list_ok",
      not any(EXT.bare_address_list_ok(v) for v in VECT["invalid"]),
      [v for v in VECT["invalid"] if EXT.bare_address_list_ok(v)])
check("non-strings are refused", not any(EXT.bare_address_list_ok(v) for v in (None, 5, ["a@b.hu"], b"a@b.hu")))

S2_BAD = ['"a,evil@x.com,b" <kovacs@fireeng.hu>', "Name <kovacs@fireeng.hu>", "kovacs@fireeng.hu (x)",
          "<kovacs@fireeng.hu>", "kovacs@fireeng.hu;evil@x.com", "kovacs@fireeng.hu, ,b@x.hu"]
for bad in S2_BAD:
    for mode in ("consume", "peek"):
        # a live standing recipient AND an approved row for exactly this envelope
        store = standing_store()
        r = req(mode=mode, to=(bad,), text=sreq["text"])
        approve(store, anchor_for(req(to=(bad,), text=sreq["text"])))
        res = decide(store, r)
        check(f"helper {mode}: {bad!r} -> refuse bad_request, nothing consumed or traced",
              res["decision"] == "refuse" and res["reason"] == "bad_request"
              and rows(store)[0][0] is None and not os.path.exists(os.path.join(store, "email-standing-sends.log")), res)
    store = standing_store()
    res = decide(store, req(to=(ADDR,), cc=[bad], text=sreq["text"]))
    check(f"helper: {bad!r} as cc -> refuse bad_request", res["decision"] == "refuse" and res["reason"] == "bad_request", res)
    res = decide(store, req(to=(ADDR,), bcc=[bad], text=sreq["text"]))
    check(f"helper: {bad!r} as bcc -> refuse bad_request", res["decision"] == "refuse" and res["reason"] == "bad_request", res)
    store = standing_store()
    cmd = f"npx tsx {CLI} send --to '{bad}' --subject Teszt --body '{GM_TEXT_BODY}'"
    code, out, err = run_hook(store, bash(cmd))
    check(f"hook: {bad!r} as --to -> deny (exit {code}) even with a live standing recipient", code == 2, (out, err[:200]))
    code, out, err = run_hook(store, bash(f"npx tsx {CLI} send --to {ADDR} --cc '{bad}' --subject Teszt --body '{GM_TEXT_BODY}'"))
    check(f"hook: {bad!r} as --cc -> deny (exit {code})", code == 2, (out, err[:200]))
# the bare list still works, anchor parity unchanged
store = standing_store()
two = "kovacs@fireeng.hu,b@fireeng.hu"
a2 = anchor_for(req(to=(two,), text=sreq["text"]))
approve(store, a2)
res = decide(store, req(to=(two,), text=sreq["text"]))
check("helper: a bare two-address list with a matching approval -> allow 'approval'",
      res["decision"] == "allow" and res["reason"] == "approval", res)
store = make_store(level=3)
res = decide(store, req(to=('Name <kovacs@fireeng.hu>',), text=sreq["text"]))
check("helper: level 3 does not wave a non-bare list through", res["decision"] == "refuse" and res["reason"] == "bad_request", res)
cmd = f"npx tsx {CLI} send --to a@fireeng.hu,b@fireeng.hu --subject Teszt --body '{GM_TEXT_BODY}'"
store = make_store()
code, _, err = run_hook(store, bash(cmd))
check("hook: a bare two-address --to still reaches the approval step (deny with an anchor)",
      code == 2 and anchor_of(err) is not None, err[:300])

print(f"\n{passed} passed, {len(failed)} failed")
if failed:
    print("FAILED: " + "; ".join(failed))
    sys.exit(1)
print("All email-send-authorize tests passed.")
