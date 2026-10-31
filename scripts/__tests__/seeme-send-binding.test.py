#!/usr/bin/env python3
"""Card e487f46c: scripts/sms/seeme-send.py binds the APPROVED text and number.

Proven against a fake dashboard (127.0.0.1, one-shot consume state, window check, like the real
POST /api/approvals/<id>/consume) and a stub SeeMe gateway on the same loopback server. The real
provider and the live dashboard are never contacted: every process under test carries a
loopback-only socket guard (sitecustomize), self-tested below against a non-loopback address and
the live CDP ports, which are refused BEFORE any connect().

  - exact {number, text} envelope -> one consume, then one send (ordering from one shared log);
  - changed text / changed number / hash-less (legacy) approval -> no consume, no send;
  - the same E.164 number in other spellings (+36, 06, 0036, spaces, dashes) -> sent;
  - second use of one approval -> 409 -> no send; expired / past its own timeout -> no send;
  - consume fails (500, ok:false, 404) -> no send;
  - a number that only matches as prefix/suffix of a longer digit run in the description -> no send;
  - every refusal is ONE line with neither the text nor the full number;
  - --print-anchor equals an independently computed sha256 of the canonical envelope;
  - mutation control: with the hash comparison removed, a changed text IS sent.

Run: python3 <thisfile>   Exit 0 = all pass.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "sms", "seeme-send.py")

NUM = "36301234567"
TEXT = "Kedves Ügyfelünk! A szerződés \"aláírva\", köszönjük."
failed = []
passed = 0


def check(name, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print("PASS " + name)
    else:
        failed.append(name)
        print("FAIL " + name + ((" :: " + detail) if detail else ""))


def anchor(number, text):
    canon = json.dumps({"kind": "sms", "number": number, "text": text},
                       ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


LOG = []
LOCK = threading.Lock()
APPROVALS = {}
CONSUMED = set()
CONSUME_MODE = {}   # approval id -> "500" | "notok"


def note(line):
    with LOCK:
        LOG.append(line)


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/gateway"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            note("SEND " + q["number"][0] + " " + q["message"][0])
            return self.send_json(200, {"code": "0", "result": "OK", "split": 1, "price": 1})
        aid = self.path.rsplit("/", 1)[1]
        note("GET " + aid)
        rec = APPROVALS.get(aid)
        if rec is None:
            return self.send_json(404, {"error": "not found"})
        return self.send_json(200, rec)

    def do_POST(self):
        aid = self.path.split("/")[3]
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        note("CONSUME " + aid)
        with LOCK:
            CONSUMED_BODIES.append(body)
        mode = CONSUME_MODE.get(aid)
        if mode == "500":
            return self.send_json(500, {"ok": False})
        if mode == "notok":
            return self.send_json(200, {"ok": False})
        rec = APPROVALS.get(aid)
        if rec is None:
            return self.send_json(404, {"ok": False, "reason": "not_found"})
        with LOCK:
            if aid in CONSUMED:
                return self.send_json(409, {"ok": False, "reason": "already_consumed"})
            if body.get("category") != rec["category"]:
                return self.send_json(409, {"ok": False, "reason": "wrong_category"})
            if not LAX["hash"] and body.get("content_hash") != rec.get("content_hash"):
                return self.send_json(409, {"ok": False, "reason": "hash_mismatch"})
            if rec["resolved_at"] < time.time() - int(body.get("max_age_seconds", 1800)):
                return self.send_json(409, {"ok": False, "reason": "expired"})
            CONSUMED.add(aid)
        return self.send_json(200, {"ok": True, "approval": {"id": aid}})


CONSUMED_BODIES = []
LAX = {"hash": False}
srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

TMPROOT = tempfile.TemporaryDirectory(prefix="seeme-binding-")
FIX = TMPROOT.name
GUARD = os.path.join(FIX, "guard")
os.makedirs(GUARD)
with open(os.path.join(GUARD, "sitecustomize.py"), "w") as fh:
    fh.write('''import socket
_orig = socket.socket.connect
_BLOCKED_PORTS = {18800, 18899}
def _guard(self, addr):
    if self.family in (socket.AF_INET, socket.AF_INET6) and isinstance(addr, tuple):
        host, port = addr[0], addr[1]
        if host not in ("127.0.0.1", "::1", "localhost") or port in _BLOCKED_PORTS:
            raise PermissionError("loopback-only guard: refused " + str(host) + ":" + str(port))
    return _orig(self, addr)
socket.socket.connect = _guard
''')

ENVV = {
    "SEEME_INTERNAL_FILE": os.path.join(FIX, "internal.json"),
    "SEEME_DASH_TOKEN_FILE": os.path.join(FIX, ".dashboard-token"),
    "SEEME_ENV_FILE": os.path.join(FIX, "seeme-gateway.env"),
    "SEEME_LOG_FILE": os.path.join(FIX, "seeme-send.log"),
    "SEEME_DASH_BASE": "http://127.0.0.1:%d" % PORT,
    "PYTHONPATH": GUARD,
}
with open(ENVV["SEEME_INTERNAL_FILE"], "w") as fh:
    fh.write('{"internal": ["36305552860"]}')
with open(ENVV["SEEME_DASH_TOKEN_FILE"], "w") as fh:
    fh.write("test-token-not-a-secret")
with open(ENVV["SEEME_ENV_FILE"], "w") as fh:
    fh.write("SEEME_API_KEY=fake\nSEEME_SENDER=36300000000\nSEEME_BASE=http://127.0.0.1:%d/gateway\n" % PORT)


def run(text, to, approval, extra=(), script=SCRIPT, env_extra=None):
    env = dict(os.environ)
    env.update(ENVV)
    env.update(env_extra or {})
    args = [sys.executable, script, "--to", to]
    if approval:
        args += ["--approval", approval]
    args += list(extra)
    p = subprocess.run(args, input=text.encode("utf-8"), capture_output=True, env=env, timeout=60)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def reset():
    with LOCK:
        del LOG[:]
        del CONSUMED_BODIES[:]


def kinds():
    return [l.split(" ")[0] for l in LOG]


def approve(aid, number=NUM, text=TEXT, **over):
    rec = {
        "id": aid, "status": "approved", "category": "external_message",
        "action_description": "SMS-t kuldenek a %s szamra (SeeMe)." % number,
        "content_hash": anchor(number, text),
        "requested_at": int(time.time()) - 60, "resolved_at": int(time.time()) - 10,
        "timeout_at": int(time.time()) + 3000,
    }
    rec.update(over)
    APPROVALS[aid] = rec
    return rec


def one_line_clean(out, text=TEXT, full=NUM):
    lines = [l for l in out.strip().splitlines() if l.startswith("FAIL:")]
    return len(lines) == 1 and "Kedves" not in out and text not in out and full not in out


# --- guard self-test: a non-loopback address and the live CDP port are refused before connect() ---
probe = ("import socket,sys\n"
         "for host, port in (('192.0.2.1', 80), ('127.0.0.1', 18800), ('127.0.0.1', 18899)):\n"
         "    s = socket.socket()\n"
         "    try:\n"
         "        s.connect((host, port)); print('CONNECTED', host, port); sys.exit(3)\n"
         "    except PermissionError as e:\n"
         "        print('refused', port)\n")
p = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                   env=dict(os.environ, PYTHONPATH=GUARD), timeout=30)
check("socket guard refuses 192.0.2.1 and the CDP ports 18800/18899 before connect()",
      p.returncode == 0 and p.stdout.decode().count("refused") == 3, p.stdout.decode() + p.stderr.decode())

# --- 1. exact envelope: one consume, then one send ---
approve("ok-1")
reset()
rc, out = run(TEXT, "+36 30 123 4567", "ok-1")
check("exact envelope: exit 0", rc == 0, out)
check("exact envelope: GET, then CONSUME, then SEND, once each (consume strictly before send)",
      kinds() == ["GET", "CONSUME", "SEND"], str(kinds()))
check("the send carries exactly the approved number and text",
      LOG[-1] == "SEND %s %s" % (NUM, TEXT), LOG[-1])
b = CONSUMED_BODIES[0] if CONSUMED_BODIES else {}
check("consume body: category, own anchor hash, consumer, window",
      b.get("category") == "external_message" and b.get("content_hash") == anchor(NUM, TEXT)
      and b.get("consumer") == "seeme-send.py" and b.get("max_age_seconds") == 1800, str(b))
check("stdout masks the external number", NUM not in out and "*********67" in out, out)

# --- 2. changed text / changed number / legacy approval ---
approve("chg-text")
reset()
rc, out = run(TEXT + " Plusz egy mondat.", NUM, "chg-text")
check("changed text: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
check("changed text: one-line reason without text or full number", one_line_clean(out, TEXT + " Plusz egy mondat."), out)

reset()
rc, out = run(TEXT + "\n", NUM, "chg-text")
check("a trailing newline is a different text: refused", rc != 0 and "SEND" not in kinds(), out)

approve("chg-num")
reset()
rc, out = run(TEXT, "36301234568", "chg-num")
check("changed number: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
check("changed number: reason masks the number", "36301234568" not in out and NUM not in out, out)

approve("legacy", content_hash=None)
reset()
rc, out = run(TEXT, NUM, "legacy")
check("approval without content_hash: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), out)

approve("bad-hash", content_hash="XYZ")
reset()
rc, out = run(TEXT, NUM, "bad-hash")
check("malformed content_hash: refused", rc != 0 and "SEND" not in kinds(), out)

# --- 3. same E.164 number, other spellings ---
for i, spelling in enumerate(["06 30 123 4567", "06-30-123-4567", "+36-30-123-4567", "0036 30 123 4567", "36301234567", " +36 30 1234567 "]):
    aid = "fmt-%d" % i
    approve(aid)
    reset()
    rc, out = run(TEXT, spelling, aid)
    check("spelling %r -> same E.164, sent once" % spelling, rc == 0 and kinds() == ["GET", "CONSUME", "SEND"] and LOG[-1].startswith("SEND " + NUM + " "), out + str(LOG))

# description spells the number differently from --to: still the same number
approve("desc-fmt", action_description="SMS a +36 (30) 123-4567 szamra".replace("(30)", "30"))
reset()
rc, out = run(TEXT, "06301234567", "desc-fmt")
check("description spelled +36 30 123-4567, --to 06...: sent", rc == 0 and "SEND" in kinds(), out)

# --- 4. prefix / suffix number in the description is not a match ---
approve("suffix", action_description="SMS a 363012345678 szamra")
reset()
rc, out = run(TEXT, NUM, "suffix")
check("number only as a prefix of a longer digit run: refused", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
approve("prefix", action_description="SMS a 9936301234567 szamra")
reset()
rc, out = run(TEXT, NUM, "prefix")
check("number only as a suffix of a longer digit run: refused", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
approve("other-num", action_description="SMS a 36709998877 szamra")
reset()
rc, out = run(TEXT, NUM, "other-num")
check("description names another number: refused", rc != 0 and "SEND" not in kinds(), out)

# --- 5. second use ---
approve("twice")
reset()
rc1, out1 = run(TEXT, NUM, "twice")
rc2, out2 = run(TEXT, NUM, "twice")
check("second use of one approval: first sent, second refused with 409, one send in total",
      rc1 == 0 and rc2 != 0 and kinds().count("SEND") == 1 and kinds().count("CONSUME") == 2 and "already_consumed" in out2, str(LOG) + out2)
check("second use: one-line reason without text or full number", one_line_clean(out2), out2)

# --- 6. window ---
approve("old", resolved_at=int(time.time()) - 4000)
reset()
rc, out = run(TEXT, NUM, "old")
check("decision older than the window: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), out)
check("expired: one-line reason", one_line_clean(out), out)
approve("old-ok-env", resolved_at=int(time.time()) - 4000)
reset()
rc, out = run(TEXT, NUM, "old-ok-env", env_extra={"SEEME_APPROVAL_WINDOW_S": "7200"})
check("window is configurable (7200 s): the same age is accepted and sent", rc == 0 and "SEND" in kinds(), out)
approve("past-timeout", timeout_at=int(time.time()) - 5)
reset()
rc, out = run(TEXT, NUM, "past-timeout")
check("approval past its own timeout_at: refused, no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
approve("late-decision", resolved_at=int(time.time()) - 10, timeout_at=int(time.time()) - 100)
reset()
rc, out = run(TEXT, NUM, "late-decision")
check("decided after its timeout_at: refused", rc != 0 and "SEND" not in kinds(), out)
approve("no-resolved", resolved_at=None)
reset()
rc, out = run(TEXT, NUM, "no-resolved")
check("no resolved_at: refused", rc != 0 and "SEND" not in kinds(), out)

# --- 7. consume failures ---
for aid, mode in (("c500", "500"), ("cnotok", "notok")):
    approve(aid)
    CONSUME_MODE[aid] = mode
    reset()
    rc, out = run(TEXT, NUM, aid)
    check("consume %s: no send, non-zero exit, one-line reason" % mode, rc != 0 and "SEND" not in kinds() and "CONSUME" in kinds() and one_line_clean(out), out)
reset()
rc, out = run(TEXT, NUM, "does-not-exist")
check("unknown approval: no consume, no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
# --- 8. other statuses / categories / dry-run ---
approve("pending", status="pending")
reset()
rc, out = run(TEXT, NUM, "pending")
check("pending approval: no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
approve("wrongcat", category="memory_maintenance")
reset()
rc, out = run(TEXT, NUM, "wrongcat")
check("wrong category: no send", rc != 0 and "SEND" not in kinds(), out)
approve("dry-1")
reset()
rc, out = run(TEXT, NUM, "dry-1", extra=("--dry-run",))
check("dry-run with a matching approval: exit 0, no consume, no send", rc == 0 and kinds() == ["GET"], str(LOG) + out)
reset()
rc, out = run(TEXT + "x", NUM, "dry-1", extra=("--dry-run",))
check("dry-run with a changed text: refused", rc != 0, out)
reset()
rc, out = run("teszt", "36305552860", None)
check("internal number: sent, no approval needed, no consume", rc == 0 and kinds() == ["SEND"], str(LOG) + out)

# --- 9. --print-anchor ---
rc, out = run(TEXT, "06 30 123 4567", None, extra=("--print-anchor",))
check("--print-anchor equals the independently computed canonical sha256", rc == 0 and out.strip() == anchor(NUM, TEXT), out)
rc, out2 = run(TEXT, "+36301234567", None, extra=("--print-anchor",))
check("--print-anchor is the same for every spelling of the number", out2.strip() == out.strip(), out2)

# --- 10. mutation control: without the hash comparison a changed text IS sent ---
src = open(SCRIPT, encoding="utf-8").read()
mut_src = src.replace("    if ch != anchor:\n", "    if False:\n")
mut_path = os.path.join(FIX, "seeme-send-mutated.py")
with open(mut_path, "w", encoding="utf-8") as fh:
    fh.write(mut_src)
check("the mutation changed the script", mut_src != src)
approve("mut-1")
reset()
rc, out = run(TEXT + " MAS", NUM, "mut-1", script=mut_path)
check("mutated client (no pre-check): the server-side hash match still refuses", rc != 0 and "SEND" not in kinds(), str(LOG) + out)
LAX["hash"] = True   # control: a lax server AND a mutated client = the changed text goes out
approve("mut-2")
reset()
rc, out = run(TEXT + " MAS", NUM, "mut-2", script=mut_path)
LAX["hash"] = False
check("mutation control: with both hash comparisons removed the changed text IS sent (the cases above can fail)",
      rc == 0 and LOG[-1] == "SEND %s %s MAS" % (NUM, TEXT), str(LOG) + out)

print()
print("%d passed, %d failed" % (passed, len(failed)))
TMPROOT.cleanup()
sys.exit(1 if failed else 0)
