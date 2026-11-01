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
  - B1: an approval whose action_payload is not byte-identical to the canonical envelope (other
    text, other number, missing, spaced, extra key, not a string) -> no consume, no send;
  - B2: the description names exactly one phone number (none / two -> no send);
  - B4: --approval must be a UUID, refused before any request (path tricks, newline, upper case);
  - B5: the 1800 s window is fixed, SEEME_APPROVAL_WINDOW_S may only narrow it;
  - mutation controls: with the hash / payload / one-number comparisons removed, the bad case IS sent.

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
import uuid
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


def canon(number, text):
    return json.dumps({"kind": "sms", "number": number, "text": text},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def uid(name):
    """The approval id the client accepts is a UUID (B4): the test names map to stable UUIDs."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "seeme-test-" + name))


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


def run(text, to, approval, extra=(), script=SCRIPT, env_extra=None, raw_approval=False):
    env = dict(os.environ)
    env.update(ENVV)
    env.update(env_extra or {})
    args = [sys.executable, script, "--to", to]
    if approval:
        args += ["--approval", approval if raw_approval else uid(approval)]
    args += list(extra)
    p = subprocess.run(args, input=text.encode("utf-8"), capture_output=True, env=env, timeout=60)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def reset():
    with LOCK:
        del LOG[:]
        del CONSUMED_BODIES[:]


def kinds():
    return [l.split(" ")[0] for l in LOG]


def approve(name, number=NUM, text=TEXT, **over):
    aid = uid(name)
    rec = {
        "id": aid, "status": "approved", "category": "external_message",
        "action_description": "SMS-t kuldenek a %s szamra (SeeMe)." % number,
        "action_payload": canon(number, text),
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
approve("old-env-wide", resolved_at=int(time.time()) - 4000)
reset()
rc, out = run(TEXT, NUM, "old-env-wide", env_extra={"SEEME_APPROVAL_WINDOW_S": "7200"})
check("B5: the env variable cannot WIDEN the window (7200 asked, 1800 fixed): refused, no consume, no send",
      rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
approve("old-env-huge", resolved_at=int(time.time()) - 4000)
reset()
rc, out = run(TEXT, NUM, "old-env-huge", env_extra={"SEEME_APPROVAL_WINDOW_S": "999999999"})
check("B5: a huge env window is capped at 1800 too", rc != 0 and "SEND" not in kinds(), out)
approve("env-wide-ok", resolved_at=int(time.time()) - 100)
reset()
rc, out = run(TEXT, NUM, "env-wide-ok", env_extra={"SEEME_APPROVAL_WINDOW_S": "7200"})
check("B5: inside the fixed window a wide env value changes nothing: sent, consume asks for 1800 s",
      rc == 0 and "SEND" in kinds() and CONSUMED_BODIES[0].get("max_age_seconds") == 1800, out + str(CONSUMED_BODIES))
for bad in ("0", "-5", "abc", ""):
    approve("env-bad-" + (bad or "empty"), resolved_at=int(time.time()) - 100)
    reset()
    rc, out = run(TEXT, NUM, "env-bad-" + (bad or "empty"), env_extra={"SEEME_APPROVAL_WINDOW_S": bad})
    check("B5: env value %r falls back to 1800: a 100 s old decision is sent" % bad, rc == 0 and "SEND" in kinds(), out)
approve("env-narrow-old", resolved_at=int(time.time()) - 100)
reset()
rc, out = run(TEXT, NUM, "env-narrow-old", env_extra={"SEEME_APPROVAL_WINDOW_S": "30"})
check("B5: the env variable may NARROW the window (30 s): a 100 s old decision is refused", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)
approve("env-narrow-new", resolved_at=int(time.time()) - 5)
reset()
rc, out = run(TEXT, NUM, "env-narrow-new", env_extra={"SEEME_APPROVAL_WINDOW_S": "30"})
check("B5: narrowed window, fresh decision: sent, consume asks for 30 s",
      rc == 0 and "SEND" in kinds() and CONSUMED_BODIES[0].get("max_age_seconds") == 30, out + str(CONSUMED_BODIES))
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
    CONSUME_MODE[uid(aid)] = mode
    reset()
    rc, out = run(TEXT, NUM, aid)
    check("consume %s: no send, non-zero exit, one-line reason" % mode, rc != 0 and "SEND" not in kinds() and "CONSUME" in kinds() and one_line_clean(out), out)
reset()
rc, out = run(TEXT, NUM, "does-not-exist")
check("unknown approval: no consume, no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), out)

# --- 7b. B1: the approval must carry the canonical envelope as action_payload ---
OTHER = TEXT + " Es nezd meg: https://pelda.example/x"
approve("pl-other-text", action_payload=canon(NUM, OTHER))   # hash is of TEXT, payload (what the owner saw) is OTHER
reset()
rc, out = run(TEXT, NUM, "pl-other-text")
check("B1: payload shows another text than the one hashed/sent: no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
check("B1: payload mismatch: one-line reason without text or full number", one_line_clean(out), out)
approve("pl-other-num", action_payload=canon("36709998877", TEXT))
reset()
rc, out = run(TEXT, NUM, "pl-other-num")
check("B1: payload shows another number: no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
approve("pl-none", action_payload=None)
reset()
rc, out = run(TEXT, NUM, "pl-none")
check("B1: approval without action_payload (hash only): no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
approve("pl-spaced", action_payload=canon(NUM, TEXT).replace(",", ", "))
reset()
rc, out = run(TEXT, NUM, "pl-spaced")
check("B1: same data but not byte-identical to the canonical JSON: no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), str(LOG) + out)
approve("pl-extra", action_payload=json.dumps({"kind": "sms", "number": NUM, "text": TEXT, "extra": 1}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
reset()
rc, out = run(TEXT, NUM, "pl-extra")
check("B1: payload with an extra key: no consume, no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), str(LOG) + out)
approve("pl-nonstr", action_payload={"kind": "sms"})
reset()
rc, out = run(TEXT, NUM, "pl-nonstr")
check("B1: payload that is not a string: no consume, no send", rc != 0 and "SEND" not in kinds() and "CONSUME" not in kinds(), str(LOG) + out)

# --- 7c. B2: exactly one phone number in the description ---
approve("d-none", action_description="SMS az ugyfelnek (SeeMe).")
reset()
rc, out = run(TEXT, NUM, "d-none")
check("B2: description names no number: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), out)
approve("d-two", action_description="SMS a %s szamra, masolat a 36709998877 szamra" % NUM)
reset()
rc, out = run(TEXT, NUM, "d-two")
check("B2: description names the recipient AND another number: refused, no consume, no send", rc != 0 and "CONSUME" not in kinds() and "SEND" not in kinds(), out)
check("B2: the refusal does not print the second number", "36709998877" not in out and NUM not in out, out)
approve("d-same-twice", action_description="SMS a +36 30 123 4567 szamra (%s), ugyanaz a szam" % NUM)
reset()
rc, out = run(TEXT, NUM, "d-same-twice")
check("B2: the same number twice (other spellings) is still ONE number: sent", rc == 0 and "SEND" in kinds(), out)

# --- 7d. B4: --approval must be a UUID before any request is made ---
for bad in ("../../etc/passwd", "appr-ext-1", "not-a-uuid\nFAKE-LOG-LINE", "11111111-1111-1111-1111-11111111111Z",
            "11111111-1111-1111-1111-1111111111111", "11111111-1111-1111-1111-111111111111/consume",
            "11111111-1111-1111-1111-111111111111?x=1", uid("x").upper()):
    reset()
    rc, out = run(TEXT, NUM, bad, raw_approval=True)
    check("B4: --approval %r refused before any request" % bad, rc != 0 and LOG == [] and "nem UUID" in out, str(LOG) + out)
reset()
rc, out = run("teszt", "36305552860", "../x", raw_approval=True)
check("B4: a malformed --approval is refused for an internal number too (it would reach the log)", rc != 0 and LOG == [], str(LOG) + out)

# --- 7e. --print-request builds the request this script then accepts ---
rc, out = run(TEXT, "06 30 123 4567", None, extra=("--print-request", "ezermester", "--description", "Indok: teszt."))
try:
    req = json.loads(out)
except Exception:
    req = {}
check("--print-request: valid JSON for an external_message with the canonical envelope as action_payload and its sha256 as content_hash",
      rc == 0 and req.get("category") == "external_message" and req.get("agent_id") == "ezermester"
      and req.get("action_payload") == canon(NUM, TEXT) and req.get("content_hash") == anchor(NUM, TEXT)
      and req.get("content_hash") == hashlib.sha256(req.get("action_payload", "").encode("utf-8")).hexdigest()
      and NUM in req.get("action_description", ""), out)
rc, out = run(TEXT, NUM, None, extra=("--print-request", "ezermester", "--description", "Masolat: 36709998877"))
check("--print-request: a --description naming another number is refused", rc != 0 and "36709998877" not in out, out)
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
# (the payload comparison goes too: a changed text no longer matches the approval's envelope either)
mut_src = src.replace("    if ch != anchor:\n", "    if False:\n").replace('    if rec.get("action_payload") != payload:\n', "    if False:\n")
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

# --- 11. mutation control for B1: without the payload comparison a hash-only approval IS sent ---
# (the fake dashboard, like the real consume, checks the hash but not the payload)
mut2_src = src.replace('    if rec.get("action_payload") != payload:\n', "    if False:\n")
mut2_path = os.path.join(FIX, "seeme-send-mutated-payload.py")
with open(mut2_path, "w", encoding="utf-8") as fh:
    fh.write(mut2_src)
check("the payload mutation changed the script", mut2_src != src)
approve("mut-pl", action_payload=canon(NUM, OTHER))
reset()
rc, out = run(TEXT, NUM, "mut-pl", script=mut2_path)
check("mutation control (B1): with the payload comparison removed an approval showing another text IS sent (the payload cases above can fail)",
      rc == 0 and LOG[-1] == "SEND %s %s" % (NUM, TEXT), str(LOG) + out)
# mutation control for B2: with the exact-one-number test removed the two-number description IS sent
mut3_src = src.replace("    if named != {to_number}:\n", "    if to_number not in named:\n")
mut3_path = os.path.join(FIX, "seeme-send-mutated-onenum.py")
with open(mut3_path, "w", encoding="utf-8") as fh:
    fh.write(mut3_src)
check("the one-number mutation changed the script", mut3_src != src)
approve("mut-two", action_description="SMS a %s szamra, masolat a 36709998877 szamra" % NUM)
reset()
rc, out = run(TEXT, NUM, "mut-two", script=mut3_path)
check("mutation control (B2): with the exact-one-number test relaxed the two-number description IS sent", rc == 0 and "SEND" in kinds(), str(LOG) + out)

# --- 12. B6: the consumer refuses the texts the server refuses (format characters, C0 other than \n, DEL, C1) ---
GOOD_ML = "Kedves Ügyfelünk!\n\nA ma esedékes időpontot áttettük holnap 10:00-ra (árvíztűrő tükörfúrógép).\nÜdv: Fireeng \U0001F600"
BAD_TEXTS = [
    ("U+202E", "Holnap 10-kor.‮"), ("U+2066", "Szia ⁦x"), ("U+200B", "Holnap​ 10-kor."),
    ("U+200D", "Hol‍nap"), ("U+FEFF", "﻿Holnap 10-kor."), ("U+00AD", "Hol­nap"),
    ("CR", "Holnap\r10-kor."), ("CRLF", "Holnap\r\n10-kor."), ("TAB", "Holnap\t10-kor."),
    ("NUL", "Holnap\u0000"), ("ESC", "Holnap\u001b[0m"), ("DEL", "Holnap\u007f"),
    ("U+0085", "Holnap\u0085 10-kor."), ("U+009F", "Holnap\u009f"),
]
rc, out = run(GOOD_ML, "06 30 123 4567", None, extra=("--print-anchor",))
check("B6: a normal multi-line Hungarian text with accents and an emoji still passes (--print-anchor = sha256 of its envelope)",
      rc == 0 and out.strip() == anchor(NUM, GOOD_ML), out)
rc, out = run(GOOD_ML, NUM, None, extra=("--print-request", "ezermester"))
try:
    req = json.loads(out)
except Exception:
    req = {}
check("B6: --print-request for that text carries the canonical envelope and its hash",
      rc == 0 and req.get("action_payload") == canon(NUM, GOOD_ML) and req.get("content_hash") == anchor(NUM, GOOD_ML), out)
for name, bad_text in BAD_TEXTS:
    # an approval that WOULD match the bad text exactly (hash and payload): only the character rule can stop it
    approve("b6-" + name, text=bad_text)
    reset()
    rc, out = run(bad_text, NUM, "b6-" + name)
    check("B6: text with %s is refused before any request: no GET, no consume, no send, one line without the text" % name,
          rc != 0 and LOG == [] and out.count("FAIL:") == 1 and "tiltott karakter" in out and "Holnap" not in out and "Szia" not in out, str(LOG) + out)
    for flag in (("--print-anchor",), ("--print-request", "ezermester"), ("--dry-run",)):
        rc, out = run(bad_text, NUM, None, extra=flag)
        check("B6: text with %s is refused for %s" % (name, flag[0]), rc != 0 and "tiltott karakter" in out and not out.lstrip().startswith("{"), out)
    reset()
    rc, out = run(bad_text, "36305552860", None)
    check("B6: text with %s is refused for an internal number too: no send" % name, rc != 0 and LOG == [], str(LOG) + out)

print()
print("%d passed, %d failed" % (passed, len(failed)))
TMPROOT.cleanup()
sys.exit(1 if failed else 0)
