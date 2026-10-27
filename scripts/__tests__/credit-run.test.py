#!/usr/bin/env python3
"""fec6335f N4b: the headless-run caller (scripts/credit-run.py), against a stub dashboard.

Written from the blueprint (4.2, N4b, 11.6) and the spec (E-05), not from the code:
  - the request: POST /api/credit-gate/runs with the Bearer token read at run time from an injectable
    file, X-Agent-Id: ezermester, a JSON body built by json.dumps (the prompt verbatim: quotes, $(...),
    backticks and accents reach the dashboard as text), never a config hash;
  - the exit codes: 0 finished, 2 the run failed (a 409 while polling or an overlong wait cancels it
    first; only a cancel the dashboard took (202) makes it 2, else 7: the run may go on), 3 the gate does
    not run it (409: closed, off, shadow, hash not approved -> the subagent; approval_spent is passed
    on), 4 a bad request (refused here, or 400/404/413), 5 the dashboard cannot be used before anything
    started (refused connection, no token, 401, 5xx -> the subagent), 6 interrupted and the run
    cancelled (the cancel taken, 202; an interrupt whose cancel is not taken is 7), 7 unknown (the POST's answer was lost, or the run cannot be polled: NOT the subagent);
  - the poll: every --poll-s seconds (10 by default) until the run is done; a passing outage is
    retried, a lasting one is 7 with the run id; an overlong wait cancels the run;
  - BE-4b P7: SIGTERM, SIGHUP or SIGINT while the POST is in flight does not lose the run: the answer
    is awaited, the run is cancelled, exit 6; during the poll the same;
  - the dashboard must be on loopback (the token never leaves the host), redirects are not followed;
  - nothing secret is printed: not the token, not the prompt.

Every socket in this process (and in the CLI child, which runs through --guarded-run) goes through a
guard that refuses a non-loopback connect(), a non-loopback name lookup, the live CDP ports
(18800, 18899) and this suite's own blocked test port 18993 -- BEFORE the connect; self-tested first.

Run: python3 -I <thisfile>   Exit 0 = all pass.
Also: python3 -I <thisfile> --guarded-run <script> [args...]  runs <script> as __main__ behind the guard.
"""
import importlib.util
import io
import json
import os
import runpy
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "credit-run.py")
BLOCKED_PORTS = {18800, 18899, 18993}
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def install_guard():
    """Refuse every non-loopback connect and name lookup, and the blocked ports, before the call."""
    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_getaddrinfo = socket.getaddrinfo

    def check(addr):
        if isinstance(addr, (str, bytes)):
            return  # AF_UNIX
        if not isinstance(addr, tuple) or len(addr) < 2:
            raise PermissionError("credit-run test guard: unreadable address refused")
        host, port = addr[0], addr[1]
        if host not in LOOPBACK or int(port) in BLOCKED_PORTS:
            raise PermissionError("credit-run test guard: connect to %s:%s refused" % (host, port))

    def connect(self, addr):
        check(addr)
        return orig_connect(self, addr)

    def connect_ex(self, addr):
        check(addr)
        return orig_connect_ex(self, addr)

    def getaddrinfo(host, port, *a, **kw):
        h = host.decode() if isinstance(host, bytes) else host
        if h is not None and h not in LOOPBACK:
            raise PermissionError("credit-run test guard: name lookup of %s refused" % h)
        return orig_getaddrinfo(host, port, *a, **kw)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.getaddrinfo = getaddrinfo


def guard_selftest():
    """True when the guard refuses the blocked test port, a non-loopback address and a lookup."""
    refused = 0
    for addr in (("127.0.0.1", 18993), ("192.0.2.1", 443)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(addr)
        except PermissionError:
            refused += 1
        except OSError:
            pass
        finally:
            s.close()
    try:
        socket.getaddrinfo("example.com", 443)
    except PermissionError:
        refused += 1
    except OSError:
        pass
    return refused == 3


if len(sys.argv) >= 3 and sys.argv[1] == "--guarded-run":
    install_guard()
    if not guard_selftest():
        sys.stderr.write("credit-run test guard: self-test failed\n")
        sys.exit(70)
    script = sys.argv[2]
    sys.argv = [script] + sys.argv[3:]
    runpy.run_path(script, run_name="__main__")
    sys.exit(0)

install_guard()

failed = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failed.append(name)


check("guard: the blocked test port, a non-loopback address and a lookup are refused before the call", guard_selftest())

TOKEN = "test-token-not-a-secret-%s" % os.getpid()


class Stub(BaseHTTPRequestHandler):
    seen = []       # (method, path, headers dict, parsed body)
    polls = {}      # run id -> GET count
    runs = {}       # run id -> scenario

    def log_message(self, *a):
        pass

    def _send(self, status, obj, raw=None, headers=None):
        data = raw if raw is not None else json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _record(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except Exception:
            body = "UNPARSED"
        Stub.seen.append((self.command, self.path, dict(self.headers), body))
        return body

    def do_POST(self):
        body = self._record()
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self._send(401, {"error": "Unauthorized"})
        if self.path.endswith("/cancel"):
            if Stub.runs.get(self.path.split("/")[-2]) in ("slowdropped", "slowpostdropped"):
                self.close_connection = True
                return None  # the connection drops without an answer: the cancel's fate is unknown
            if Stub.runs.get(self.path.split("/")[-2]) in ("offstuck", "slowstuck", "slowpoststuck"):
                return self._send(409, {"reason": "gate_off"})  # the dashboard cannot stop it either
            return self._send(202, {"run_id": self.path.split("/")[-2], "cancelling": True})
        if self.path != "/api/credit-gate/runs":
            return self._send(404, {"error": "Not found"})
        node = (body or {}).get("node_id") if isinstance(body, dict) else None
        if node in ("closed", "off", "shadow", "hash"):
            reason = {"closed": "gate_closed", "off": "gate_off", "shadow": "gate_shadow", "hash": "hash_not_approved"}[node]
            return self._send(409, {"reason": reason, "detail": "disarm" if node == "closed" else None})
        if node == "spent":
            return self._send(409, {"reason": "binary_changed", "approval_spent": True})
        if node in ("slowpost", "slowpoststuck", "slowpostdropped", "slowclosed"):
            time.sleep(1.5)  # the dashboard is starting the run; the answer is on its way
            if node == "slowclosed":
                return self._send(409, {"reason": "gate_closed"})
        if node == "lost":
            time.sleep(1.5)  # longer than the CLI's --http-timeout-s in the test
            try:
                return self._send(202, {"run_id": "hr-lost-late", "status": "running"})
            except Exception:
                return None
        if node == "dropped":
            self.close_connection = True
            return None  # the run may have started; no answer at all
        if node == "bad":
            return self._send(400, {"error": "cwd: refused", "reason": "cwd_forbidden"})
        if node == "big":
            return self._send(413, {"error": "body too large"})
        if node == "boom":
            return self._send(500, {"error": "internal"})
        if node == "garbled":
            return self._send(202, None, raw=b"<html>not json</html>")
        run_id = "hr-%s-%d" % (node, len(Stub.seen))
        Stub.runs[run_id] = node
        return self._send(202, {"run_id": run_id, "mode": (body or {}).get("mode"), "status": "running"})

    def do_GET(self):
        self._record()
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self._send(401, {"error": "Unauthorized"})
        run_id = self.path.rsplit("/", 1)[-1]
        node = Stub.runs.get(run_id)
        n = Stub.polls[run_id] = Stub.polls.get(run_id, 0) + 1
        running = {"run_id": run_id, "status": "running", "done": False}
        if node is None or node == "vanished":
            return self._send(404, {"reason": "not_found"})
        if node == "gone":
            return self._send(503, {"error": "down"})
        if node in ("offnow", "offstuck"):
            return self._send(409, {"reason": "gate_off"})
        if node == "flaky" and n == 1:
            return self._send(503, {"error": "down"})
        if node in ("slow", "slowpost", "slowstuck", "slowdropped", "slowpoststuck", "slowpostdropped"):
            return self._send(200, running)
        if node == "redirect":
            # A loopback target, so only the CLI's own refusal can keep the token from following it.
            return self._send(302, {}, headers={"Location": "http://127.0.0.1:%d/api/steal" % self.server.server_address[1]})
        if node == "ok" and n < 3:
            return self._send(200, running)
        if node in ("fail", "timeout"):
            return self._send(200, {"run_id": run_id, "status": "failed" if node == "fail" else "timeout", "done": True, "exit_code": 1})
        return self._send(200, {
            "run_id": run_id, "status": "succeeded", "done": True, "exit_code": 0, "cli_usd": "0.074983", "est_usd": "0.114535",
            "is_error": False, "num_turns": 3, "result_text": "all done", "usage": {"input_tokens": 8},
        })


srv = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=srv.serve_forever, daemon=True).start()
API = "http://127.0.0.1:%d" % srv.server_address[1]

tmp = tempfile.mkdtemp(prefix="credit-run-test-")
TOKEN_FILE = os.path.join(tmp, "token")
with open(TOKEN_FILE, "w", encoding="utf-8") as fh:
    fh.write(TOKEN + "\n")
WT = os.path.join(tmp, "wt")
os.mkdir(WT)
PROMPT = 'Do the "node": $(touch /tmp/credit-run-pwned) `id` árvíztűrő\nline two\n'
PROMPT_FILE = os.path.join(tmp, "prompt.txt")
with open(PROMPT_FILE, "w", encoding="utf-8") as fh:
    fh.write(PROMPT)


def args_for(node, **over):
    a = {"--node": node, "--model": "claude-sonnet-5-5", "--effort": "high", "--budget": "0.40", "--cwd": WT, "--prompt-file": PROMPT_FILE,
         "--api": API, "--token-file": TOKEN_FILE, "--poll-s": "0.05"}
    a.update(over)
    out = []
    for k, v in a.items():
        if v is not None:
            out += [k, v]
    return out


def run(node, *extra, **over):
    """The CLI as a child process behind this suite's guard: (rc, last JSON line, stdout + stderr)."""
    p = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--guarded-run", CLI, *args_for(node, **over), *extra],
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    lines = [ln for ln in p.stdout.strip().splitlines() if ln.strip()]
    try:
        last = json.loads(lines[-1]) if lines else {}
    except Exception:
        last = {"unparsed": p.stdout}
    return p.returncode, last, p.stdout + p.stderr


def posts():
    return [s for s in Stub.seen if s[0] == "POST" and s[1] == "/api/credit-gate/runs"]


# --- a run that finishes ------------------------------------------------------------------------
before = len(Stub.seen)
rc, last, text = run("ok")
check("a run that succeeds exits 0", rc == 0)
check("the result is on stdout (one JSON line): status, result text, cost", last.get("rc") == 0 and last.get("status") == "succeeded"
      and last.get("result_text") == "all done" and last.get("cli_usd") == "0.074983" and last.get("run_id", "").startswith("hr-ok-"))
new = Stub.seen[before:]
check("one POST, then a GET per poll until done (3 polls)", [s[0] for s in new] == ["POST", "GET", "GET", "GET"])
method, path, headers, body = new[0] if new else (None, None, {}, None)
check("the request goes to POST /api/credit-gate/runs", path == "/api/credit-gate/runs")
check("the request carries the Bearer token read from the file", headers.get("Authorization") == "Bearer " + TOKEN)
check("the request says X-Agent-Id: ezermester (a label, not a credential)", headers.get("X-Agent-Id") == "ezermester")
check("the body is JSON", headers.get("Content-Type", "").startswith("application/json"))
check("the body is exactly the run request, the prompt verbatim (json.dumps, no shell)", body == {
    "node_id": "ok", "model": "claude-sonnet-5-5", "effort": "high", "budget_usd": "0.40", "cwd": WT, "prompt": PROMPT, "mode": "normal"})
check("the polls go to GET /api/credit-gate/runs/<id> with the token", all(s[1] == "/api/credit-gate/runs/" + last.get("run_id", "?")
                                                                            and s[2].get("Authorization") == "Bearer " + TOKEN for s in new[1:]))
check("nothing secret is printed: neither the token nor the prompt", TOKEN not in text and "árvíztűrő" not in text and "credit-run-pwned" not in text)
check("the prompt's $(...) never ran", not os.path.exists("/tmp/credit-run-pwned"))

rc, last, _ = run("ok", "--canary-approval-id", "c6a1-approval")
cb = (posts()[-1][3] if posts() else None) or {}
check("a canary: mode canary and the approval id; never a config hash", rc == 0 and cb.get("mode") == "canary"
      and cb.get("canary_approval_id") == "c6a1-approval" and "config_hash" not in cb and cb.get("budget_usd") == "0.40")

# --- the gate does not run it: 3 (-> the subagent) ------------------------------------------------
for node, reason in (("closed", "gate_closed"), ("off", "gate_off"), ("shadow", "gate_shadow"), ("hash", "hash_not_approved")):
    rc, last, _ = run(node)
    check("409 %s exits 3 and names the reason" % reason, rc == 3 and last.get("reason") == reason)

# --- a bad request: 4 -----------------------------------------------------------------------------
rc, last, _ = run("bad")
check("a 400 from the dashboard exits 4 with its reason", rc == 4 and last.get("reason") == "cwd_forbidden")
rc, last, _ = run("big")
check("a 413 exits 4", rc == 4)
big = os.path.join(tmp, "big.txt")
with open(big, "wb") as fh:
    fh.write(b"x" * (256 * 1024 + 1))
just = os.path.join(tmp, "just.txt")
with open(just, "wb") as fh:
    fh.write(b"x" * (256 * 1024))
empty = os.path.join(tmp, "empty.txt")
open(empty, "w").close()
latin1 = os.path.join(tmp, "latin1.txt")
with open(latin1, "wb") as fh:
    fh.write(b"\xe1rv\xedz")
nul = os.path.join(tmp, "nul.txt")
with open(nul, "wb") as fh:
    fh.write(b"a\x00b")
before = len(Stub.seen)
local = [
    ("budget '5'", {"--budget": "5"}), ("budget '-1.00'", {"--budget": "-1.00"}), ("budget '1.000'", {"--budget": "1.000"}),
    ("budget '0.00'", {"--budget": "0.00"}), ("budget ' 1.00'", {"--budget": " 1.00"}), ("budget '1e2'", {"--budget": "1e2"}),
    ("effort medium", {"--effort": "medium"}), ("a relative cwd", {"--cwd": "wt/proj"}), ("a missing prompt file", {"--prompt-file": os.path.join(tmp, "nope")}),
    ("a prompt above 256 KB", {"--prompt-file": big}), ("an empty prompt", {"--prompt-file": empty}), ("a prompt that is not UTF-8", {"--prompt-file": latin1}),
    ("a NUL in the prompt", {"--prompt-file": nul}), ("a node id with a space", {"--node": "N 1"}), ("a missing --cwd", {"--cwd": None}),
    ("an approval id with a slash", {"--canary-approval-id": "a/b"}), ("a dashboard that is not on loopback", {"--api": "http://192.0.2.1:3420"}),
    ("an https dashboard elsewhere", {"--api": "https://example.com"}), ("a zero poll interval", {"--poll-s": "0"}),
]
for name, over in local:
    rc, last, _ = run("ok", **over)
    check("refused here, exit 4: %s" % name, rc == 4 and "error" in last)
check("none of the local refusals reached the dashboard", len(Stub.seen) == before)
rc, _, _ = run("ok", **{"--prompt-file": just})
check("a prompt of exactly 256 KB is sent", rc == 0)

# --- the dashboard cannot be used: 5 (-> the subagent) ----------------------------------------------
closed = socket.socket()
closed.bind(("127.0.0.1", 0))
dead = "http://127.0.0.1:%d" % closed.getsockname()[1]
closed.close()
rc, last, _ = run("ok", **{"--api": dead})
check("an unreachable dashboard exits 5", rc == 5 and "unreachable" in (last.get("error") or ""))
before = len(Stub.seen)
rc, last, text = run("ok", **{"--token-file": os.path.join(tmp, "missing-token")})
check("a missing token file exits 5, and nothing is sent", rc == 5 and len(Stub.seen) == before)
blank = os.path.join(tmp, "blank-token")
with open(blank, "w") as fh:
    fh.write("\n")
rc, _, _ = run("ok", **{"--token-file": blank})
check("an empty token file exits 5", rc == 5)
wrong = os.path.join(tmp, "wrong-token")
with open(wrong, "w") as fh:
    fh.write("not-the-token\n")
rc, last, text = run("ok", **{"--token-file": wrong})
check("a 401 exits 5, and the token is not printed", rc == 5 and "not-the-token" not in text)
rc, _, _ = run("boom")
check("a 500 exits 5", rc == 5)
rc, last, _ = run("garbled")
check("an unreadable 202 exits 7 (a run may have started: not the subagent)", rc == 7)
before = len(Stub.seen)
rc, last, _ = run("redirect")
check("a redirect is not followed (the token goes nowhere else): exit 7 (after the start), no request to the target",
      rc == 7 and not any(s[1] == "/api/steal" for s in Stub.seen[before:]) and len(Stub.seen[before:]) == 4)

# --- the run itself fails: 2 ----------------------------------------------------------------------
rc, last, _ = run("fail")
check("a failed run exits 2 with its status", rc == 2 and last.get("status") == "failed")
rc, last, _ = run("timeout")
check("a timed-out run exits 2", rc == 2 and last.get("status") == "timeout")
rc, last, _ = run("vanished")
check("a run the dashboard no longer knows (404) exits 2", rc == 2)

# --- the poll ---------------------------------------------------------------------------------------
rc, last, _ = run("flaky")
check("one failed poll is retried: exit 0", rc == 0 and last.get("status") == "succeeded")
rc, last, _ = run("gone")
gone_id = last.get("run_id")
check("a dashboard that stays away while polling exits 7 after 3 tries, naming the run", rc == 7 and Stub.polls.get(gone_id) == 3
      and gone_id is not None)
before = len(Stub.seen)
rc, last, _ = run("offnow")
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("a 409 while polling sends the cancel first; the cancel taken (202): exit 2", rc == 2 and len(cancels) == 1
      and cancels[0][1] == "/api/credit-gate/runs/%s/cancel" % last.get("run_id") and last.get("cancelled") is True)
before = len(Stub.seen)
rc, last, _ = run("offstuck")
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("B7: a 409 while polling and a cancel that is not taken: exit 7 (the run may go on), naming the run",
      rc == 7 and len(cancels) == 1 and last.get("cancelled") is False and last.get("run_id", "").startswith("hr-offstuck-")
      and last.get("reason") == "gate_off")
rc, last, _ = run("spent")
check("a 409 that spent the canary approval says so (approval_spent), exit 3", rc == 3 and last.get("approval_spent") is True)

# --- the POST's answer lost: 7, never the subagent ----------------------------------------------------
rc, last, _ = run("lost", **{"--http-timeout-s": "0.5"})
check("a POST whose answer times out exits 7 (unknown)", rc == 7 and "run_id" not in last)
rc, last, _ = run("dropped")
check("a POST whose connection drops without an answer exits 7", rc == 7)

# --- BE-4b P7: a signal while the POST is in flight -----------------------------------------------------


def stub_saw(before, pred, deadline_s=20.0):
    """True once a request after index `before` of Stub.seen matches `pred`; False at the deadline."""
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if any(pred(s) for s in Stub.seen[before:]):
            return True
        time.sleep(0.01)
    return False


def signalled(node, sig, phase="post"):
    """The CLI behind the guard, signalled once the stub has seen it reach `phase` (B11: no fixed sleep).

    "post": its POST of `node` arrived (the stub holds the answer 1.5 s, so the signal lands while it is in
    flight); "poll": its first poll of the run arrived (the run then stays running until signalled).
    """
    before = len(Stub.seen)
    p = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "--guarded-run", CLI, *args_for(node)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
    if phase == "post":
        reached = stub_saw(before, lambda s: s[0] == "POST" and s[1] == "/api/credit-gate/runs"
                           and isinstance(s[3], dict) and s[3].get("node_id") == node)
    else:
        reached = stub_saw(before, lambda s: s[0] == "GET" and s[1].startswith("/api/credit-gate/runs/hr-%s-" % node))
    check("the stub saw the %s of %s before the %s" % (phase, node, sig.name), reached)
    p.send_signal(sig)
    out, err = p.communicate(timeout=30)
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    try:
        last = json.loads(lines[-1]) if lines else {}
    except Exception:
        last = {"unparsed": out}
    return p.returncode, last, out + err


for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    before = len(Stub.seen)
    rc, last, text = signalled("slowpost", sig)
    new = Stub.seen[before:]
    cancels = [s for s in new if s[0] == "POST" and s[1].endswith("/cancel")]
    check("P7 %s during the POST: the run that started is cancelled, exit 6" % sig.name,
          rc == 6 and last.get("run_id", "").startswith("hr-slowpost-") and len(cancels) == 1
          and cancels[0][1] == "/api/credit-gate/runs/%s/cancel" % last.get("run_id") and "Traceback" not in text)
before = len(Stub.seen)
rc, last, text = signalled("slowclosed", signal.SIGTERM)
check("P7 a signal during a POST that the gate refuses: nothing to cancel, exit 3",
      rc == 3 and not any(s[1].endswith("/cancel") for s in Stub.seen[before:]))
before = len(Stub.seen)
rc, last, text = signalled("slow", signal.SIGTERM, phase="poll")
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("a SIGTERM while polling cancels the run, exit 6", rc == 6 and len(cancels) == 1 and last.get("reason") == "interrupted")
check("a SIGTERM while polling with the cancel taken (202): exit 6, cancelled true",
      rc == 6 and last.get("cancelled") is True)
for node, what in (("slowstuck", "409"), ("slowdropped", "no answer")):
    before = len(Stub.seen)
    rc, last, text = signalled(node, signal.SIGTERM, phase="poll")
    cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
    check("B9: a SIGTERM while polling and a cancel answered with %s: exit 7 (the run may go on), cancelled false, naming the run" % what,
          rc == 7 and len(cancels) == 1 and last.get("cancelled") is False and last.get("reason") == "interrupted"
          and last.get("run_id", "").startswith("hr-%s-" % node) and last.get("signal") == "SIGTERM" and "Traceback" not in text)
for node, what in (("slowpoststuck", "409"), ("slowpostdropped", "no answer")):
    before = len(Stub.seen)
    rc, last, text = signalled(node, signal.SIGTERM)
    cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
    check("B9: a SIGTERM during the POST and a cancel answered with %s: exit 7, cancelled false, naming the run" % what,
          rc == 7 and len(cancels) == 1 and last.get("cancelled") is False and last.get("run_id", "").startswith("hr-%s-" % node)
          and "Traceback" not in text)
before = len(Stub.seen)
rc, last, _ = run("slow", **{"--max-wait-min": "0.002"})
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("a wait longer than --max-wait-min cancels the run and exits 2", rc == 2 and last.get("reason") == "client_timeout"
      and len(cancels) == 1 and cancels[0][1] == "/api/credit-gate/runs/%s/cancel" % last.get("run_id") and last.get("cancelled") is True)
before = len(Stub.seen)
rc, last, _ = run("slowstuck", **{"--max-wait-min": "0.002"})
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("B7: an overlong wait whose cancel is not taken: exit 7 (the run may go on), naming the run",
      rc == 7 and last.get("reason") == "client_timeout" and len(cancels) == 1 and last.get("cancelled") is False
      and last.get("run_id", "").startswith("hr-slowstuck-"))

# --- the importable module ---------------------------------------------------------------------------
spec = importlib.util.spec_from_file_location("credit_run", CLI)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
check("the default poll interval is 10 s", mod.DEFAULT_POLL_S == 10)
check("the default token file is the install's store/.dashboard-token, read at run time",
      mod.DEFAULT_TOKEN_FILE == os.path.join(os.path.dirname(os.path.dirname(CLI)), "store", ".dashboard-token"))
calls = []


def interrupting_sleep(s):
    calls.append(s)
    if len(calls) == 2:
        raise KeyboardInterrupt


buf = io.StringIO()
before = len(Stub.seen)
rc = mod.main(args_for("slow", **{"--poll-s": "7"}), sleep=interrupting_sleep, out=buf)
cancels = [s for s in Stub.seen[before:] if s[0] == "POST" and s[1].endswith("/cancel")]
check("main() sleeps --poll-s between polls", calls == [7.0, 7.0])
check("an interrupted wait cancels the run and exits 6", rc == 6 and len(cancels) == 1 and json.loads(buf.getvalue().strip().splitlines()[-1]).get("reason") == "interrupted")
buf = io.StringIO()
rc = mod.main(args_for("ok", **{"--budget": "5"}), sleep=interrupting_sleep, out=buf)
check("main() returns 4 for a bad budget", rc == 4)

# --- B9: the interrupt path with the HTTP call replaced (no network) -----------------------------------
def interrupt_with(cancel_answer):
    """mod.interrupted() with call() faked: (rc, JSON line, the calls made)."""
    made = []

    def fake_call(api, token, method, path, body=None, timeout=0):
        made.append((method, path))
        return cancel_answer

    real_call, real_sig = mod.call, mod._SIGNALS.signum
    mod.call = fake_call
    mod._SIGNALS.signum = signal.SIGTERM
    buf = io.StringIO()
    try:
        rc = mod.interrupted(buf, "http://127.0.0.1:1", "t", "hr-x-1", 1)
    finally:
        mod.call, mod._SIGNALS.signum = real_call, real_sig
    return rc, json.loads(buf.getvalue().strip().splitlines()[-1]), made


rc, line, made = interrupt_with((202, {"cancelling": True}))
check("B9 interrupted(): a cancel taken (202) is exit 6, cancelled true",
      rc == 6 and line.get("cancelled") is True and line.get("run_id") == "hr-x-1" and made == [("POST", "/api/credit-gate/runs/hr-x-1/cancel")])
rc, line, _ = interrupt_with((409, {"reason": "gate_off"}))
check("B9 interrupted(): a cancel answered 409 is exit 7, cancelled false", rc == 7 and line.get("cancelled") is False and line.get("run_id") == "hr-x-1")
rc, line, _ = interrupt_with((None, {"error": "dashboard answer lost: TimeoutError", "lost": True}))
check("B9 interrupted(): a cancel with no answer is exit 7, cancelled false", rc == 7 and line.get("cancelled") is False)
rc, line, _ = interrupt_with((500, None))
check("B9 interrupted(): a cancel answered 5xx is exit 7, cancelled false", rc == 7 and line.get("cancelled") is False)
rc, line, _ = interrupt_with((200, {}))
check("B9 interrupted(): only 202 counts as taken (a 200 is exit 7)", rc == 7 and line.get("cancelled") is False)
doc = mod.__doc__
check("B9 the docstring: 6 needs a taken cancel; 7 covers an interrupt whose cancel was not taken, and bans the fallback",
      "6  interrupted" in doc and "cancel was taken (202" in doc and "an interrupt" in doc.split("7  unknown")[1].split("One JSON line")[0]
      and "do NOT fall back to the subagent on the same\n     worktree" in doc)

# --- control: this suite can fail ---------------------------------------------------------------------
rc_ok, _, _ = run("ok")
rc_fail, _, _ = run("fail")
check("control: the stub tells a finished run from a failed one (0 vs 2)", (rc_ok, rc_fail) == (0, 2))

srv.shutdown()
print()
if failed:
    print("%d FAILED: %s" % (len(failed), failed), file=sys.stderr)
    sys.exit(1)
print("All credit-run tests passed.")
