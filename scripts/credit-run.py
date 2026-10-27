#!/usr/bin/env python3
"""Run one blueprint node headless on the Team API credit, through the dashboard (card fec6335f, N4b).

The ezermester's caller of the credit gate's runs API (blueprint 4.2): it asks the dashboard to start
`claude -p` for one node (POST /api/credit-gate/runs), then polls the run (GET /api/credit-gate/runs/<id>)
every --poll-s seconds until it is done. The dashboard decides everything that matters -- the gate, the
reservation, the config hash, the canary approval, the clean environment -- this script only asks and
waits. When the gate does not run it, the exit code says so, and the node goes to the usual subagent
(spec E-05).

Usage:
  credit-run.py --node <node id> --model <claude-opus-5-5|claude-sonnet-5-5> --effort <high|xhigh>
                --budget <USD, two decimals, e.g. 2.00> --cwd <the node's worktree> --prompt-file <path>
                [--canary-approval-id <id>] [--api http://localhost:3420] [--token-file PATH]
                [--max-wait-min 120]
  --canary-approval-id: a canary run (spec K-01): the owner's credit_gate_canary approval, which the
                        dashboard consumes; the budget must stay below 1.00.

Exit codes:
  0  the run finished (succeeded): its result is on stdout
  2  the run failed, timed out, was cancelled or lost; or the dashboard stopped following it (a 404
     while polling), or a 409 while polling or the --max-wait-min limit had the run cancelled (the
     cancel is sent first, and the dashboard took it: 202)
  3  the gate does not run it (409: closed, off, shadow, hash not approved, caller not allowed, ...)
     -> use the subagent. `approval_spent: true` in the output: a canary approval was used up.
  4  a bad request: refused here, or by the dashboard (400, 404, 413)
  5  the dashboard cannot be used and nothing started: the connection was refused, no token,
     401/403, 5xx -> use the subagent
  6  interrupted (SIGTERM, SIGHUP, SIGINT) and nothing is left running: either nothing had been sent
     yet, or the run that had started was cancelled and the cancel was taken (202; run_id in the
     output, `cancelled: true`)
  7  unknown: the POST's answer was lost (a timeout, a dropped connection, an unreadable 202), or the
     started run cannot be polled any more, or it had to be stopped (a 409 while polling, the
     --max-wait-min limit, an interrupt) and the dashboard did not take the cancel (a 409, an error
     or no answer instead of the 202; run_id in the output, `cancelled: false`). A run may be going
     on: do NOT fall back to the subagent on the same
     worktree; the coordinator decides.
One JSON line on stdout says what happened (progress goes to stderr). Nothing secret is printed: not the
token, not the prompt.

Signals: while the POST is in flight, SIGTERM, SIGHUP and SIGINT are blocked (pthread_sigmask), so the
run id of a run the dashboard has just started is never lost; a signal that came in the meantime is
handled right after the answer: a started run is cancelled. While polling, a signal cancels the run at
once. Either way the exit code is 6 only when the dashboard took the cancel (202); a cancel it did not
take (409, an error, no answer) leaves the run's fate unknown, and that is 7.

Who is calling: the request says X-Agent-Id: ezermester. The dashboard's Bearer token is shared by the
whole fleet, so it does not tell who calls, and the header is only a label anyone can type (blueprint
11.6): headless.allowedCallers stops an accidental caller, not a deliberate one. What bounds the
spending is the gate. The token is read from its file at run time and is sent only to a loopback
dashboard; proxies and redirects are not followed, so it cannot leave the host. The JSON body is
built by json.dumps: the prompt never passes through a shell.
"""
import argparse
import http.client
import json
import math
import os
import re
import signal
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_API = "http://localhost:3420"
DEFAULT_TOKEN_FILE = os.path.join(ROOT, "store", ".dashboard-token")
AGENT_ID = "ezermester"
DEFAULT_POLL_S = 10.0
DEFAULT_MAX_WAIT_MIN = 120.0
MAX_POLL_FAILURES = 3
MAX_PROMPT_BYTES = 256 * 1024
MAX_TOKEN_CHARS = 4096
HTTP_TIMEOUT_S = 30

RC_DONE, RC_RUN_FAILED, RC_GATE, RC_BAD_REQUEST, RC_UNUSABLE, RC_INTERRUPTED, RC_UNKNOWN = 0, 2, 3, 4, 5, 6, 7
STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)

_BUDGET = re.compile(r"^(0|[1-9][0-9]{0,5})\.[0-9]{2}$")
_NODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_MODEL = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_APPROVAL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
EFFORTS = ("high", "xhigh")
OPEN_STATUSES = ("starting", "spawning", "running")
# What the run's answer may carry to stdout (the dashboard's view of a run).
RUN_FIELDS = ("run_id", "node_id", "model", "effort", "mode", "status", "exit_code", "signal", "reason", "budget_usd", "est_usd",
              "cli_usd", "basis", "is_error", "num_turns", "total_cost_usd", "usage", "result_text")


class _Usage(Exception):
    pass


class _Interrupted(Exception):
    pass


class _SignalState:
    """What the handlers saw. `raising`: a signal interrupts the wait at once (not during a POST)."""
    def __init__(self):
        self.signum = None
        self.raising = False


_SIGNALS = _SignalState()


def _on_signal(signum, _frame):
    _SIGNALS.signum = signum
    if _SIGNALS.raising:
        _SIGNALS.raising = False
        raise _Interrupted()


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # exit 4, not argparse's 2 (2 means "the run failed" here)
        raise _Usage(message)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # the token stays with this host
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def parse_args(argv):
    p = _Parser(prog="credit-run.py", description="Run one node headless through the dashboard's credit gate.")
    p.add_argument("--node", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--effort", required=True)
    p.add_argument("--budget", required=True, help="the --max-budget-usd cap, two decimals")
    p.add_argument("--cwd", required=True, help="the node's worktree (absolute)")
    p.add_argument("--prompt-file", required=True)
    p.add_argument("--canary-approval-id")
    p.add_argument("--api", default=DEFAULT_API)
    p.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    p.add_argument("--max-wait-min", type=float, default=DEFAULT_MAX_WAIT_MIN)
    p.add_argument("--poll-s", type=float, default=DEFAULT_POLL_S, help=argparse.SUPPRESS)
    p.add_argument("--http-timeout-s", type=float, default=HTTP_TIMEOUT_S, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def loopback_api(api):
    """The dashboard URL when it is a plain http URL on this host; else None."""
    try:
        u = urllib.parse.urlsplit(api)
        host, _port = u.hostname, u.port
    except ValueError:
        return None
    if u.scheme != "http" or host not in _LOOPBACK or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        return None
    return api.rstrip("/")


def read_prompt(path):
    """(text, None) or (None, why): UTF-8, not empty, no NUL, at most MAX_PROMPT_BYTES bytes."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_PROMPT_BYTES + 1)
    except OSError as exc:
        return None, "prompt file not readable: %s" % type(exc).__name__
    if len(raw) > MAX_PROMPT_BYTES:
        return None, "prompt above %d bytes" % MAX_PROMPT_BYTES
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "prompt is not UTF-8"
    if text == "" or "\0" in text:
        return None, "prompt is empty or has a NUL"
    return text, None


def build_request(args):
    """(api, body, None) or (None, None, why) -- every check that needs no dashboard."""
    api = loopback_api(args.api)
    if api is None:
        return None, None, "--api must be http://localhost, 127.0.0.1 or [::1] (the token never leaves this host)"
    if not _NODE.match(args.node):
        return None, None, "--node: 1-64 of A-Z a-z 0-9 _ . : -"
    if not _MODEL.match(args.model):
        return None, None, "--model: not a model id"
    if args.effort not in EFFORTS:
        return None, None, "--effort: high or xhigh"
    if not _BUDGET.match(args.budget) or args.budget == "0.00":
        return None, None, "--budget: USD with exactly two decimals, above 0.00 (e.g. 2.00)"
    if "\0" in args.cwd or not os.path.isabs(args.cwd):
        return None, None, "--cwd: an absolute path"
    if args.canary_approval_id is not None and not _APPROVAL.match(args.canary_approval_id):
        return None, None, "--canary-approval-id: not an approval id"
    if not all(math.isfinite(x) and x > 0 for x in (args.poll_s, args.max_wait_min, args.http_timeout_s)):
        return None, None, "--poll-s, --max-wait-min and --http-timeout-s must be positive"
    prompt, why = read_prompt(args.prompt_file)
    if prompt is None:
        return None, None, why
    body = {"node_id": args.node, "model": args.model, "effort": args.effort, "budget_usd": args.budget, "cwd": args.cwd,
            "prompt": prompt, "mode": "normal"}
    if args.canary_approval_id is not None:
        body["mode"] = "canary"
        body["canary_approval_id"] = args.canary_approval_id
    return api, body, None


def read_token(path):
    """The dashboard token, read now; None when it is missing or not one line of visible characters."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            token = fh.read(MAX_TOKEN_CHARS + 2).strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not token or len(token) > MAX_TOKEN_CHARS or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
        return None
    return token


def _never_connected(exc):
    """True when the request provably never reached the dashboard (refused, no such address)."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    return isinstance(reason, (ConnectionRefusedError, socket.gaierror))


def call(api, token, method, path, body=None, timeout=HTTP_TIMEOUT_S):
    """(status, answer dict or None); status None = no answer (see answer["lost"]). Never raises."""
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {"Authorization": "Bearer " + token, "X-Agent-Id": AGENT_ID, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(api + path, data=data, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        # Refused: it never got there. Anything else (a timeout, a reset, no answer): it may have.
        lost = not _never_connected(exc)
        return None, {"error": "dashboard %s: %s" % ("answer lost" if lost else "unreachable", type(exc).__name__), "lost": lost}
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 -- an unreadable answer is not an answer
        return status, None
    return status, obj if isinstance(obj, dict) else None


def finish(out, rc, **fields):
    out.write(json.dumps(dict(rc=rc, **{k: v for k, v in fields.items() if v is not None}), ensure_ascii=False) + "\n")
    out.flush()
    return rc


def note(text):
    sys.stderr.write("credit-run: %s\n" % text)


def cancel(api, token, run_id, timeout=HTTP_TIMEOUT_S):
    """Ask the dashboard to stop the run; True when it took the request (202)."""
    _SIGNALS.raising = False
    status, _ = call(api, token, "POST", "/api/credit-gate/runs/%s/cancel" % run_id, timeout=timeout)
    note("cancel of %s: %s" % (run_id, status if status is not None else "no answer"))
    return status == 202


def interrupted(out, api, token, run_id, timeout):
    # 6 only for a cancel the dashboard took (202). Otherwise the run may still go on, and a caller that
    # read 6 as "stopped" would hand its worktree to a second writer: that is 7, like the other paths.
    taken = cancel(api, token, run_id, timeout)
    return finish(out, RC_INTERRUPTED if taken else RC_UNKNOWN, run_id=run_id, reason="interrupted", cancelled=taken,
                  signal=signal.Signals(_SIGNALS.signum).name if _SIGNALS.signum else None,
                  error=None if taken else "interrupted, but the dashboard did not take the cancel; the run may go on")


def wait(api, token, run_id, args, sleep, monotonic, out):
    deadline = monotonic() + args.max_wait_min * 60
    failures = 0
    last = None
    try:
        while True:
            _SIGNALS.raising = True
            if _SIGNALS.signum is not None:
                raise _Interrupted()
            sleep(args.poll_s)
            status, run = call(api, token, "GET", "/api/credit-gate/runs/" + run_id, timeout=args.http_timeout_s)
            _SIGNALS.raising = False
            if status == 200 and run is not None:
                failures = 0
                st = run.get("status")
                if st != last:
                    note("%s %s" % (run_id, st))
                    last = st
                if run.get("done") is True or (isinstance(st, str) and st not in OPEN_STATUSES):
                    view = {k: run.get(k) for k in RUN_FIELDS}
                    view["run_id"] = run_id
                    return finish(out, RC_DONE if st == "succeeded" else RC_RUN_FAILED, **view)
            elif status in (404, 409):
                # 409: the dashboard will not serve it now (e.g. off after a restart): stop it if it still runs.
                # A cancel it did not take leaves the run's fate unknown here (7), not failed (2).
                cancelled = cancel(api, token, run_id, args.http_timeout_s) if status == 409 else None
                stopped = status == 404 or cancelled
                return finish(out, RC_RUN_FAILED if stopped else RC_UNKNOWN, run_id=run_id, status_code=status,
                              reason=(run or {}).get("reason"), cancelled=cancelled,
                              error="the dashboard no longer follows this run" + ("" if stopped else ", and it did not take the cancel"))
            else:
                failures += 1
                if failures >= MAX_POLL_FAILURES:
                    return finish(out, RC_UNKNOWN, run_id=run_id, status_code=status,
                                  error="the run started, but it cannot be polled; its fate is unknown here")
            if monotonic() >= deadline:
                cancelled = cancel(api, token, run_id, args.http_timeout_s)
                return finish(out, RC_RUN_FAILED if cancelled else RC_UNKNOWN, run_id=run_id, reason="client_timeout", cancelled=cancelled,
                              error=None if cancelled else "the wait is over, but the dashboard did not take the cancel")
    except (_Interrupted, KeyboardInterrupt):
        return interrupted(out, api, token, run_id, args.http_timeout_s)
    finally:
        _SIGNALS.raising = False


def post_run(api, token, body, timeout, block_signals):
    """The POST, with the stop signals held back until its answer is in (BE-4b P7)."""
    if not block_signals:
        return call(api, token, "POST", "/api/credit-gate/runs", body, timeout=timeout)
    old = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        return call(api, token, "POST", "/api/credit-gate/runs", body, timeout=timeout)
    finally:
        # A signal that came meanwhile is delivered here; the handler only records it.
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def install_signal_handlers():
    for sig in STOP_SIGNALS:
        signal.signal(sig, _on_signal)


def main(argv=None, sleep=time.sleep, monotonic=time.monotonic, out=None, handle_signals=False):
    out = out if out is not None else sys.stdout
    if handle_signals:
        install_signal_handlers()
    try:
        args = parse_args(argv)
    except _Usage as exc:
        return finish(out, RC_BAD_REQUEST, error="usage: %s" % exc)
    api, body, why = build_request(args)
    if why is not None:
        return finish(out, RC_BAD_REQUEST, error=why)
    token = read_token(args.token_file)
    if token is None:
        return finish(out, RC_UNUSABLE, error="the dashboard token is not readable")
    if _SIGNALS.signum is not None:
        return finish(out, RC_INTERRUPTED, reason="interrupted", error="stopped before anything was sent")
    status, answer = post_run(api, token, body, args.http_timeout_s, handle_signals)
    if status is None:
        return finish(out, RC_UNKNOWN if answer.get("lost") else RC_UNUSABLE, error=answer["error"])
    if status == 202 and answer is None:
        return finish(out, RC_UNKNOWN, status_code=status, error="the run may have started, but its answer is unreadable")
    answer = answer or {}
    if status == 409:
        return finish(out, RC_GATE, reason=answer.get("reason"), detail=answer.get("detail"),
                      approval_spent=True if answer.get("approval_spent") is True else None)
    if status in (400, 404, 413):
        return finish(out, RC_BAD_REQUEST, status_code=status, reason=answer.get("reason"), error=answer.get("error") or "refused")
    run_id = answer.get("run_id")
    if status == 202 and not (isinstance(run_id, str) and _RUN_ID.match(run_id)):
        return finish(out, RC_UNKNOWN, status_code=status, error="the run may have started, but its answer carries no run id")
    if status != 202:
        return finish(out, RC_UNUSABLE, status_code=status, error="unexpected answer from the dashboard")
    note("%s started (node %s, %s/%s, budget %s USD, %s)" % (run_id, args.node, args.model, args.effort, args.budget, body["mode"]))
    if _SIGNALS.signum is not None:
        return interrupted(out, api, token, run_id, args.http_timeout_s)
    return wait(api, token, run_id, args, sleep, monotonic, out)


if __name__ == "__main__":
    sys.exit(main(handle_signals=True))
