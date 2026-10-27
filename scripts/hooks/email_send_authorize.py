#!/usr/bin/env python3
"""CLI-side send authorizer (card efa58ad2, cli-send-enforce).

The Graph CLI (scripts/graph-mail.ts send|forward) spawns this file right before
it POSTs to Graph, and sends only on exit 0 AND decision == "allow". The decision
is the SAME code the PreToolUse hook runs -- email-approval-gate.py's authorize():
level, standing list, content anchor, one-shot consumption -- so there is one
implementation of the anchor and of the approval rules, not a TypeScript copy.

Contract (one JSON object on stdin, one JSON line on stdout):
  stdin : {"mode": "consume"|"peek", "tool": "graph-mail", "kind": "send"|"forward",
           "to": [str], "cc": [str], "bcc": [str], "text": str,
           "html_sha256": str?, "attachments": [{"name","sha256","size"}]?,
           "forward": {"message_id","subject"}?   (kind "forward" only, required there)
           "comment_source"?, "comment_sha256"?, "comment_file"?  (forward trace only)
           "ref": str?   (idempotency key -> approvals.consumed_ref)}
          The values are the ones the CLI is about to send, in the shape the hook's
          extractor yields for the same command (to/cc/bcc entries raw; text =
          subject and body joined as email_extract builds it), so both sides
          compute one anchor.
  stdout: {"decision": "allow"|"refuse", "reason": str, "approval_id": str|null,
           "anchor": str|null, "standing": str|null, "detail": str|null,
           "note": str|null, "owner_gap": str|null, "level": int|null,
           "mode": str}
  exit  : 0 = allow, 2 = refuse (any refusal, bad input and internal errors
          included). Anything else (1, signal, no JSON) is a refusal for the caller.
  reasons: allow -> approval | standing | level3;
           refuse -> level1 qa_failed config_invalid unreadable no_text no_recipient
           standing_not_live trace_unwritable db_unavailable none pending consumed
           expired race bad_request internal_error.

Paths. The DB, the autonomy config, the standing list and the standing log come
from THIS file's real location (realpath -> repo root -> store/). No environment
variable can redirect them (a hand-made DB holding an own "approved" row would
defeat the gate), and the helper removes EMAIL_APPROVAL_GATE_STORE and
OUTGOING_COPY_GATE_RULES from its environment before the gate modules load.
Tests reach other paths ONLY by importing this module and calling
run(envelope, paths=...) in-process (or from a driver script that does): the
stdin/stdout entry point has no argument and no variable for it, so production
cannot reach that parameter.

Window: EMAIL_APPROVAL_WINDOW_S is honoured like the hook does (a non-integer is a
refusal, config_invalid), but never above the 1800 s default: this variable cannot
widen how old an approval may be.

Consumption is a single conditional UPDATE under BEGIN IMMEDIATE, strictly
single-use, no refund (Brainy msg 3132, Q1). QA (the copy gate's audit) runs
BEFORE consumption; a failing letter spends nothing. In mode "consume" a standing
send is traced (daily log + local log) exactly once, here; in "peek" nothing is
written at all.
"""
import importlib.util
import json
import os
import sys

_HERE = os.path.dirname(os.path.realpath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DEFAULT_WINDOW_S = 1800
_ENV_SCRUB = ("EMAIL_APPROVAL_GATE_STORE", "OUTGOING_COPY_GATE_RULES")
_GATE = None


def derived_paths():
    store = os.path.join(_ROOT, "store")
    return {"db": os.path.join(store, "claudeclaw.db"),
            "config": os.path.join(store, "autonomy-config.json"),
            "standing": os.path.join(store, "email-standing-recipients.json"),
            "log": os.path.join(store, "email-standing-sends.log"),
            "store": store}


def _load_gate():
    global _GATE
    if _GATE is None:
        spec = importlib.util.spec_from_file_location(
            "email_approval_gate", os.path.join(_HERE, "email-approval-gate.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _GATE = mod
    return _GATE


def _window():
    """(seconds, error); capped at the default so the env cannot widen it."""
    raw = os.environ.get("EMAIL_APPROVAL_WINDOW_S", str(_DEFAULT_WINDOW_S))
    try:
        secs = int(raw)
    except ValueError:
        return None, f"EMAIL_APPROVAL_WINDOW_S={raw!r} nem egesz szam"
    return min(secs, _DEFAULT_WINDOW_S), None


def _str_list(req, key):
    val = req.get(key, [])
    if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
        raise ValueError(f"{key} must be a list of strings")
    return val


def _opt_str(req, key):
    val = req.get(key)
    if val is not None and not isinstance(val, str):
        raise ValueError(f"{key} must be a string")
    return val


def build_env(req):
    """Validate the request and build the envelope dict content_anchor reads."""
    if not isinstance(req, dict):
        raise ValueError("request must be a JSON object")
    if req.get("mode") not in ("consume", "peek"):
        raise ValueError("mode must be consume or peek")
    if req.get("tool") != "graph-mail":
        raise ValueError("tool must be graph-mail")
    kind = req.get("kind")
    if kind not in ("send", "forward"):
        raise ValueError("kind must be send or forward")
    if not isinstance(req.get("text"), str):
        raise ValueError("text must be a string")
    env = {"to": _str_list(req, "to"), "cc": _str_list(req, "cc"), "bcc": _str_list(req, "bcc"),
           "text": req["text"], "unreadable_reason": None}
    html = _opt_str(req, "html_sha256")
    if html:
        env["html_sha256"] = html
    atts = req.get("attachments")
    if atts:
        if not isinstance(atts, list):
            raise ValueError("attachments must be a list")
        norm = []
        for a in atts:
            if not (isinstance(a, dict) and isinstance(a.get("name"), str)
                    and isinstance(a.get("sha256"), str) and isinstance(a.get("size"), int)
                    and not isinstance(a.get("size"), bool)):
                raise ValueError("attachment needs name, sha256, size")
            norm.append({"name": a["name"], "sha256": a["sha256"], "size": a["size"]})
        env["attachments"] = norm
    fwd = req.get("forward")
    if kind == "forward":
        if not (isinstance(fwd, dict) and isinstance(fwd.get("message_id"), str) and fwd["message_id"]
                and isinstance(fwd.get("subject"), str)):
            raise ValueError("forward needs message_id and subject")
        env["forward"] = {"message_id": fwd["message_id"], "subject": fwd["subject"]}
        for key in ("comment_source", "comment_sha256", "comment_file"):
            val = _opt_str(req, key)
            if val:
                env[key] = val
    elif fwd is not None:
        raise ValueError("forward is only valid for kind forward")
    ref = _opt_str(req, "ref")
    return env, req["mode"], (ref or None)


def _out(result, **extra):
    keys = ("decision", "reason", "approval_id", "anchor", "standing", "detail",
            "note", "owner_gap", "level", "mode")
    out = {k: result.get(k) for k in keys}
    if result.get("exc") and not out.get("detail"):
        out["detail"] = result["exc"]
    out.update(extra)
    return out


def run(req, paths=None):
    """The whole decision. Returns the stdout dict. `paths` is the test-only
    parameter (see the module docstring); None = derived from the repo root."""
    try:
        env, mode, ref = build_env(req)
    except ValueError as exc:
        return {"decision": "refuse", "reason": "bad_request", "detail": str(exc)}
    try:
        gate = _load_gate()
        window = _window()
        res = gate.authorize(env, mode, paths=paths or derived_paths(), consumer="graph-mail",
                             ref=ref, run_qa=True, unreadable_level=1, window=window,
                             bare_recipients=True)
        return _out(res)
    except Exception as exc:  # noqa: BLE001 -- "cannot decide" is a refusal
        return {"decision": "refuse", "reason": "internal_error", "detail": repr(exc)}


def main():
    for key in _ENV_SCRUB:
        os.environ.pop(key, None)
    try:
        req = json.loads(sys.stdin.read())
        verdict = run(req)
    except Exception as exc:  # noqa: BLE001
        verdict = {"decision": "refuse", "reason": "bad_request", "detail": repr(exc)}
    sys.stdout.write(json.dumps(verdict, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0 if verdict.get("decision") == "allow" else 2


if __name__ == "__main__":
    sys.exit(main())
