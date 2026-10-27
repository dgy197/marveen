"""Memory write gate: Python adapter between the dashboard and the shared batch client.

Card 3e9f6c28 (b1, node G2b); protocol: blueprint r5 4.3.

Started by src/memory-gate/transport.ts as
    /usr/bin/python3 -I gate_adapter.py --batch-dir <dir> --store-dir <store>
with a minimal environment. Reads ONE JSON request on stdin, writes ONE JSON
answer on stdout, nothing else:

    stdin : {"v":1,"caller":"memoria-iras-kapu","timeout_s":30,
             "calls":[{"k":"<id>","model":..,"max_tokens":..,"system":..,"prompt":..}]}
    stdout: {"v":1,"results":[{"k":..,"ok":true,"text":".."} | {"k":..,"ok":false,"error":"<class>"}]}

What it guarantees (the dashboard process never sees the API key or the tokens):
  - the batch directory is trusted before anything is imported from it (realpath
    is a directory owned by us, not group/world writable; batch_client.py and
    usage_log.py are regular files, not symlinks), it is APPENDED to sys.path
    (stdlib wins, GN2) and the resolved modules must live inside it;
  - the ask() contract is checked (keyword parameters, a module-level
    append_usage that IS usage_log.append_usage); any deviation = no call;
  - every prompt is checked for the exact dashboard / oauth token values (GB2);
    the values stay in memory, never reach stdout, stderr or an exception text;
  - append_usage is wrapped (GB3): once a call reached the usage log, an ask()
    failure is `usage_log_failed` whatever its own class, and no further call runs;
  - anything not provably pre-send or server-rejected is `maybe_billed` (GN4).

Python 3.9, stdlib only. No print(), no traceback: every exception becomes a class name.
"""
import builtins
import http.client
import importlib.util
import inspect
import json
import os
import socket
import ssl
import stat
import sys
import urllib.error

CALLER = "memoria-iras-kapu"
MAX_CALLS = 5
MAX_STDIN_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 4096
MAX_TIMEOUT_S = 30
REQUIRED_ASK_KWARGS = ("model", "max_tokens", "system", "caller", "timeout")

# Classes the parent (transport.ts) accepts; anything else it reads as `error`.
TRANSIENT_HTTP = {429, 529}

_REAL_STDOUT = sys.stdout


def _silence():
    """No print, no traceback, no stray stderr text from us or the client."""
    builtins.print = lambda *a, **k: None  # noqa: E731 - deliberate kill switch
    sys.excepthook = lambda *a: None
    devnull = open(os.devnull, "w")
    sys.stdout = devnull
    sys.stderr = devnull


def _emit(results):
    _REAL_STDOUT.write(json.dumps({"v": 1, "results": results}, ensure_ascii=True))
    _REAL_STDOUT.flush()


def _parse_args(argv):
    out = {}
    i = 0
    while i < len(argv):
        if argv[i] in ("--batch-dir", "--store-dir") and i + 1 < len(argv):
            out[argv[i]] = argv[i + 1]
            i += 2
        else:
            return None
    if "--batch-dir" not in out or "--store-dir" not in out:
        return None
    return out


def _read_request():
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        return None
    req = json.loads(raw.decode("utf-8"))
    if not isinstance(req, dict) or req.get("v") != 1 or req.get("caller") != CALLER:
        return None
    calls = req.get("calls")
    if not isinstance(calls, list) or len(calls) == 0 or len(calls) > MAX_CALLS:
        return None
    t = req.get("timeout_s")
    if not isinstance(t, int) or isinstance(t, bool) or t < 1 or t > MAX_TIMEOUT_S:
        return None
    for c in calls:
        if not isinstance(c, dict):
            return None
        k = c.get("k")
        if not isinstance(k, str) or not k.isdigit() or len(k) > 18:
            return None
        mt = c.get("max_tokens")
        if not isinstance(mt, int) or isinstance(mt, bool) or mt < 1 or mt > 4096:
            return None
        for f in ("model", "system", "prompt"):
            if not isinstance(c.get(f), str):
                return None
    return {"timeout_s": t, "calls": calls}


class _Fatal(Exception):
    def __init__(self, cls):
        super().__init__(cls)
        self.cls = cls


def _private_dir_ok(path):
    st = os.stat(path)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _private_file_ok(path):
    st = os.lstat(path)
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _inside(path, real_dir):
    real = os.path.realpath(path)
    return os.path.dirname(real) == real_dir


def load_client(batch_dir):
    """Return (batch_client, usage_log) or raise _Fatal with the class name."""
    try:
        real_dir = os.path.realpath(batch_dir)
        if not os.path.isabs(batch_dir) or not _private_dir_ok(real_dir):
            raise _Fatal("untrusted_batch_dir")
        for name in ("batch_client.py", "usage_log.py"):
            if not _private_file_ok(os.path.join(real_dir, name)):
                raise _Fatal("untrusted_batch_dir")
    except _Fatal:
        raise
    except BaseException:
        raise _Fatal("untrusted_batch_dir")
    # APPEND, never insert: a json.py in the batch dir must not shadow the stdlib.
    if real_dir not in sys.path:
        sys.path.append(real_dir)
    for mod in ("usage_log", "batch_client"):
        # Resolve BEFORE executing anything: a same-named module earlier on
        # sys.path (site-packages) must not run at all.
        if mod in sys.modules and not _inside(getattr(sys.modules[mod], "__file__", "") or "", real_dir):
            raise _Fatal("contract_mismatch")
        spec = importlib.util.find_spec(mod)
        if spec is None or not spec.origin or not _inside(spec.origin, real_dir):
            raise _Fatal("contract_mismatch")
    try:
        import usage_log  # noqa: E402
        import batch_client  # noqa: E402
    except BaseException:
        raise _Fatal("contract_mismatch")
    for mod in (usage_log, batch_client):
        if not _inside(getattr(mod, "__file__", "") or "", real_dir):
            raise _Fatal("contract_mismatch")
    ask = getattr(batch_client, "ask", None)
    if not callable(ask):
        raise _Fatal("contract_mismatch")
    try:
        params = inspect.signature(ask).parameters
    except (TypeError, ValueError):
        raise _Fatal("contract_mismatch")
    kw_kinds = (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    for name in REQUIRED_ASK_KWARGS:
        if name not in params or params[name].kind not in kw_kinds:
            raise _Fatal("contract_mismatch")
    au = getattr(batch_client, "append_usage", None)
    ul = getattr(usage_log, "append_usage", None)
    if au is None or au is not ul or not inspect.isfunction(au) or au.__module__ != "usage_log":
        raise _Fatal("contract_mismatch")
    return batch_client, usage_log


def read_tokens(store_dir):
    """Exact token values for the residue check. None = check unavailable."""
    tokens = []
    try:
        with open(os.path.join(store_dir, ".dashboard-token"), "r", encoding="utf-8") as f:
            v = f.read().strip()
        if not v:
            return None
        tokens.append(v)
    except BaseException:
        return None
    try:
        with open(os.path.join(store_dir, ".claude-oauth-token"), "r", encoding="utf-8") as f:
            v = f.read().strip()
        if v:
            tokens.append(v)
    except FileNotFoundError:
        pass  # no oauth token on this install: that check is skipped
    except BaseException:
        return None
    return tokens


def classify(exc):
    """Map an ask() exception (raised before append_usage was entered) to a class (GN4)."""
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        if code in TRANSIENT_HTTP or 500 <= code <= 599:
            return "transient"
        if code in (401, 403):
            return "auth"
        if code in (400, 402):
            body = b""
            try:
                body = exc.read(8192) or b""
            except BaseException:
                pass
            if b"credit" in body.lower():
                return "credit"
            return "bad_request"
        if 400 <= code <= 499:
            return "bad_request"
        return "error"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (ConnectionRefusedError, socket.gaierror)):
            return "transient"
        return "maybe_billed"
    if isinstance(exc, (ConnectionRefusedError, socket.gaierror)):
        return "transient"
    if isinstance(exc, (socket.timeout, OSError, ssl.SSLError, http.client.HTTPException)):
        return "maybe_billed"
    return "error"


def run(batch_dir, store_dir, req):
    calls = req["calls"]
    try:
        bc, _ul = load_client(batch_dir)
    except _Fatal as f:
        return [{"k": c["k"], "ok": False, "error": f.cls} for c in calls]
    tokens = read_tokens(store_dir)
    if tokens is None:
        return [{"k": c["k"], "ok": False, "error": "residue_check_unavailable"} for c in calls]

    original = bc.append_usage
    flag = {"entered": False, "failed": None}

    def append_usage_wrapper(*a, **kw):
        flag["entered"] = True
        try:
            return original(*a, **kw)
        except BaseException as e:
            flag["failed"] = type(e).__name__
            raise

    bc.append_usage = append_usage_wrapper
    results = []
    halted = False
    for c in calls:
        k = c["k"]
        if halted:
            results.append({"k": k, "ok": False, "error": "stopped"})
            continue
        if any(t in c["system"] or t in c["prompt"] for t in tokens):
            results.append({"k": k, "ok": False, "error": "secret_residue"})
            continue
        flag["entered"] = False
        flag["failed"] = None
        try:
            text = bc.ask(c["prompt"], model=c["model"], max_tokens=c["max_tokens"], system=c["system"],
                          caller=CALLER, timeout=req["timeout_s"])
        except BaseException as e:  # noqa: BLE001 - everything becomes a class name
            if flag["entered"]:
                # The call happened (usage was being logged): the log write failing
                # or not, this is a billed call whose accounting is in doubt.
                results.append({"k": k, "ok": False, "error": "usage_log_failed"})
                halted = True
            else:
                results.append({"k": k, "ok": False, "error": classify(e)})
            continue
        if text is None:
            results.append({"k": k, "ok": False, "error": "stopped"})
            halted = True
            continue
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_BYTES or any(t in text for t in tokens):
            results.append({"k": k, "ok": False, "error": "error"})
            continue
        results.append({"k": k, "ok": True, "text": text})
    return results


def main():
    _silence()
    try:
        args = _parse_args(sys.argv[1:])
        if args is None:
            _emit([])
            return 2
        try:
            req = _read_request()
        except BaseException:
            req = None
        if req is None:
            _emit([])
            return 2
        _emit(run(args["--batch-dir"], args["--store-dir"], req))
        return 0
    except BaseException:
        try:
            _emit([])
        except BaseException:
            pass
        return 3


if __name__ == "__main__":
    sys.exit(main())
