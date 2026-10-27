"""Fake shared batch client for the memory-gate adapter tests (card 3e9f6c28, G2b).

NO network: every outcome is scripted. The scenario is the first line of the
prompt, `SCN:<name>`. Each call is appended to calls.log next to this file, so a
test can prove that a call did (or did not) reach ask().
The real client's signature is mirrored exactly (batch_client.py:44).
"""
import http.client
import io
import json
import os
import socket
import ssl
import time
import urllib.error
from pathlib import Path

from usage_log import append_usage

HERE = os.path.dirname(os.path.abspath(__file__))
USAGE = os.path.join(HERE, "usage.jsonl")


def _http(code, body=b"{}"):
    return urllib.error.HTTPError("https://example.invalid/v1/messages", code, "x", {}, io.BytesIO(body))


def ask(prompt, *, model="claude-haiku-5-5", max_tokens=512, system=None, caller="ismeretlen", timeout=120, extra=None, thinking=False):
    scn = prompt.split("\n", 1)[0][4:] if prompt.startswith("SCN:") else "ok"
    with open(os.path.join(HERE, "calls.log"), "a") as f:
        f.write(json.dumps({"scn": scn, "caller": caller, "timeout": timeout, "model": model}) + "\n")
    if scn == "ok":
        append_usage(Path(USAGE), {"ts": int(time.time()), "caller": caller, "in": 10, "out": 5})
        return '{"op":"CREATE","target":null,"confidence":0.9,"reason":"fake"}'
    if scn == "env":
        return json.dumps(sorted(os.environ.keys()))
    if scn == "modules":
        import colorsys  # noqa: F401 - a colorsys.py in this dir must NOT win (stdlib first)
        return json.dumps({"json": json.__file__, "colorsys": colorsys.__file__})
    if scn == "stop":
        return None
    if scn == "sleep":
        time.sleep(60)
        return "late"
    if scn == "big":
        return "x" * 5000
    if scn == "print":
        print("PRINTED-BY-CLIENT")
        return "printed"
    if scn == "usage_blocking":
        append_usage(Path(USAGE), {"_raise": "blocking"})
    if scn == "usage_value_then_429":
        try:
            append_usage(Path(USAGE), {"_raise": "value"})
        except ValueError:
            raise _http(429)
    table = {
        "http400credit": lambda: _http(400, b'{"error":{"message":"Your credit balance is too low"}}'),
        "http400": lambda: _http(400, b'{"error":{"message":"bad"}}'),
        "http401": lambda: _http(401),
        "http403": lambda: _http(403),
        "http404": lambda: _http(404),
        "http429": lambda: _http(429),
        "http500": lambda: _http(500),
        "http529": lambda: _http(529),
        "refused": lambda: ConnectionRefusedError(61, "refused"),
        "refused_url": lambda: urllib.error.URLError(ConnectionRefusedError(61, "refused")),
        "gaierror": lambda: urllib.error.URLError(socket.gaierror(8, "nodename")),
        "timeout": lambda: socket.timeout("timed out"),
        "timeout_url": lambda: urllib.error.URLError(socket.timeout("timed out")),
        "reset": lambda: ConnectionResetError(54, "reset"),
        "remote_disc": lambda: http.client.RemoteDisconnected("closed"),
        "incomplete": lambda: http.client.IncompleteRead(b"par"),
        "ssl": lambda: ssl.SSLError(1, "tls"),
        "urlerror_other": lambda: urllib.error.URLError("weird"),
        "badjson": lambda: json.JSONDecodeError("x", "doc", 0),
        "boom": lambda: RuntimeError("boom"),
    }
    if scn in table:
        raise table[scn]()
    return "unknown-scenario"
