"""Fake usage log for the memory-gate adapter tests (card 3e9f6c28, G2b). Scripted failures via record["_raise"]."""
import json
from pathlib import Path


def append_usage(path: Path, record: dict) -> bool:
    r = record.get("_raise")
    if r == "blocking":
        raise BlockingIOError("usage_log_busy")
    if r == "value":
        raise ValueError("usage_log_shape")
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")
    return True
