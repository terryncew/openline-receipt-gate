"""Opt-in, value-free wall-clock profiling for the latency investigation.

Set GATEWAY_PROFILE to a JSONL output path before starting a process.
Unset it for normal operation and for final latency comparisons. Nested
stages are inclusive: a transaction contains its durable commit; do not
sum overlapping stages. Handler time does not include transport queueing.
No request body, action, credential, signing key, or SQL parameter is logged.
"""

from __future__ import annotations

import contextvars
import functools
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager

_OUTPUT = os.environ.get("GATEWAY_PROFILE", "")
_ACTIVE = contextvars.ContextVar("gateway_profile", default=None)
_LOCK = threading.Lock()
_SEQUENCE = 0
_WARNED = False


def set_trace(value: str | None):
    """Associate spans across services using only a validated UUID."""
    event = _ACTIVE.get()
    if event is None or not value:
        return
    try:
        event["trace_id"] = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        pass


def _emit(event):
    global _SEQUENCE, _WARNED
    try:
        with _LOCK:
            _SEQUENCE += 1
            event["sequence"] = _SEQUENCE
            event["pid"] = os.getpid()
            line = json.dumps(event, sort_keys=True, separators=(",", ":"))
            # Append one complete JSONL record; the output is diagnostic,
            # not part of the security receipt or database transaction.
            with open(_OUTPUT, "a", encoding="utf-8") as out:
                out.write(line + "\n")
    except OSError:
        # Diagnostic output failure must not change authorization behavior.
        if not _WARNED:
            _WARNED = True
            print("[profiling] output unavailable", flush=True)


@contextmanager
def span(name: str):
    if not _OUTPUT:
        yield
        return
    event = _ACTIVE.get()
    root = event is None
    token = None
    if root:
        event = {"component": name, "started_ns": time.time_ns(),
                 "stages_ms": {}, "calls": {}}
        token = _ACTIVE.set(event)
    started = time.perf_counter_ns()
    try:
        yield
    finally:
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        stages = event["stages_ms"]
        stages[name] = stages.get(name, 0.0) + elapsed
        calls = event["calls"]
        calls[name] = calls.get(name, 0) + 1
        if root:
            _ACTIVE.reset(token)
            event["elapsed_ms"] = elapsed
            _emit(event)


def profiled(name: str):
    """Time a function, creating a request record at the outermost call."""
    def decorate(fn):
        if not _OUTPUT:
            return fn
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            with span(name):
                return fn(*args, **kwargs)
        return wrapped
    return decorate
