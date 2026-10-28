"""Lightweight timers that record how long each stage of a session takes."""

import json
import os
import threading
import time
from contextlib import contextmanager

from loguru import logger

_TIMING_FILE = os.getenv("HONEYENGAGE_TIMING_FILE", "timing_metrics.jsonl")
_write_lock = threading.Lock()


def enabled() -> bool:
  return bool(os.getenv("HONEYENGAGE_TIMING"))


@contextmanager
def measure(component: str, session_id: str = "", **context):
  if not enabled():
    yield
    return

  started = time.perf_counter()
  ok = True
  try:
    yield
  except Exception:
    ok = False
    raise
  finally:
    elapsed = time.perf_counter() - started
    record = {
      "session_id": session_id or os.getenv("SESSION_ID", ""),
      "component": component,
      "duration_s": round(elapsed, 4),
      "ok": ok,
      "coa_mode": os.getenv("HONEYENGAGE_COA_MODE", ""),
      "attacker_level": os.getenv("LLMATTACKER_LEVEL", ""),
      **context,
    }
    try:
      with _write_lock, open(_TIMING_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:  # pragma: no cover - instrumentation must never break a run
      logger.warning(f"Could not write timing record for {component}: {exc}")
