"""Background scan execution for live Streamlit progress monitoring."""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import Any

from ..db import audit, execute, insert, new_id, now_iso
from .scan_runner import run_scan

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vulnblend-scan")
_LOCK = Lock()
_JOBS: dict[str, Future] = {}


def _record_event(scan_id: str, message: str, level: str = "error") -> None:
    insert(
        "execution_events",
        {
            "id": new_id("evt_"),
            "scan_id": scan_id,
            "stage": "worker",
            "level": level,
            "message": message,
            "metadata": {"source": "background-worker"},
            "created_at": now_iso(),
        },
    )


def _execute(scan_id: str, config: dict[str, Any], app: dict[str, Any]) -> dict[str, Any]:
    try:
        result = run_scan(scan_id, config, app)
        audit("scan_worker_finished", "scan", scan_id, {"status": result.get("status", "unknown")})
        return result
    except Exception as exc:  # persist failures so the UI never leaves a scan stuck
        message = f"Background worker failed: {type(exc).__name__}: {exc}"
        execute(
            "UPDATE scan_executions SET status=?, current_stage=?, ended_at=?, limitation=?, errors_count=errors_count+1 WHERE id=?",
            ["failed", "worker", now_iso(), message, scan_id],
        )
        _record_event(scan_id, message)
        audit("scan_worker_failed", "scan", scan_id, {"error": type(exc).__name__})
        return {"status": "failed", "error": message}
    finally:
        with _LOCK:
            _JOBS.pop(scan_id, None)


def start_scan(scan_id: str, config: dict[str, Any], app: dict[str, Any]) -> bool:
    """Queue a scan and return False when that scan is already running."""
    with _LOCK:
        existing = _JOBS.get(scan_id)
        if existing and not existing.done():
            return False
        _JOBS[scan_id] = _EXECUTOR.submit(_execute, scan_id, config, app)
    return True


def is_running(scan_id: str | None) -> bool:
    if not scan_id:
        return False
    with _LOCK:
        job = _JOBS.get(scan_id)
        return bool(job and not job.done())


def shutdown() -> None:
    _EXECUTOR.shutdown(wait=False, cancel_futures=True)
