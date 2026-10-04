"""SQLite persistence layer."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import DB_PATH, ROOT


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def get_connection(path: Path | str | None = None) -> sqlite3.Connection:
    db_path = Path(path or DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    schema = (ROOT / "vulblend" / "schema.sql").read_text(encoding="utf-8")
    with get_connection() as conn:
        conn.executescript(schema)
        conn.commit()


@contextmanager
def transaction():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return list(conn.execute(sql, tuple(params)).fetchall())


def one(sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(sql, tuple(params)).fetchone()


def execute(sql: str, params: Iterable[Any] = ()) -> int:
    with transaction() as conn:
        cur = conn.execute(sql, tuple(params))
        return cur.rowcount


def insert(table: str, payload: dict[str, Any]) -> str:
    row_id = payload.setdefault("id", new_id())
    columns = ", ".join(payload.keys())
    placeholders = ", ".join(["?"] * len(payload))
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in payload.values()]
    with transaction() as conn:
        conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", values)
    return row_id


def audit(action: str, entity_type: str, entity_id: str | None = None, details: dict[str, Any] | None = None, actor: str = "local-user") -> None:
    insert("audit_events", {
        "id": new_id("aud_"), "actor": actor, "action": action,
        "entity_type": entity_type, "entity_id": entity_id,
        "details": details or {}, "created_at": now_iso(),
    })


def json_load(value: Any, default: Any = None) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
