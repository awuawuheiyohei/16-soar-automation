"""DB helper —— 统一用 context manager 避免 SQLite WAL lock"""
import os
import sqlite3
import json
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# 支持用环境变量指向独立 DB（测试隔离 / 多环境）
DB_PATH = Path(os.environ.get("SOAR_DB", DATA_DIR / "soar.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


@contextmanager
def db_connection():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
    finally:
        conn.close()


def init_db(verbose=False):
    with db_connection() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.commit()
    if verbose:
        print(f"[+] DB at {DB_PATH}")


def row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()} if row else {}


def rows_to_dicts(rows) -> list:
    return [row_to_dict(r) for r in rows]


def write_audit(conn, actor: str, action: str, entity_type: str = None,
                entity_id: str = None, details: dict = None):
    conn.execute(
        "INSERT INTO audit_log (actor, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)",
        (actor, action, entity_type, entity_id, json.dumps(details or {}, ensure_ascii=False))
    )
    conn.commit()


def next_id(conn, table: str, column: str, prefix: str, width: int = 4) -> str:
    """
    生成形如 ALR-0007 的顺序 ID。
    取当前最大值 +1，而不是 COUNT(*)：表里可能有删除过的记录，
    用 COUNT 会重新发出已存在的 ID，撞 PRIMARY KEY。

    注意用 INSTR(col,'-') 定位分隔符，而不是硬算 SUBSTR 起点：
    硬算起点极易差一位，把 "-0007" 整段拿去 CAST，结果恒为 -1，
    于是每次都发出 ALR-0001 并撞 PRIMARY KEY。
    """
    row = conn.execute(
        f"SELECT MAX(CAST(SUBSTR({column}, INSTR({column}, '-') + 1) AS INTEGER)) AS m FROM {table}"
    ).fetchone()
    nxt = (row["m"] or 0) + 1
    return f"{prefix}-{nxt:0{width}d}"


def wipe_database(conn):
    """删除所有业务表的数据（保留表结构）—— seed 前调用"""
    tables = [
        "audit_log", "false_positive_feedback", "approval_requests", "action_runs",
        "playbook_runs", "playbook_actions", "playbooks", "alert_correlations",
        "alerts", "detection_rules",
    ]
    for t in tables:
        conn.execute(f"DELETE FROM {t}")
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN "
                 "('action_runs','alert_correlations','audit_log')")
    conn.commit()