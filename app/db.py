"""SQLite persistence layer: analyses (projects) and their runs (one per pcap submission)."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "app.db"))
PCAP_DIR = DATA_DIR / "pcaps"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    default_metadata TEXT,                 -- used when a run is submitted without metadata (JSON)
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    status        TEXT NOT NULL,           -- queued | running | awaiting_approval | done | failed
    stage         TEXT NOT NULL,           -- queued | zeek | tshark | llm | llm_writing | done | failed
    progress      INTEGER NOT NULL DEFAULT 0,
    provider      TEXT NOT NULL,
    dry_run       INTEGER NOT NULL DEFAULT 0,
    metadata      TEXT NOT NULL,           -- metadata used for this run (JSON)
    pcap_filename TEXT NOT NULL,
    pcap_size     INTEGER NOT NULL,
    pcap_sha256   TEXT NOT NULL,
    pcap_path     TEXT NOT NULL,
    report        TEXT,                    -- zeek/tshark summary
    result        TEXT,                    -- LLM analysis (markdown)
    error         TEXT,
    created_at    TEXT NOT NULL,           -- when the user submitted it
    started_at    TEXT,
    finished_at   TEXT
);
-- (columns added later come from MIGRATIONS)

-- commands proposed by the LLM (require user approval)
CREATE TABLE IF NOT EXISTS tool_calls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool_use_id  TEXT NOT NULL,            -- id of the Claude tool_use block
    tool         TEXT NOT NULL,
    args         TEXT NOT NULL,            -- arguments proposed by the model (JSON)
    purpose      TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL,            -- pending | approved | rejected | invalid | limit | executed
    final_args   TEXT,                     -- arguments actually run, if the user edited them (JSON)
    user_note    TEXT,
    output       TEXT,
    exit_code    INTEGER,
    duration     REAL,
    created_at   TEXT NOT NULL,
    decided_at   TEXT,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_run ON tool_calls(run_id, id);
CREATE INDEX IF NOT EXISTS idx_runs_analysis ON runs(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
"""

# Columns to add to existing DBs: (column, DDL)
MIGRATIONS = [
    ("compare_previous", "compare_previous INTEGER NOT NULL DEFAULT 1"),
    ("context_run_ids", "context_run_ids TEXT"),  # ids of earlier runs given to the LLM as context (JSON)
    ("stats", "stats TEXT"),                      # structured statistics for charts (JSON)
    ("conversation", "conversation TEXT"),        # Claude message history (to resume after approval, JSON)
]

RUN_LIST_COLUMNS = ("id, analysis_id, status, stage, progress, provider, dry_run, metadata, "
                    "pcap_filename, pcap_size, pcap_sha256, compare_previous, context_run_ids, error, created_at, started_at, finished_at, "
                    "result IS NOT NULL AS has_result, "
                    "(SELECT COUNT(*) FROM tool_calls t WHERE t.run_id = runs.id AND t.status = 'pending') AS pending_approvals, "
                    "(SELECT COUNT(*) FROM tool_calls t WHERE t.run_id = runs.id) AS tool_call_count, json_extract(stats, '$.totals') AS totals, "
                    "json_extract(stats, '$.timeline.start') AS capture_start, "
                    "json_extract(stats, '$.timeline.end') AS capture_end")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def pcap_file(stored_path: str) -> Path:
    """Resolve a stored pcap path.

    Older rows store an absolute path from wherever the app ran then (e.g. a host path); if that
    path doesn't exist here (e.g. inside a container with a different DATA_DIR), look the file up by
    name in the current PCAP_DIR.
    """
    p = Path(stored_path)
    return p if p.exists() else PCAP_DIR / p.name


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _q(sql: str, params: tuple = ()) -> list[dict]:
    conn = connect()
    try:
        with conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _exec(sql: str, params: tuple = ()) -> int:
    conn = connect()
    try:
        with conn:
            return conn.execute(sql, params).lastrowid
    finally:
        conn.close()


def init() -> None:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode = WAL")  # lets the API read while worker threads write
        conn.executescript(SCHEMA)
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(runs)")}
        for col, ddl in MIGRATIONS:
            if col not in existing:
                conn.execute(f"ALTER TABLE runs ADD COLUMN {ddl}")
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- analyses
def create_analysis(name: str, description: str, default_metadata: dict | None) -> int:
    return _exec(
        "INSERT INTO analyses (name, description, default_metadata, created_at) VALUES (?, ?, ?, ?)",
        (name, description, json.dumps(default_metadata) if default_metadata else None, now()),
    )


def list_analyses() -> list[dict]:
    return _q("""
        SELECT a.id, a.name, a.description, a.created_at,
               COUNT(r.id) AS run_count,
               MAX(r.created_at) AS last_run_at,
               SUM(r.status IN ('queued', 'running', 'awaiting_approval')) AS active_runs,
               SUM(r.status = 'awaiting_approval') AS awaiting_runs
        FROM analyses a LEFT JOIN runs r ON r.analysis_id = a.id
        GROUP BY a.id ORDER BY a.created_at DESC""")


def get_analysis(analysis_id: int) -> dict | None:
    rows = _q("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    return rows[0] if rows else None


def update_analysis(analysis_id: int, **fields) -> None:
    if "default_metadata" in fields:
        fields["default_metadata"] = json.dumps(fields["default_metadata"]) if fields["default_metadata"] else None
    if fields:
        cols = ", ".join(f"{k} = ?" for k in fields)
        _exec(f"UPDATE analyses SET {cols} WHERE id = ?", (*fields.values(), analysis_id))


def delete_analysis(analysis_id: int) -> list[str]:
    """Return the pcap paths of the deleted runs (the caller removes the files)."""
    paths = [r["pcap_path"] for r in _q("SELECT pcap_path FROM runs WHERE analysis_id = ?", (analysis_id,))]
    _exec("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    return paths


# ---------------------------------------------------------------- runs
def create_run(analysis_id: int, *, provider: str, dry_run: bool, compare_previous: bool,
               metadata: str, pcap_filename: str, pcap_size: int, pcap_sha256: str,
               pcap_path: str) -> int:
    return _exec("""
        INSERT INTO runs (analysis_id, status, stage, progress, provider, dry_run, compare_previous,
                          metadata, pcap_filename, pcap_size, pcap_sha256, pcap_path, created_at)
        VALUES (?, 'queued', 'queued', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (analysis_id, provider, int(dry_run), int(compare_previous), metadata, pcap_filename,
         pcap_size, pcap_sha256, pcap_path, now()))


def previous_runs(analysis_id: int, before_run_id: int, limit: int) -> list[dict]:
    """The last `limit` runs completed before this one in the same analysis (oldest first)."""
    rows = _q("""SELECT id, created_at, metadata, report, result FROM runs
                 WHERE analysis_id = ? AND id < ? AND status = 'done'
                 ORDER BY id DESC LIMIT ?""", (analysis_id, before_run_id, limit))
    return rows[::-1]


def get_run(run_id: int) -> dict | None:
    rows = _q("SELECT * FROM runs WHERE id = ?", (run_id,))
    return rows[0] if rows else None


def list_runs(analysis_id: int) -> list[dict]:
    return _q(f"SELECT {RUN_LIST_COLUMNS} FROM runs WHERE analysis_id = ? ORDER BY created_at, id",
              (analysis_id,))


def update_run(run_id: int, **fields) -> None:
    cols = ", ".join(f"{k} = ?" for k in fields)
    _exec(f"UPDATE runs SET {cols} WHERE id = ?", (*fields.values(), run_id))


def reset_run(run_id: int) -> None:
    delete_tool_calls(run_id)
    update_run(run_id, status="queued", stage="queued", progress=0, error=None,
               report=None, result=None, context_run_ids=None, stats=None, conversation=None, started_at=None, finished_at=None)


def queue_position(run_id: int) -> int:
    """Position in the queue (1 = next)."""
    return _q("SELECT COUNT(*) AS n FROM runs WHERE status = 'queued' AND id <= ?", (run_id,))[0]["n"]


def claim_run(run_id: int) -> bool:
    """Atomic queued → running transition; two workers can't take the same run."""
    conn = connect()
    try:
        with conn:
            cur = conn.execute("UPDATE runs SET status = 'running' WHERE id = ? AND status = 'queued'", (run_id,))
            return cur.rowcount == 1
    finally:
        conn.close()


# ---------------------------------------------------------------- tool calls
def create_tool_call(run_id: int, *, tool_use_id: str, tool: str, args: list, purpose: str,
                     status: str, output: str | None = None) -> int:
    return _exec("""INSERT INTO tool_calls (run_id, tool_use_id, tool, args, purpose, status, output, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                 (run_id, tool_use_id, tool, json.dumps(args), purpose, status, output, now()))


def get_tool_call(call_id: int) -> dict | None:
    rows = _q("SELECT * FROM tool_calls WHERE id = ?", (call_id,))
    return rows[0] if rows else None


def list_tool_calls(run_id: int) -> list[dict]:
    return _q("SELECT * FROM tool_calls WHERE run_id = ? ORDER BY id", (run_id,))


def update_tool_call(call_id: int, **fields) -> None:
    cols = ", ".join(f"{k} = ?" for k in fields)
    _exec(f"UPDATE tool_calls SET {cols} WHERE id = ?", (*fields.values(), call_id))


def decide_tool_call(call_id: int, status: str, final_args: list | None, note: str | None) -> bool:
    """pending → approved/rejected; False if a decision was already made."""
    conn = connect()
    try:
        with conn:
            cur = conn.execute("""UPDATE tool_calls SET status = ?, final_args = ?, user_note = ?, decided_at = ?
                                  WHERE id = ? AND status = 'pending'""",
                               (status, json.dumps(final_args) if final_args is not None else None,
                                note, now(), call_id))
            return cur.rowcount == 1
    finally:
        conn.close()


def resume_if_decided(run_id: int) -> bool:
    """Re-queue the run if no approvals are pending (atomic). True if it was queued."""
    conn = connect()
    try:
        with conn:
            cur = conn.execute("""UPDATE runs SET status = 'queued', stage = 'tool'
                                  WHERE id = ? AND status = 'awaiting_approval'
                                  AND NOT EXISTS (SELECT 1 FROM tool_calls WHERE run_id = ? AND status = 'pending')""",
                               (run_id, run_id))
            return cur.rowcount == 1
    finally:
        conn.close()


def delete_tool_calls(run_id: int) -> None:
    _exec("DELETE FROM tool_calls WHERE run_id = ?", (run_id,))


def runs_missing_stats() -> list[int]:
    """Runs that were parsed but have no stats (processed before the stats feature existed)."""
    return [r["id"] for r in _q("""SELECT id FROM runs WHERE stats IS NULL AND report IS NOT NULL
                                   AND status IN ('done', 'failed') ORDER BY id""")]


def recover_pending() -> list[int]:
    """On server restart: re-queue runs that were interrupted.

    Runs with a stored conversation resume where they left off; runs awaiting approval are left alone.
    """
    _exec("UPDATE runs SET status = 'queued' WHERE status = 'running'")
    return [r["id"] for r in _q("SELECT id FROM runs WHERE status = 'queued' ORDER BY id")]
