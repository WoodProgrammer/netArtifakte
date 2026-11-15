"""SQLite persistence layer.

analyses (projects, owned by a team) → runs (one per pcap submission) → tool_calls / followups.
users ↔ teams (many-to-many); sessions for browser logins.
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "app.db"))
PCAP_DIR = DATA_DIR / "pcaps"

ACTIVE_STATUSES = ("queued", "running", "awaiting_approval")
TERMINAL_STATUSES = ("done", "failed", "cancelled")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    is_admin       INTEGER NOT NULL DEFAULT 0,
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    last_login_at  TEXT
);

CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id  INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,       -- sha256 of the cookie value; the raw token is never stored
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);

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
    status        TEXT NOT NULL,           -- queued | running | awaiting_approval | done | failed | cancelled
    stage         TEXT NOT NULL,           -- queued | zeek | tshark | llm | llm_writing | awaiting_approval | tool | followup | done | failed | cancelled
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

-- follow-up questions asked after an analysis finished
CREATE TABLE IF NOT EXISTS followups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    question     TEXT NOT NULL,
    answer       TEXT,
    status       TEXT NOT NULL,            -- queued | running | done | failed | cancelled
    error        TEXT,
    usage        TEXT,                     -- token usage + estimated cost of this follow-up (JSON)
    created_at   TEXT NOT NULL,
    finished_at  TEXT
);
-- (columns added later come from MIGRATIONS)
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_tool_calls_run ON tool_calls(run_id, id);
CREATE INDEX IF NOT EXISTS idx_runs_analysis ON runs(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_followups_run ON followups(run_id, id);
CREATE INDEX IF NOT EXISTS idx_analyses_team ON analyses(team_id);
"""

# Columns to add to existing DBs: (table, column, DDL)
MIGRATIONS = [
    ("runs", "compare_previous", "compare_previous INTEGER NOT NULL DEFAULT 1"),
    ("runs", "context_run_ids", "context_run_ids TEXT"),     # ids of earlier runs given to the LLM as context (JSON)
    ("runs", "stats", "stats TEXT"),                         # structured statistics for charts (JSON)
    ("runs", "conversation", "conversation TEXT"),           # Claude message history (to resume after approval, JSON)
    ("runs", "submitted_by", "submitted_by INTEGER"),        # user id
    ("runs", "cancel_requested", "cancel_requested INTEGER NOT NULL DEFAULT 0"),
    ("runs", "usage", "usage TEXT"),                         # cumulative token usage + estimated cost (JSON)
    ("runs", "active_followup_id", "active_followup_id INTEGER"),  # set while a follow-up is being answered
    ("runs", "pcap_deleted", "pcap_deleted INTEGER NOT NULL DEFAULT 0"),  # removed by the retention policy
    ("analyses", "team_id", "team_id INTEGER"),
    ("analyses", "created_by", "created_by INTEGER"),
    ("analyses", "auto_approve", "auto_approve INTEGER NOT NULL DEFAULT 0"),  # run Claude's commands without asking
    ("tool_calls", "followup_id", "followup_id INTEGER"),    # null = proposed during the initial analysis
    ("tool_calls", "decided_by", "decided_by INTEGER"),      # user id; null + approved = auto-approved
]

DEFAULT_TEAM = "Default"

RUN_LIST_COLUMNS = ("id, analysis_id, status, stage, progress, provider, dry_run, metadata, "
                    "pcap_filename, pcap_size, pcap_sha256, compare_previous, context_run_ids, error, "
                    "created_at, started_at, finished_at, submitted_by, usage, pcap_deleted, "
                    "(SELECT username FROM users u WHERE u.id = runs.submitted_by) AS submitted_by_name, "
                    "result IS NOT NULL AS has_result, "
                    "(SELECT COUNT(*) FROM tool_calls t WHERE t.run_id = runs.id AND t.status = 'pending') AS pending_approvals, "
                    "(SELECT COUNT(*) FROM tool_calls t WHERE t.run_id = runs.id) AS tool_call_count, "
                    "(SELECT COUNT(*) FROM followups f WHERE f.run_id = runs.id) AS followup_count, "
                    "json_extract(stats, '$.totals') AS totals, "
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


def _one(sql: str, params: tuple = ()) -> dict | None:
    rows = _q(sql, params)
    return rows[0] if rows else None


def _exec(sql: str, params: tuple = ()) -> int:
    conn = connect()
    try:
        with conn:
            return conn.execute(sql, params).lastrowid
    finally:
        conn.close()


def _rowcount(sql: str, params: tuple = ()) -> int:
    conn = connect()
    try:
        with conn:
            return conn.execute(sql, params).rowcount
    finally:
        conn.close()


def init() -> None:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode = WAL")  # lets the API read while worker threads write
        conn.executescript(SCHEMA)
        for table, col, ddl in MIGRATIONS:
            existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        conn.executescript(INDEXES)
        # Analyses created before teams existed go to a "Default" team.
        if conn.execute("SELECT 1 FROM analyses WHERE team_id IS NULL LIMIT 1").fetchone():
            conn.execute("INSERT OR IGNORE INTO teams (name, created_at) VALUES (?, ?)", (DEFAULT_TEAM, now()))
            team_id = conn.execute("SELECT id FROM teams WHERE name = ?", (DEFAULT_TEAM,)).fetchone()["id"]
            conn.execute("UPDATE analyses SET team_id = ? WHERE team_id IS NULL", (team_id,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- users
def create_user(username: str, password_hash: str, is_admin: bool = False) -> int:
    return _exec("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                 (username, password_hash, int(is_admin), now()))


def get_user(user_id: int) -> dict | None:
    return _one("SELECT * FROM users WHERE id = ?", (user_id,))


def get_user_by_name(username: str) -> dict | None:
    return _one("SELECT * FROM users WHERE username = ?", (username,))


def list_users() -> list[dict]:
    return _q("""SELECT u.id, u.username, u.is_admin, u.active, u.created_at, u.last_login_at,
                        (SELECT json_group_array(team_id) FROM team_members m WHERE m.user_id = u.id) AS team_ids
                 FROM users u ORDER BY u.username""")


def update_user(user_id: int, **fields) -> None:
    if fields:
        cols = ", ".join(f"{k} = ?" for k in fields)
        _exec(f"UPDATE users SET {cols} WHERE id = ?", (*fields.values(), user_id))


def count_users() -> int:
    return _q("SELECT COUNT(*) AS n FROM users")[0]["n"]


def count_active_admins(exclude_user_id: int | None = None) -> int:
    return _q("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND active = 1 AND id IS NOT ?",
              (exclude_user_id,))[0]["n"]


def user_team_ids(user_id: int) -> list[int]:
    return [r["team_id"] for r in _q("SELECT team_id FROM team_members WHERE user_id = ?", (user_id,))]


def set_user_teams(user_id: int, team_ids: list[int]) -> None:
    conn = connect()
    try:
        with conn:
            conn.execute("DELETE FROM team_members WHERE user_id = ?", (user_id,))
            conn.executemany("INSERT INTO team_members (team_id, user_id) VALUES (?, ?)",
                             [(t, user_id) for t in set(team_ids)])
    finally:
        conn.close()


# ---------------------------------------------------------------- sessions
def create_session(token_hash: str, user_id: int, ttl: timedelta) -> None:
    expires = (datetime.now(timezone.utc) + ttl).isoformat(timespec="seconds")
    _exec("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
          (token_hash, user_id, now(), expires))


def get_session_user(token_hash: str) -> dict | None:
    return _one("""SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1""", (token_hash, now()))


def delete_session(token_hash: str) -> None:
    _exec("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_user_sessions(user_id: int) -> None:
    _exec("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def purge_expired_sessions() -> None:
    _exec("DELETE FROM sessions WHERE expires_at <= ?", (now(),))


# ---------------------------------------------------------------- teams
def create_team(name: str) -> int:
    return _exec("INSERT INTO teams (name, created_at) VALUES (?, ?)", (name, now()))


def get_team(team_id: int) -> dict | None:
    return _one("SELECT * FROM teams WHERE id = ?", (team_id,))


def list_teams(team_ids: list[int] | None = None) -> list[dict]:
    """All teams (team_ids=None) or only the given ones, with member/analysis counts and estimated spend."""
    where, params = "", ()
    if team_ids is not None:
        if not team_ids:
            return []
        where = f"WHERE t.id IN ({','.join('?' * len(team_ids))})"
        params = tuple(team_ids)
    return _q(f"""
        SELECT t.id, t.name, t.created_at,
               (SELECT json_group_array(user_id) FROM team_members m WHERE m.team_id = t.id) AS member_ids,
               (SELECT COUNT(*) FROM analyses a WHERE a.team_id = t.id) AS analysis_count,
               (SELECT COALESCE(SUM(json_extract(r.usage, '$.cost_usd')), 0)
                  FROM runs r JOIN analyses a ON a.id = r.analysis_id WHERE a.team_id = t.id) AS cost_usd
        FROM teams t {where} ORDER BY t.name""", params)


def update_team(team_id: int, name: str) -> None:
    _exec("UPDATE teams SET name = ? WHERE id = ?", (name, team_id))


def set_team_members(team_id: int, user_ids: list[int]) -> None:
    conn = connect()
    try:
        with conn:
            conn.execute("DELETE FROM team_members WHERE team_id = ?", (team_id,))
            conn.executemany("INSERT INTO team_members (team_id, user_id) VALUES (?, ?)",
                             [(team_id, u) for u in set(user_ids)])
    finally:
        conn.close()


def delete_team(team_id: int) -> None:
    _exec("DELETE FROM teams WHERE id = ?", (team_id,))


# ---------------------------------------------------------------- analyses
def create_analysis(name: str, description: str, default_metadata: dict | None, *,
                    team_id: int, created_by: int | None, auto_approve: bool = False) -> int:
    return _exec(
        """INSERT INTO analyses (name, description, default_metadata, created_at, team_id, created_by, auto_approve)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, description, json.dumps(default_metadata) if default_metadata else None, now(),
         team_id, created_by, int(auto_approve)),
    )


def list_analyses(team_ids: list[int] | None = None) -> list[dict]:
    """All analyses (team_ids=None, admins) or only those of the given teams."""
    where, params = "", ()
    if team_ids is not None:
        if not team_ids:
            return []
        where = f"WHERE a.team_id IN ({','.join('?' * len(team_ids))})"
        params = tuple(team_ids)
    statuses = ",".join(f"'{s}'" for s in ACTIVE_STATUSES)
    return _q(f"""
        SELECT a.id, a.name, a.description, a.created_at, a.team_id, t.name AS team_name,
               COUNT(r.id) AS run_count,
               MAX(r.created_at) AS last_run_at,
               COALESCE(SUM(r.status IN ({statuses})), 0) AS active_runs,
               COALESCE(SUM(r.status = 'awaiting_approval'), 0) AS awaiting_runs,
               COALESCE(SUM(json_extract(r.usage, '$.cost_usd')), 0) AS cost_usd
        FROM analyses a
        LEFT JOIN teams t ON t.id = a.team_id
        LEFT JOIN runs r ON r.analysis_id = a.id
        {where}
        GROUP BY a.id ORDER BY a.created_at DESC""", params)


def get_analysis(analysis_id: int) -> dict | None:
    return _one("""SELECT a.*, t.name AS team_name, u.username AS created_by_name
                   FROM analyses a LEFT JOIN teams t ON t.id = a.team_id
                   LEFT JOIN users u ON u.id = a.created_by WHERE a.id = ?""", (analysis_id,))


def update_analysis(analysis_id: int, **fields) -> None:
    if "default_metadata" in fields:
        fields["default_metadata"] = json.dumps(fields["default_metadata"]) if fields["default_metadata"] else None
    if "auto_approve" in fields:
        fields["auto_approve"] = int(bool(fields["auto_approve"]))
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
               pcap_path: str, submitted_by: int | None) -> int:
    return _exec("""
        INSERT INTO runs (analysis_id, status, stage, progress, provider, dry_run, compare_previous,
                          metadata, pcap_filename, pcap_size, pcap_sha256, pcap_path, created_at, submitted_by)
        VALUES (?, 'queued', 'queued', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (analysis_id, provider, int(dry_run), int(compare_previous), metadata, pcap_filename,
         pcap_size, pcap_sha256, pcap_path, now(), submitted_by))


def previous_runs(analysis_id: int, before_run_id: int, limit: int) -> list[dict]:
    """The last `limit` runs completed before this one in the same analysis (oldest first)."""
    rows = _q("""SELECT id, created_at, metadata, report, result FROM runs
                 WHERE analysis_id = ? AND id < ? AND status = 'done'
                 ORDER BY id DESC LIMIT ?""", (analysis_id, before_run_id, limit))
    return rows[::-1]


def get_run(run_id: int) -> dict | None:
    return _one("""SELECT r.*, u.username AS submitted_by_name FROM runs r
                   LEFT JOIN users u ON u.id = r.submitted_by WHERE r.id = ?""", (run_id,))


def list_runs(analysis_id: int) -> list[dict]:
    return _q(f"SELECT {RUN_LIST_COLUMNS} FROM runs WHERE analysis_id = ? ORDER BY created_at, id",
              (analysis_id,))


def update_run(run_id: int, **fields) -> None:
    cols = ", ".join(f"{k} = ?" for k in fields)
    _exec(f"UPDATE runs SET {cols} WHERE id = ?", (*fields.values(), run_id))


def reset_run(run_id: int) -> None:
    delete_tool_calls(run_id)
    _exec("DELETE FROM followups WHERE run_id = ?", (run_id,))
    update_run(run_id, status="queued", stage="queued", progress=0, error=None, report=None, result=None,
               context_run_ids=None, stats=None, conversation=None, started_at=None, finished_at=None,
               cancel_requested=0, active_followup_id=None)


def add_usage(run_id: int, usage: dict, followup_id: int | None = None) -> None:
    """Add one Claude turn's usage to the run (and to the follow-up, if any)."""
    def merge(current: str | None) -> str:
        total = json.loads(current) if current else {}
        for k, v in usage.items():
            total[k] = round(total.get(k, 0) + v, 6)
        return json.dumps(total)

    run = get_run(run_id)
    update_run(run_id, usage=merge(run["usage"]))
    if followup_id is not None:
        f = get_followup(followup_id)
        update_followup(followup_id, usage=merge(f["usage"]))


def queue_position(run_id: int) -> int:
    """Position in the queue (1 = next)."""
    return _q("SELECT COUNT(*) AS n FROM runs WHERE status = 'queued' AND id <= ?", (run_id,))[0]["n"]


def claim_run(run_id: int) -> bool:
    """Atomic queued → running transition; two workers can't take the same run."""
    return _rowcount("UPDATE runs SET status = 'running' WHERE id = ? AND status = 'queued'", (run_id,)) == 1


def request_cancel(run_id: int) -> str | None:
    """Cancel a run. Queued / awaiting-approval runs are cancelled immediately; running ones get a flag
    the worker checks between steps. Returns the new status, or None if the run isn't active."""
    conn = connect()
    try:
        with conn:
            cur = conn.execute("""UPDATE runs SET status = 'cancelled', stage = 'cancelled', finished_at = COALESCE(finished_at, ?)
                                  WHERE id = ? AND status IN ('queued', 'awaiting_approval')""", (now(), run_id))
            if cur.rowcount:
                conn.execute("UPDATE tool_calls SET status = 'rejected', user_note = 'cancelled', decided_at = ? "
                             "WHERE run_id = ? AND status = 'pending'", (now(), run_id))
                return "cancelled"
            cur = conn.execute("UPDATE runs SET cancel_requested = 1 WHERE id = ? AND status = 'running'", (run_id,))
            return "cancelling" if cur.rowcount else None
    finally:
        conn.close()


def request_cancel_followup(run_id: int) -> str | None:
    """Cancel the follow-up being answered on a run. The run's own analysis is kept: the run goes back
    to 'done'. Returns the new state, or None if no follow-up is active."""
    run = get_run(run_id)
    if not run or not run["active_followup_id"]:
        return None
    conn = connect()
    try:
        with conn:
            cur = conn.execute("""UPDATE runs SET status = 'done', stage = 'done', progress = 100, active_followup_id = NULL
                                  WHERE id = ? AND status IN ('queued', 'awaiting_approval')""", (run_id,))
            if cur.rowcount:
                conn.execute("UPDATE tool_calls SET status = 'rejected', user_note = 'cancelled', decided_at = ? "
                             "WHERE run_id = ? AND status = 'pending'", (now(), run_id))
                conn.execute("UPDATE followups SET status = 'cancelled', finished_at = ? WHERE id = ?",
                             (now(), run["active_followup_id"]))
                return "cancelled"
            cur = conn.execute("UPDATE runs SET cancel_requested = 1 WHERE id = ? AND status = 'running'", (run_id,))
            return "cancelling" if cur.rowcount else None
    finally:
        conn.close()


def cancel_requested(run_id: int) -> bool:
    r = _one("SELECT cancel_requested FROM runs WHERE id = ?", (run_id,))
    return bool(r and r["cancel_requested"])


# ---------------------------------------------------------------- tool calls
def create_tool_call(run_id: int, *, tool_use_id: str, tool: str, args: list, purpose: str,
                     status: str, output: str | None = None, followup_id: int | None = None) -> int:
    return _exec("""INSERT INTO tool_calls (run_id, tool_use_id, tool, args, purpose, status, output, created_at, followup_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                 (run_id, tool_use_id, tool, json.dumps(args), purpose, status, output, now(), followup_id))


def get_tool_call(call_id: int) -> dict | None:
    return _one("""SELECT t.*, u.username AS decided_by_name FROM tool_calls t
                   LEFT JOIN users u ON u.id = t.decided_by WHERE t.id = ?""", (call_id,))


def list_tool_calls(run_id: int) -> list[dict]:
    return _q("""SELECT t.*, u.username AS decided_by_name FROM tool_calls t
                 LEFT JOIN users u ON u.id = t.decided_by WHERE t.run_id = ? ORDER BY t.id""", (run_id,))


def update_tool_call(call_id: int, **fields) -> None:
    cols = ", ".join(f"{k} = ?" for k in fields)
    _exec(f"UPDATE tool_calls SET {cols} WHERE id = ?", (*fields.values(), call_id))


def decide_tool_call(call_id: int, status: str, final_args: list | None, note: str | None,
                     decided_by: int | None) -> bool:
    """pending → approved/rejected; False if a decision was already made."""
    return _rowcount("""UPDATE tool_calls SET status = ?, final_args = ?, user_note = ?, decided_at = ?, decided_by = ?
                        WHERE id = ? AND status = 'pending'""",
                     (status, json.dumps(final_args) if final_args is not None else None,
                      note, now(), decided_by, call_id)) == 1


def resume_if_decided(run_id: int) -> bool:
    """Re-queue the run if no approvals are pending (atomic). True if it was queued."""
    return _rowcount("""UPDATE runs SET status = 'queued', stage = 'tool'
                        WHERE id = ? AND status = 'awaiting_approval'
                        AND NOT EXISTS (SELECT 1 FROM tool_calls WHERE run_id = ? AND status = 'pending')""",
                     (run_id, run_id)) == 1


def delete_tool_calls(run_id: int) -> None:
    _exec("DELETE FROM tool_calls WHERE run_id = ?", (run_id,))


# ---------------------------------------------------------------- follow-ups
def create_followup(run_id: int, user_id: int | None, question: str) -> int:
    return _exec("INSERT INTO followups (run_id, user_id, question, status, created_at) VALUES (?, ?, ?, 'queued', ?)",
                 (run_id, user_id, question, now()))


def get_followup(followup_id: int) -> dict | None:
    return _one("""SELECT f.*, u.username AS user_name FROM followups f
                   LEFT JOIN users u ON u.id = f.user_id WHERE f.id = ?""", (followup_id,))


def list_followups(run_id: int) -> list[dict]:
    return _q("""SELECT f.*, u.username AS user_name FROM followups f
                 LEFT JOIN users u ON u.id = f.user_id WHERE f.run_id = ? ORDER BY f.id""", (run_id,))


def update_followup(followup_id: int, **fields) -> None:
    cols = ", ".join(f"{k} = ?" for k in fields)
    _exec(f"UPDATE followups SET {cols} WHERE id = ?", (*fields.values(), followup_id))


def start_followup(run_id: int, followup_id: int) -> bool:
    """Re-open a finished run to answer a follow-up (atomic): done → queued."""
    return _rowcount("""UPDATE runs SET status = 'queued', stage = 'followup', active_followup_id = ?, cancel_requested = 0
                        WHERE id = ? AND status = 'done'""", (followup_id, run_id)) == 1


# ---------------------------------------------------------------- maintenance
def runs_missing_stats() -> list[int]:
    """Runs that were parsed but have no stats (processed before the stats feature existed)."""
    return [r["id"] for r in _q("""SELECT id FROM runs WHERE stats IS NULL AND report IS NOT NULL
                                   AND pcap_deleted = 0 AND status IN ('done', 'failed') ORDER BY id""")]


def runs_with_expired_pcaps(days: int) -> list[dict]:
    """Finished runs whose pcap is older than `days` days and still on disk."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    statuses = ",".join(f"'{s}'" for s in TERMINAL_STATUSES)
    return _q(f"""SELECT id, pcap_path FROM runs WHERE pcap_deleted = 0 AND status IN ({statuses})
                  AND created_at < ?""", (cutoff,))


def recover_pending() -> list[int]:
    """On server restart: re-queue runs that were interrupted.

    Runs with a stored conversation resume where they left off; runs awaiting approval are left alone.
    """
    _exec("UPDATE runs SET status = 'queued' WHERE status = 'running'")
    return [r["id"] for r in _q("SELECT id FROM runs WHERE status = 'queued' ORDER BY id")]
