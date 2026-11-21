"""Tiny DB layer shared by the honeypot and the dashboard.
DATABASE_URL=postgresql://...  -> Supabase/Postgres (production)
unset                          -> local SQLite file (development / tests)
SQL is written with '?' placeholders and works on both."""
import os, sqlite3, threading

URL = os.getenv("DATABASE_URL", "")
PG = URL.startswith("postgres")

SCHEMA = """
create table if not exists events (
    id text primary key, ts text not null, ip text, session text,
    method text, path text, query text, ua text, host text, body text,
    headers text, tags text, severity integer default 0, category text,
    mitre text, creds text, canary text
);
create table if not exists canaries (
    token text primary key, ts text, ip text, kind text, used_by text, used_at text
);
create table if not exists ips (
    ip text primary key, first_seen text, last_seen text,
    hits integer default 0, score integer default 0, country text, blocked integer default 0
);
create index if not exists events_ts_idx on events (ts);
create index if not exists events_ip_idx on events (ip);
"""

if PG:
    from psycopg_pool import ConnectionPool
    from psycopg.rows import dict_row
    _pool = ConnectionPool(URL, min_size=1, max_size=5, open=True,
                           kwargs={"prepare_threshold": None, "connect_timeout": 5, "row_factory": dict_row})
else:
    _lock = threading.Lock()
    _conn = sqlite3.connect(os.getenv("SQLITE_PATH", "honeypot2.db"), check_same_thread=False)
    _conn.row_factory = sqlite3.Row


def _run(sql, params, fetch):
    if PG:
        with _pool.connection(timeout=5) as c:
            cur = c.execute(sql.replace("?", "%s"), params)
            return cur.fetchall() if fetch else None
    with _lock:
        cur = _conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()] if fetch else None
        _conn.commit()
        return rows


def execute(sql, params=()):
    _run(sql, params, False)


def query(sql, params=()):
    return [dict(r) for r in _run(sql, params, True)]


def init():
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            execute(stmt)
