"""
Low-interaction web honeypot (FastAPI) for Render, backed by Supabase Postgres.
- Serves fake exposed files / admin portals and logs EVERY request to Postgres.
- Recovers the real client IP behind Render's proxy chain (X-Forwarded-For).
- Also prints each event to stdout (prefixed "HP ") so Render's log stream
  holds a readable backup copy you can screenshot.
Nothing here executes attacker input; all credentials/keys below are fake.

Requires schema.sql to have been run once against the Supabase database
(Supabase dashboard -> SQL Editor -> paste schema.sql -> Run).
"""
import asyncio, ipaddress, json, os, secrets, uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs

from psycopg_pool import ConnectionPool
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

DATABASE_URL = os.environ["DATABASE_URL"]  # Supabase: Project Settings -> Database -> Connection string (URI, Session pooler)
EXPORT_TOKEN = os.getenv("EXPORT_TOKEN", "")
MY_IPS = {i.strip() for i in os.getenv("MY_IPS", "").split(",") if i.strip()}
MAX_BODY = 4096

pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, open=True,
                      kwargs={"prepare_threshold": None, "connect_timeout": 5})  # works with session AND transaction pooler

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # hide FastAPI's own giveaways

# ---------------------------------------------------------------- client IP
def _ip(s):
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None

def client_ip(request: Request):
    """Return (client_ip, raw_xff). Order of trust:
    1. CF-Connecting-IP / True-Client-IP (set by Cloudflare, which fronts Render)
    2. first PUBLIC address in X-Forwarded-For
    3. socket peer (the proxy itself - last resort)
    NOTE: XFF can be forged by the attacker (they can pre-fill it), so the raw
    header is always logged; verify your own test request from a known IP."""
    h = request.headers
    for name in ("cf-connecting-ip", "true-client-ip"):
        ip = _ip(h.get(name, ""))
        if ip:
            return str(ip), h.get("x-forwarded-for", "")
    xff = h.get("x-forwarded-for", "")
    for part in xff.split(","):
        ip = _ip(part)
        if ip and ip.is_global:
            return str(ip), xff
    return (request.client.host if request.client else "unknown"), xff

# ------------------------------------------------------------------ logging
INSERT_SQL = """
insert into events (id, ts, ip, xff, peer, method, path, query, ua, host,
                     referer, content_type, header_names, body, creds, is_mine)
values (%(id)s, %(ts)s, %(ip)s, %(xff)s, %(peer)s, %(method)s, %(path)s, %(query)s,
        %(ua)s, %(host)s, %(referer)s, %(content_type)s, %(header_names)s, %(body)s,
        %(creds)s, %(is_mine)s)
on conflict (id) do nothing
"""

def _insert_sync(ev: dict):
    row = {**ev,
           "ip": ev["ip"] if _ip(ev["ip"]) else None,   # inet column: must be null, not "unknown"
           "header_names": json.dumps(ev["header_names"]),
           "creds": json.dumps(ev["creds"])}
    with pool.connection(timeout=5) as conn:   # fail fast if DB is down; never hang a scanner's request
        conn.execute(INSERT_SQL, row)

async def log_event(ev: dict):
    print("HP " + json.dumps(ev, ensure_ascii=False), flush=True)  # readable backup in Render's log tab
    try:
        await asyncio.to_thread(_insert_sync, ev)
    except Exception as e:
        print("HP-DB-ERROR " + str(e), flush=True)  # DB hiccup should never break the lure response

def extract_creds(ctype: str, body: str):
    creds = {}
    try:
        data = json.loads(body) if "json" in ctype else {k: v[0] for k, v in parse_qs(body).items()}
    except Exception:
        return creds
    if not isinstance(data, dict):
        return creds
    for k, v in data.items():
        kl = str(k).lower()
        if kl in ("username", "user", "log", "login", "email", "userid", "uname"):
            creds["username"] = str(v)[:100]
        elif kl in ("password", "pass", "pwd", "passwd"):
            creds["password"] = str(v)[:100]
    return creds

# -------------------------------------------------------------------- lures
FAKE_ENV = """APP_ENV=production
APP_KEY=base64:kf83jHs0Zk2mQ9xTn1vLw7Yb4RcE6uPdA5gS8hJ0tXo=
DB_HOST=10.0.3.14
DB_DATABASE=orders
DB_USERNAME=svc_backup
DB_PASSWORD=Winter2024!Prod
AWS_ACCESS_KEY_ID=AKIAFAKEHONEYPOT00000
AWS_SECRET_ACCESS_KEY=honeypot/notreal/0000000000000000
"""
FAKE_GIT = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.com/acme-corp/internal-portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""
FAKE_ACTUATOR = {"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment",
                 "properties": {"DB_PASSWORD": {"value": "******"}}}]}
ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.git/\nDisallow: /phpmyadmin/\nDisallow: /internal/\n"
NOT_FOUND = ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>404 Not Found</title></head>"
             "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr>"
             "<address>Apache/2.4.41 (Ubuntu) Server</address></body></html>")

def login_page(title, err=""):
    return f"""<html><head><title>{title}</title></head><body style="font-family:sans-serif;background:#f1f1f1">
<div style="width:320px;margin:80px auto;background:#fff;padding:24px;border:1px solid #ccc">
<h2>{title}</h2>{'<p style="color:#c00">'+err+'</p>' if err else ''}
<form method="post"><input name="username" placeholder="Username"><br><br>
<input name="password" type="password" placeholder="Password"><br><br>
<button type="submit">Log in</button></form></div></body></html>"""

def build_response(path: str, method: str) -> Response:
    p = path.lower()
    last = p.rsplit("/", 1)[-1]
    hdr = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
    if last.startswith(".env"):
        return PlainTextResponse(FAKE_ENV, headers=hdr)
    if "/.git/config" in p:
        return PlainTextResponse(FAKE_GIT, headers=hdr)
    if "/.git/head" in p:
        return PlainTextResponse("ref: refs/heads/main\n", headers=hdr)
    if p == "/robots.txt":
        return PlainTextResponse(ROBOTS, headers=hdr)
    if "actuator" in p:
        return Response(json.dumps(FAKE_ACTUATOR), media_type="application/json", headers=hdr)
    if "server-status" in p:
        return PlainTextResponse("Apache Server Status for localhost\nServer uptime: 41 days 3 hours\nTotal accesses: 8841203\n", headers=hdr)
    if p.endswith(".sql") or "backup" in last or p.endswith((".bak", ".zip", ".tar.gz", ".gz")):
        return PlainTextResponse("-- MySQL dump 10.13  Distrib 5.7.42\n-- Host: localhost  Database: orders\n-- (truncated)\n", headers=hdr)
    if p in ("/config.json", "/config.php", "/wp-config.php.bak", "/config.yml"):
        return Response(json.dumps({"db": {"host": "10.0.3.14", "user": "svc_backup", "pass": "Winter2024!Prod"}}),
                        media_type="application/json", headers=hdr)
    err = "Invalid username or password." if method == "POST" else ""
    if "wp-login" in p or p.startswith("/wp-admin"):
        return HTMLResponse(login_page("WordPress &rsaquo; Log In", err), headers=hdr)
    if "phpmyadmin" in p or "pma" in p or "adminer" in p:
        return HTMLResponse(login_page("phpMyAdmin", err.replace("Invalid username or password.", "Cannot log in to the MySQL server")), headers=hdr)
    if p.startswith(("/admin", "/administrator", "/login", "/manager", "/console", "/cpanel", "/boaform", "/signin", "/user/login")):
        return HTMLResponse(login_page("Administration Portal", err), headers=hdr)
    if p == "/":
        return HTMLResponse("<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>", headers=hdr)
    return HTMLResponse(NOT_FOUND, status_code=404, headers=hdr)

# ------------------------------------------------------------------- routes
@app.api_route("/healthz", methods=["GET", "HEAD"])   # UptimeRobot sends HEAD as well as GET
async def healthz():           # Render health check + uptime pinger; NOT logged
    return PlainTextResponse("ok")

@app.get("/_export/{token}")
async def export(token: str, limit: int = 5000):
    # download your logs as JSON lines (secret path from EXPORT_TOKEN), newest first
    if not (EXPORT_TOKEN and secrets.compare_digest(token, EXPORT_TOKEN)):
        return HTMLResponse(NOT_FOUND, status_code=404)
    def _fetch():
        with pool.connection(timeout=10) as conn:
            cur = conn.execute(
                "select id, ts, ip, xff, peer, method, path, query, ua, host, referer, "
                "content_type, header_names, body, creds, is_mine from events "
                "order by ts desc limit %s", (limit,))
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    rows = await asyncio.to_thread(_fetch)
    lines = "\n".join(json.dumps(r, default=str) for r in rows)
    return PlainTextResponse(lines, media_type="application/x-ndjson")

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def catch_all(request: Request, full_path: str):
    raw = await request.body()
    body = raw[:MAX_BODY].decode("utf-8", "replace")
    ctype = request.headers.get("content-type", "")
    ip, xff = client_ip(request)
    h = request.headers
    ev = {
        "id": uuid.uuid4().hex[:12],
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": ip,
        "xff": xff,
        "peer": request.client.host if request.client else None,
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "ua": h.get("user-agent", ""),
        "host": h.get("host", ""),
        "referer": h.get("referer", ""),
        "content_type": ctype,
        "header_names": sorted(h.keys()),
        "body": body,
        "creds": extract_creds(ctype, body) if request.method in ("POST", "PUT") else {},
        "is_mine": ip in MY_IPS,
    }
    await log_event(ev)
    return build_response(request.url.path, request.method)
