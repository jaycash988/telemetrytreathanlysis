"""
Honeypot v2 - medium-interaction web honeypot.

New compared to v1:
  * attack classification (SQLi / XSS / RCE / log4shell / traversal / ...) + MITRE ATT&CK id + severity
  * per-visitor CANARY credentials: every fake secret we hand out is unique, so if it is ever
    presented back to us (login form, Authorization header, URL...) we know the visitor is
    reusing stolen data -> severity 10 "canary_reuse"
  * fake REST API with fake JWT login (any password "works"), fake Jenkins script console
  * per-IP threat score + tarpit (slow responses) for abusive IPs
  * session tracking (cookie) so one actor's requests can be grouped
  * optional Discord/Slack webhook alerts for severity >= ALERT_MIN
  * shares its database with the dashboard (dashboard/app.py)
All credentials/keys are fake. Nothing here executes attacker input.
"""
import asyncio, base64, hashlib, ipaddress, json, os, re, secrets, urllib.request, uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote_plus

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from common import db
from honeypot.detect import classify

MY_IPS = {i.strip() for i in os.getenv("MY_IPS", "").split(",") if i.strip()}
ALERT_URL = os.getenv("ALERT_WEBHOOK_URL", "")
ALERT_MIN = int(os.getenv("ALERT_MIN", "8"))
TARPIT_SCORE = int(os.getenv("TARPIT_SCORE", "60"))
MAX_BODY = 4096

db.init()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
HDR = {"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "Express"}


# ------------------------------------------------------------------ helpers
def _ip(s):
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    h = request.headers
    for n in ("cf-connecting-ip", "true-client-ip"):
        ip = _ip(h.get(n, ""))
        if ip:
            return str(ip)
    for part in h.get("x-forwarded-for", "").split(","):
        ip = _ip(part)
        if ip and ip.is_global:
            return str(ip)
    return request.client.host if request.client else "unknown"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_creds(ctype, body):
    try:
        data = json.loads(body) if "json" in ctype else {k: v[0] for k, v in parse_qs(body).items()}
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        kl = str(k).lower()
        if kl in ("username", "user", "log", "login", "email", "uname"):
            out["username"] = str(v)[:100]
        elif kl in ("password", "pass", "pwd", "passwd"):
            out["password"] = str(v)[:100]
    return out


# ------------------------------------------------------------------ canaries
def new_canary(ip: str, kind: str) -> str:
    """Create a unique fake secret. Stored under two lookup keys (full + short for the DB password)."""
    c = secrets.token_hex(8)
    for tok in (c, c[:10]):
        db.execute("insert into canaries (token, ts, ip, kind) values (?,?,?,?) on conflict (token) do nothing",
                   (tok, now(), ip, kind))
    return c


def aws_key(c): return "AKIA" + c.upper()
def db_pass(c): return f"Prod-{c[:10]}!"
def api_key(c): return "sk_live_" + c
def fake_jwt(c, user="admin"):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b({'alg':'HS256','typ':'JWT'})}.{b({'sub':user,'role':'admin','iat':1700000000})}.{c}"


def find_canaries(blob: str):
    blob = unquote_plus(blob).lower()   # form bodies arrive URL-encoded ("!" -> %21)
    cands = (set(re.findall(r"[0-9a-f]{16}", blob)) | set(re.findall(r"akia([0-9a-f]{16})", blob))
             | set(re.findall(r"prod-([0-9a-f]{10})!", blob)))
    if not cands:
        return []
    ph = ",".join("?" * len(cands))
    return [r["token"] for r in db.query(f"select token from canaries where token in ({ph})", tuple(cands))]


# ------------------------------------------------------------------ lures
def fake_env(c):
    return (f"APP_ENV=production\nAPP_KEY=base64:{base64.b64encode(os.urandom(32)).decode()}\n"
            f"DB_HOST=10.0.3.14\nDB_DATABASE=orders\nDB_USERNAME=svc_backup\nDB_PASSWORD={db_pass(c)}\n"
            f"AWS_ACCESS_KEY_ID={aws_key(c)}\nAWS_SECRET_ACCESS_KEY={hashlib.sha256(c.encode()).hexdigest()[:40]}\n"
            f"STRIPE_SECRET={api_key(c)}\n")


def login_page(title, err=""):
    e = f'<p style="color:#c00">{err}</p>' if err else ""
    return (f'<html><head><title>{title}</title></head><body style="font-family:sans-serif;background:#f1f1f1">'
            f'<div style="width:320px;margin:80px auto;background:#fff;padding:24px;border:1px solid #ccc">'
            f'<h2>{title}</h2>{e}<form method="post"><input name="username" placeholder="Username"><br><br>'
            f'<input name="password" type="password" placeholder="Password"><br><br>'
            f'<button type="submit">Log in</button></form></div></body></html>')


JENKINS = ('<html><head><title>Script Console [Jenkins]</title></head><body style="font-family:monospace">'
           '<h2>Script Console</h2><p>Type in an arbitrary Groovy script and execute it on the server.</p>'
           '<form method="post"><textarea name="script" rows="10" cols="80">println(Jenkins.instance.pluginManager.plugins)</textarea>'
           '<br><button>Run</button></form></body></html>')
NOT_FOUND = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>"


def lure(request: Request, path: str, body: str, ip: str):
    """Return (Response, extra_tags). Issues canaries where it hands out secrets."""
    p, m = path.lower(), request.method
    last = p.rsplit("/", 1)[-1]
    auth = request.headers.get("authorization", "")
    if last.startswith(".env"):
        return PlainTextResponse(fake_env(new_canary(ip, "env")), headers=HDR), []
    if "/.git/config" in p:
        return PlainTextResponse('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/acme-corp/internal-portal.git\n', headers=HDR), []
    if p == "/robots.txt":
        return PlainTextResponse("User-agent: *\nDisallow: /admin/\nDisallow: /api/v1/\nDisallow: /jenkins/\nDisallow: /backup/\n", headers=HDR), []
    if p == "/api/v1/auth/login":
        creds = extract_creds(request.headers.get("content-type", ""), body)
        c = new_canary(ip, "jwt")
        return JSONResponse({"token": fake_jwt(c, creds.get("username", "admin")), "expires_in": 3600}, headers=HDR), ["login_attempt"]
    if p.startswith("/api/v1/"):
        if not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "missing bearer token"}, status_code=401, headers=HDR), []
        if p == "/api/v1/keys":
            c = new_canary(ip, "api_key")
            return JSONResponse({"keys": [{"name": "prod-deploy", "key": api_key(c), "aws": aws_key(c)}]}, headers=HDR), []
        if p == "/api/v1/users":
            return JSONResponse({"users": [{"id": 1, "email": "admin@acme-corp.example", "role": "admin"},
                                           {"id": 2, "email": "j.doe@acme-corp.example", "role": "dev"}]}, headers=HDR), []
        return JSONResponse({"status": "ok", "path": path}, headers=HDR), []
    if "jenkins" in p:
        return HTMLResponse(JENKINS, headers=HDR), []
    if "actuator" in p:
        return JSONResponse({"activeProfiles": ["prod"], "propertySources": [{"name": "env", "properties": {
            "DB_PASSWORD": {"value": db_pass(new_canary(ip, "actuator"))}}}]}, headers=HDR), []
    if p.endswith((".sql", ".bak", ".zip", ".gz")) or "backup" in last:
        return PlainTextResponse("-- MySQL dump 10.13\n-- Host: localhost  Database: orders\n-- (truncated)\n", headers=HDR), []
    is_login = m == "POST"
    err = "Invalid username or password." if is_login else ""
    tags = ["login_attempt"] if is_login and extract_creds(request.headers.get("content-type", ""), body) else []
    if "wp-login" in p or p.startswith("/wp-admin"):
        return HTMLResponse(login_page("WordPress &rsaquo; Log In", err), headers=HDR), tags
    if "phpmyadmin" in p or "adminer" in p:
        return HTMLResponse(login_page("phpMyAdmin", "Cannot log in to the MySQL server" if is_login else ""), headers=HDR), tags
    if p.startswith(("/admin", "/login", "/manager", "/console", "/signin")):
        return HTMLResponse(login_page("Administration Portal", err), headers=HDR), tags
    if p == "/":
        return HTMLResponse("<html><head><title>acme-corp</title></head><body><h1>acme-corp internal services</h1></body></html>", headers=HDR), []
    return HTMLResponse(NOT_FOUND, status_code=404, headers=HDR), []


# ------------------------------------------------------------------ pipeline
def record(ev: dict, score_add: int) -> int:
    db.execute("""insert into events (id, ts, ip, session, method, path, query, ua, host, body, headers,
                  tags, severity, category, mitre, creds, canary) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (ev["id"], ev["ts"], ev["ip"], ev["session"], ev["method"], ev["path"], ev["query"], ev["ua"],
                ev["host"], ev["body"], json.dumps(ev["headers"]), json.dumps(ev["tags"]), ev["severity"],
                ev["category"], ev["mitre"], json.dumps(ev["creds"]), ev["canary"]))
    db.execute("""insert into ips (ip, first_seen, last_seen, hits, score) values (?,?,?,1,?)
                  on conflict (ip) do update set last_seen = excluded.last_seen, hits = ips.hits + 1,
                  score = ips.score + excluded.score""", (ev["ip"], ev["ts"], ev["ts"], score_add))
    return db.query("select score from ips where ip = ?", (ev["ip"],))[0]["score"]


def alert(ev):
    if not ALERT_URL:
        return
    msg = f"[HP2] sev {ev['severity']} {ev['category']} from {ev['ip']}: {ev['method']} {ev['path']} tags={ev['tags']}"
    req = urllib.request.Request(ALERT_URL, json.dumps({"content": msg, "text": msg}).encode(),
                                 {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        print("HP-ALERT-ERROR", e, flush=True)


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthz():
    return PlainTextResponse("ok")


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def catch_all(request: Request, full_path: str):
    body = (await request.body())[:MAX_BODY].decode("utf-8", "replace")
    ip, h = client_ip(request), request.headers
    sid = request.cookies.get("sid") or secrets.token_hex(6)
    path = request.url.path

    def work():
        found = find_canaries(f"{path} {request.url.query} {body} {h.get('authorization','')} {h.get('cookie','')}")
        resp, extra = lure(request, path, body, ip)
        if found:
            extra = list(extra) + ["canary_reuse"]
        tags, cat, mitre, sev = classify(request.method, path, request.url.query, body, h.get("user-agent", ""), extra)
        if ip in MY_IPS:
            tags, sev = tags + ["mine"], 0
        ev = {"id": uuid.uuid4().hex[:12], "ts": now(), "ip": ip, "session": sid, "method": request.method,
              "path": path, "query": request.url.query, "ua": h.get("user-agent", ""), "host": h.get("host", ""),
              "body": body, "headers": sorted(h.keys()), "tags": tags, "severity": sev, "category": cat,
              "mitre": mitre, "creds": extract_creds(h.get("content-type", ""), body) if request.method in ("POST", "PUT") else {},
              "canary": ",".join(found)}
        print("HP2 " + json.dumps(ev, ensure_ascii=False), flush=True)
        score = record(ev, 0 if "mine" in tags else sev)
        if sev >= ALERT_MIN and "mine" not in tags:
            alert(ev)
        return resp, score

    try:
        resp, score = await asyncio.to_thread(work)
    except Exception as e:  # DB hiccup must never break the lure
        print("HP2-ERROR", e, flush=True)
        return HTMLResponse(NOT_FOUND, status_code=404, headers=HDR)
    if score >= TARPIT_SCORE:
        await asyncio.sleep(3)   # tarpit: waste abusive scanners' time
    resp.set_cookie("sid", sid, max_age=86400, httponly=True)
    return resp
