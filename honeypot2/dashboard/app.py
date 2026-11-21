"""
Honeypot v2 dashboard - the companion app.
Reads the same database the honeypot writes to and serves:
  * a live web UI (static/index.html)
  * a JSON API (/api/...) protected by DASH_TOKEN (header X-Token or ?token=)
  * an IP blocklist (/api/blocklist.txt) you can feed to a firewall / fail2ban / Cloudflare
"""
import hmac, ipaddress, json, os, urllib.request
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from common import db

DASH_TOKEN = os.getenv("DASH_TOKEN", "")
db.init()
app = FastAPI(title="Honeypot dashboard", docs_url=None, redoc_url=None)


def auth(x_token: str = Header(default=""), token: str = Query(default="")):
    given = x_token or token
    if DASH_TOKEN and not hmac.compare_digest(given, DASH_TOKEN):
        raise HTTPException(401, "bad token")


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.get("/api/summary", dependencies=[Depends(auth)])
def summary():
    r = db.query("""select count(*) as events, count(distinct ip) as ips,
                    coalesce(sum(case when severity >= 8 then 1 else 0 end),0) as high,
                    coalesce(sum(case when canary <> '' then 1 else 0 end),0) as canary
                    from events where tags not like '%"mine"%'""")[0]
    last = db.query("select max(ts) as ts from events")[0]["ts"]
    return {**{k: int(v or 0) for k, v in r.items()}, "last_event": last}


@app.get("/api/events", dependencies=[Depends(auth)])
def events(limit: int = 50, min_sev: int = 0, since: str = ""):
    rows = db.query("""select id, ts, ip, method, path, ua, category, mitre, severity, tags, creds, canary
                       from events where severity >= ? and ts > ? and tags not like '%"mine"%'
                       order by ts desc limit ?""", (min_sev, since, min(limit, 500)))
    for r in rows:
        r["tags"], r["creds"] = json.loads(r["tags"] or "[]"), json.loads(r["creds"] or "{}")
    return rows


def _geo(ips):
    """Best-effort country lookup (ip-api.com, free, no key). Cached in the ips table."""
    pub = [i for i in ips if _is_public(i)][:40]
    if not pub:
        return
    try:
        req = urllib.request.Request("http://ip-api.com/batch?fields=status,countryCode,query",
                                     json.dumps(pub).encode(), {"Content-Type": "application/json"})
        for r in json.loads(urllib.request.urlopen(req, timeout=5).read()):
            if r.get("status") == "success":
                db.execute("update ips set country = ? where ip = ?", (r["countryCode"], r["query"]))
    except Exception:
        pass


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@app.get("/api/top_ips", dependencies=[Depends(auth)])
def top_ips(limit: int = 15):
    rows = db.query("select ip, hits, score, country, first_seen, last_seen, blocked from ips order by score desc, hits desc limit ?", (limit,))
    missing = [r["ip"] for r in rows if not r["country"]]
    if missing:
        _geo(missing)
        rows = db.query("select ip, hits, score, country, first_seen, last_seen, blocked from ips order by score desc, hits desc limit ?", (limit,))
    return rows


@app.get("/api/categories", dependencies=[Depends(auth)])
def categories():
    return db.query("select category, count(*) as n from events where tags not like '%\"mine\"%' group by category order by n desc")


@app.get("/api/mitre", dependencies=[Depends(auth)])
def mitre():
    return db.query("select mitre, count(*) as n from events where mitre <> '' group by mitre order by n desc")


@app.get("/api/timeline", dependencies=[Depends(auth)])
def timeline(hours: int = 48):
    return db.query("select substr(ts,1,13) as hour, count(*) as n, max(severity) as max_sev from events group by substr(ts,1,13) order by hour desc limit ?", (hours,))[::-1]


@app.get("/api/canaries", dependencies=[Depends(auth)])
def canaries():
    """Issued canaries and whether anyone used them - the 'stolen credential reused' alerts."""
    return db.query("""select e.ts, e.ip, e.method, e.path, e.canary, c.ip as issued_to, c.kind
                       from events e join canaries c on c.token = e.canary
                       where e.canary <> '' order by e.ts desc limit 50""")


@app.get("/api/blocklist.txt", dependencies=[Depends(auth)])
def blocklist(min_score: int = 20):
    rows = db.query("select ip from ips where (score >= ? or blocked = 1) order by score desc", (min_score,))
    return PlainTextResponse("\n".join(r["ip"] for r in rows if _is_public(r["ip"])) + "\n")


@app.post("/api/block/{ip}", dependencies=[Depends(auth)])
def block(ip: str):
    db.execute("update ips set blocked = 1 where ip = ?", (ip,))
    return {"blocked": ip}
