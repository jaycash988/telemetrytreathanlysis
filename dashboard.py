"""
Read-only analysis pages for the honeypot (/report and /logs).

Everything is computed live from the `events` table, so the page always matches
the data in Supabase. All attacker-controlled values (path, UA, ...) are
HTML-escaped, and client IPs are masked (last IPv4 octet / last 80 bits of
IPv6) because these pages are public.
"""
import collections
import ipaddress
from datetime import datetime
from html import escape

from classify import SCANNER_UA, classify

INTERNAL_IPS = {"127.0.0.1", "::1"}          # Render's in-container health probes


def mask_ip(ip) -> str:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return "unknown"
    if a.version == 4:
        return ".".join(str(a).split(".")[:3]) + ".x"
    return ":".join(a.exploded.split(":")[:3]) + ":x"


def _ts(v) -> datetime:
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v))


def prepare(rows):
    """Classify rows (dicts straight from the events table); split internal probes from real traffic."""
    events, internal = [], 0
    for r in rows:
        r = dict(r)
        r["ip"] = str(r["ip"]) if r.get("ip") is not None else "unknown"
        r["creds"] = r.get("creds") or {}
        r["ts"] = _ts(r["ts"])
        r["path"] = r.get("path") or "/"
        r["ua"] = r.get("ua") or ""
        r["body"] = r.get("body") or ""
        r["query"] = r.get("query") or ""
        if r["ip"] in INTERNAL_IPS:
            internal += 1
            continue
        r["category"], r["tid"], r["tname"] = classify(r)
        r["scanner_ua"] = bool(SCANNER_UA.search(r["ua"]))
        events.append(r)
    events.sort(key=lambda e: e["ts"])
    return events, internal


# ------------------------------------------------------------------ html bits
CSS = """
:root{--bg:#0f1419;--panel:#171d25;--line:#2a3441;--fg:#e6e9ee;--mut:#8b97a6;--acc:#f0a30a;--ok:#3ecf8e}
@media (prefers-color-scheme:light){:root{--bg:#f6f5f1;--panel:#fff;--line:#ddd9cf;--fg:#1b1b1a;--mut:#5f6b7a;--acc:#b36b00;--ok:#13804f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
p.sub{color:var(--mut);margin:0 0 14px}nav a{color:var(--acc);margin-right:16px;text-decoration:none}nav a:hover{text-decoration:underline}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.card b{display:block;font-size:1.6rem;line-height:1.2}.card span{color:var(--mut);font-size:.8rem}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{padding:6px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}
td.n{text-align:right;font-variant-numeric:tabular-nums}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem;word-break:break-all}
.tag{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 6px;font-size:.75rem;color:var(--mut)}
.tag.hot{color:var(--acc);border-color:var(--acc)}.note{background:var(--panel);border-left:3px solid var(--acc);padding:10px 14px;border-radius:4px;color:var(--mut);font-size:.88rem}
svg text{fill:var(--mut);font-size:10px}svg rect.b{fill:var(--acc)}
"""


def _page(title, body):
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=robots content='noindex'><title>{escape(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>")


def _nav():
    return "<nav><a href='/report'>Analysis</a><a href='/logs'>Event log</a><a href='/logs.json'>Log (JSON)</a><a href='/report.pdf'>Full written report (PDF)</a></nav>"


def _table(headers, rows, num_cols=()):
    h = "".join(f"<th>{escape(x)}</th>" for x in headers)
    out = []
    for r in rows:
        out.append("<tr>" + "".join(
            f"<td class=n>{c}</td>" if i in num_cols else f"<td>{c}</td>" for i, c in enumerate(r)) + "</tr>")
    return f"<div class=wrap><table><tr>{h}</tr>{''.join(out) or '<tr><td colspan=99>No data</td></tr>'}</table></div>"


def _timeline_svg(events):
    if not events:
        return ""
    span_h = (events[-1]["ts"] - events[0]["ts"]).total_seconds() / 3600
    fmt, label = ("%Y-%m-%d", "day") if span_h > 240 else ("%Y-%m-%d %H:00", "hour")
    buckets = collections.Counter(e["ts"].strftime(fmt) for e in events)
    keys = sorted(buckets)
    peak = max(buckets.values())
    w, h, pad = 1000, 160, 28
    bw = max(2, (w - 2 * pad) / max(len(keys), 1))
    bars = []
    for i, k in enumerate(keys):
        bh = (h - 2 * pad) * buckets[k] / peak
        x = pad + i * bw
        bars.append(f"<rect class=b x={x:.1f} y={h - pad - bh:.1f} width={max(bw - 1, 1):.1f} height={bh:.1f}>"
                    f"<title>{escape(k)} UTC: {buckets[k]} request(s)</title></rect>")
    return (f"<div class=wrap><svg viewBox='0 0 {w} {h}' width=100% role=img aria-label='Requests per {label}'>"
            f"{''.join(bars)}<text x={pad} y={h - 8}>{escape(keys[0])}</text>"
            f"<text x={w - pad} y={h - 8} text-anchor=end>{escape(keys[-1])} UTC</text>"
            f"<text x={pad} y=14>peak {peak}/{label}</text></svg></div>")


# -------------------------------------------------------------------- /report
def render_report(rows, generated_at=None):
    events, internal = prepare(rows)
    gen = (generated_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")
    head = ("<h1>Telemetry &amp; Threat Analysis: Honeypot Findings</h1>"
            "<p class=sub>Low-interaction web honeypot (FastAPI on Render, telemetry in Supabase Postgres). "
            f"Computed live from the <code>events</code> table at {gen} UTC.</p>{_nav()}")
    if not events:
        return _page("Honeypot analysis", head + "<p class=note>No external events recorded yet.</p>")

    ips = collections.Counter(e["ip"] for e in events)
    cats = collections.Counter((e["category"], e["tid"], e["tname"]) for e in events)
    paths = collections.Counter(e["path"] for e in events)
    uas = collections.Counter((e["ua"][:90] or "(empty)") for e in events)
    methods = collections.Counter(e["method"] for e in events)
    creds = sum(1 for e in events if e["creds"])
    t0, t1 = events[0]["ts"], events[-1]["ts"]
    hours = (t1 - t0).total_seconds() / 3600

    cards = [(len(events), "requests logged"), (len(ips), "unique source IPs"),
             (sum(e["scanner_ua"] for e in events), "with scanner/tool user-agent"),
             (creds, "credential submissions"), (f"{hours:.0f} h", "first to last event"),
             (internal, "Render health probes (excluded)")]
    body = head + "<h2>Summary</h2><div class=cards>" + "".join(
        f"<div class=card><b>{v}</b><span>{escape(l)}</span></div>" for v, l in cards) + "</div>"
    body += (f"<p class=note style='margin-top:12px'>Window: {t0:%Y-%m-%d %H:%M} → {t1:%Y-%m-%d %H:%M} UTC. "
             "Source IPs are masked (last octet hidden). Requests to this analysis site itself are never logged. "
             "Requests from the researcher's own test machines are included unless their IPs are listed in <code>MY_IPS</code>.</p>")

    body += "<h2>Requests over time</h2>" + _timeline_svg(events)

    body += "<h2>Attack categories → MITRE ATT&amp;CK</h2>" + _table(
        ["Category (what the client was doing)", "Technique", "Name", "Events"],
        [(escape(c), f"<span class='tag hot'>{escape(t)}</span>", escape(n), k) for (c, t, n), k in cats.most_common()],
        num_cols=(3,))

    body += "<h2>Most requested paths</h2>" + _table(
        ["Path", "Hits", "Lure served"],
        [(f"<code>{escape(p[:120])}</code>", k, "yes" if _is_lure(p) else "404") for p, k in paths.most_common(20)],
        num_cols=(1,))

    per_ip = []
    for ip, k in ips.most_common(15):
        ev = [e for e in events if e["ip"] == ip]
        per_ip.append((f"<code>{escape(mask_ip(ip))}</code>", k, f"{ev[0]['ts']:%d %b %H:%M}",
                       escape(", ".join(sorted({e['category'] for e in ev}))[:110]),
                       "yes" if any(e["scanner_ua"] for e in ev) else "no"))
    body += "<h2>Source IPs</h2>" + _table(["IP (masked)", "Requests", "First seen (UTC)", "Behaviour", "Tool UA"], per_ip, num_cols=(1,))

    body += "<h2>User-agents</h2>" + _table(["User-Agent", "Requests"], [(f"<code>{escape(u)}</code>", k) for u, k in uas.most_common(10)], num_cols=(1,))
    body += "<h2>HTTP methods</h2>" + _table(["Method", "Requests"], [(escape(m), k) for m, k in methods.most_common()], num_cols=(1,))

    body += ("<h2>How this was produced</h2><p class=note>Every request to a non-reserved path is written to the <code>events</code> table by "
             "<code>app.py</code> (timestamp, resolved client IP, raw X-Forwarded-For, method, path, query, user-agent, header names, body ≤ 4 KB). "
             "<code>classify.py</code> maps each event to a MITRE ATT&amp;CK technique from payload and path rules; this page and "
             "<code>analyze.py</code> use the same rules. See the <a href='/logs' style='color:var(--acc)'>raw event log</a> for the underlying rows "
             "and the <a href='/report.pdf' style='color:var(--acc)'>written report</a> for methodology, interpretation and limitations.</p>")
    return _page("Honeypot analysis", body)


def _is_lure(p):
    p = p.lower()
    return any(s in p for s in (".env", ".git", "wp-login", "wp-admin", "phpmyadmin", "pma", "adminer", "actuator", "server-status",
                                 "robots.txt", "config.", ".sql", "backup", ".bak", ".zip", ".gz")) or p == "/" or p.startswith(
        ("/admin", "/administrator", "/login", "/manager", "/console", "/cpanel", "/boaform", "/signin", "/user/login"))


# ---------------------------------------------------------------------- /logs
def render_logs(rows, limit=300):
    events, internal = prepare(rows)
    head = ("<h1>Honeypot event log</h1><p class=sub>Most recent requests first (max "
            f"{limit}). IPs masked; request bodies and passwords are not shown.</p>{_nav()}")
    shown = list(reversed(events))[:limit]
    tr = [(f"{e['ts']:%Y-%m-%d %H:%M:%S}", f"<code>{escape(mask_ip(e['ip']))}</code>", escape(e["method"] or ""),
           f"<code>{escape((e['path'] + ('?' + e['query'] if e['query'] else ''))[:140])}</code>",
           f"<code>{escape(e['ua'][:60])}</code>", f"<span class='tag hot'>{escape(e['tid'])}</span> {escape(e['category'])}",
           "yes" if e["creds"] else "") for e in shown]
    body = head + f"<p class=note>{len(events)} external events stored; {internal} internal health probes (127.0.0.1) excluded.</p>"
    body += _table(["Time (UTC)", "Source IP", "Method", "Path", "User-Agent", "Classification", "Creds"], tr)
    return _page("Honeypot event log", body)


def logs_json(rows, limit=5000):
    events, _ = prepare(rows)
    return [{"ts": e["ts"].isoformat(), "ip": mask_ip(e["ip"]), "method": e["method"], "path": e["path"], "query": e["query"],
             "ua": e["ua"], "category": e["category"], "mitre_id": e["tid"], "mitre_name": e["tname"],
             "credential_attempt": bool(e["creds"])} for e in reversed(events)][:limit]
