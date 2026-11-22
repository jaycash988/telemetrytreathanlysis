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
:root{--bg:#121211;--panel:#1c1c1b;--line:#2c2c2a;--fg:#ececea;--mut:#8f8f8a;--acc:#c98a07;--ok:#16a37b}
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
.grid{display:grid;grid-template-columns:1fr 2fr;gap:12px;margin-top:14px}.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:12px;margin-top:12px}@media(max-width:700px){.grid{grid-template-columns:1fr}.grid>.panel{grid-column:auto!important}}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow:hidden}.panel h3{font-size:.9rem;margin:0 0 8px}.donut{display:flex;align-items:center;gap:14px}.donut ul{list-style:none;margin:0;padding:0;font-size:.8rem}.donut i{display:inline-block;width:10px;height:10px;margin-right:6px;border-radius:2px}.donut b{margin-left:4px}.hb{display:grid;grid-template-columns:110px 1fr 28px;gap:6px;align-items:center;font-size:.78rem;margin:5px 0}.hb span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right;color:var(--mut)}.hb div{background:#262624;height:14px;border-radius:2px}.hb u{display:block;height:100%;border-radius:2px}.hb b{font-size:.78rem}svg text{fill:var(--mut);font-size:10px}svg rect.b{fill:var(--acc)}
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
BLUE, ORANGE, GREEN, GREY, PURPLE, AMBER, PINK = "#3b86e6", "#d9582a", "#16a37b", "#6f6e69", "#9087e8", "#c98a07", "#d6507f"
CLASS_COLOR = {"Third-party scanner": BLUE, "Researcher test": ORANGE, "Platform check": GREEN, "Internal": GREY}
BROWSER_UA = ("mozilla/5.0",)


def source_class(ev, my_ips=frozenset()):
    """Who is behind a request. Heuristic, documented on the page:
    internal = Render's own 127.0.0.1 probes; researcher = the owner's IPs (MY_IPS) or a normal desktop/mobile
    browser UA; platform = Go-http-client / Google-Cloud checks run by the hosting platform; scanner = the rest."""
    ip, ua = ev["ip"], ev["ua"].lower()
    if ip in INTERNAL_IPS:
        return "Internal"
    if ip in my_ips:
        return "Researcher test"
    if ua.startswith("go-http-client") or ip.startswith(("34.", "35.")):
        return "Platform check"
    if ua.startswith(BROWSER_UA) and not SCANNER_UA.search(ua):
        return "Researcher test"
    return "Third-party scanner"


def _short_ua(ua):
    u = ua.lower()
    if not u:
        return "(empty)"
    for key, name in (("axios", "axios (scanner)"), ("go-http-client", "Go-http-client"), ("curl", "curl"), ("python-requests", "python-requests"),
                      ("edg/", "Edge (Windows)" if "windows" in u else "Edge"), ("chrome", "Chrome (Windows)" if "windows" in u else "Chrome"),
                      ("firefox", "Firefox"), ("safari", "Safari")):
        if key in u:
            return name
    return ua[:30]


def _donut(title, items, center):
    tot = sum(v for _, v, _ in items) or 1
    r, c, off, parts = 52, 2 * 3.14159265 * 52, 0.0, []
    for _, v, col in items:
        ln = c * v / tot
        parts.append(f"<circle r='{r}' cx='70' cy='70' fill='none' stroke='{col}' stroke-width='22' stroke-dasharray='{ln:.2f} {c - ln:.2f}' "
                     f"stroke-dashoffset='{-off:.2f}' transform='rotate(-90 70 70)'/>")
        off += ln
    leg = "".join(f"<li><i style='background:{col}'></i>{escape(l)} <b>{v}</b></li>" for l, v, col in items)
    return (f"<div class=panel><h3>{escape(title)}</h3><div class=donut><svg viewBox='0 0 140 140' width=130 height=130 role=img>"
            f"{''.join(parts)}<text x=70 y=77 text-anchor=middle style='fill:var(--fg);font-size:22px;font-weight:700'>{center}</text></svg>"
            f"<ul>{leg}</ul></div></div>")


def _hbars(title, items, color=BLUE, colors=None):
    mx = max([v for _, v in items] or [1])
    rows = "".join(f"<div class=hb><span title='{escape(l)}'>{escape(l)}</span><div><u style='width:{100 * v / mx:.1f}%;"
                   f"background:{(colors or {}).get(l, color)}'></u></div><b>{v}</b></div>" for l, v in items)
    return f"<div class=panel><h3>{escape(title)}</h3>{rows or '<p class=sub>No data</p>'}</div>"


def _source_bars(counts):
    order = ["Third-party scanner", "Researcher test", "Platform check", "Internal"]
    mx = max(counts.get(k, 0) for k in order) or 1
    bars = []
    for i, k in enumerate(order):
        v, x = counts.get(k, 0), 30 + i * 85
        h = 130 * v / mx
        bars.append(f"<rect x='{x}' y='{150 - h:.1f}' width='60' height='{h:.1f}' fill='{CLASS_COLOR[k]}'/>"
                    f"<text x={x + 30} y={144 - h:.1f} text-anchor=middle style='fill:var(--fg)'>{v}</text>"
                    f"<text x={x + 30} y=168 text-anchor=middle>{k.split()[0].replace('Third-party','Scanner')}</text>")
    return f"<div class=panel><h3>Requests by source</h3><svg viewBox='0 0 380 180' width=100%>{''.join(bars)}</svg></div>"


def _histogram(events, bin_h=6):
    """Requests + unique IPs per 6-hour bin; long empty stretches are shaded as a logging gap."""
    if not events:
        return ""
    from datetime import timedelta
    start = events[0]["ts"].replace(minute=0, second=0, microsecond=0)
    start -= timedelta(hours=start.hour % bin_h)
    n = int((events[-1]["ts"] - start).total_seconds() // (bin_h * 3600)) + 1
    req, ipset = [0] * n, [set() for _ in range(n)]
    for e in events:
        i = int((e["ts"] - start).total_seconds() // (bin_h * 3600))
        req[i] += 1
        ipset[i].add(e["ip"])
    w, h, L, B = 760, 190, 36, 28
    mx = max(max(req), 4) + 3   # headroom for the legend
    X = lambda i: L + (w - L - 10) * i / max(n - 1, 1)
    Y = lambda v: h - B - (h - B - 12) * v / mx
    gaps, i = [], 0
    while i < n:                       # >= 48 h without any event
        if req[i] == 0:
            j = i
            while j < n and req[j] == 0:
                j += 1
            if (j - i) * bin_h >= 48:
                gaps.append((i, j - 1))
            i = j
        else:
            i += 1
    out = "".join(f"<rect x='{X(a):.1f}' y='8' width='{max(X(b) - X(a), 1):.1f}' height='{h - B - 8}' fill='#ffffff' opacity='0.05'/>"
                  f"<text x='{(X(a) + X(b)) / 2:.1f}' y='24' text-anchor='middle'>no events / logging gap</text>" for a, b in gaps)
    for t in range(0, mx + 1, max(1, mx // 4)):
        out += f"<line x1='{L}' x2='{w - 10}' y1='{Y(t):.1f}' y2='{Y(t):.1f}' stroke='#2c2c2a'/><text x='{L - 6}' y='{Y(t) + 3:.1f}' text-anchor='end'>{t}</text>"
    last = -99
    for k in range(n):
        t = start + timedelta(hours=k * bin_h)
        if t.hour == 0 and k - last >= max(2, n // 10):
            last = k
            out += f"<text x='{X(k):.1f}' y='{h - 10}' text-anchor='middle'>{t:%d %b}</text>"
    for series, col in ((req, PINK), ([len(x) for x in ipset], GREEN)):
        pts = " ".join(f"{X(k):.1f},{Y(v):.1f}" for k, v in enumerate(series))
        out += f"<polyline points='{pts}' fill='none' stroke='{col}' stroke-width='2'/>" + "".join(
            f"<circle cx='{X(k):.1f}' cy='{Y(v):.1f}' r='2.5' fill='{col}'><title>{(start + timedelta(hours=k * bin_h)):%d %b %H:%M} UTC: {v}</title></circle>"
            for k, v in enumerate(series) if v)
    out += f"<text x='{L + 8}' y='16' style='fill:{PINK}'>● Requests</text><text x='{L + 80}' y='16' style='fill:{GREEN}'>● Unique source IPs</text>"
    return (f"<div class=panel><h3>Requests histogram ({bin_h}-hour bins, external traffic)</h3>"
            f"<svg viewBox='0 0 {w} {h}' width='100%'>{out}</svg></div>")


def render_report(rows, generated_at=None, my_ips=frozenset()):
    events, internal_n = prepare(rows)
    all_rows = [dict(r) for r in rows]
    gen = (generated_at or datetime.utcnow()).strftime("%d %b %Y %H:%M:%S")
    for e in events:
        e["source"] = source_class(e, my_ips)
    ext = events
    if not ext:
        return _page("Honeypot telemetry dashboard", "<h1>Honeypot Telemetry Dashboard</h1>" + _nav() + "<p class=note>No external events recorded yet.</p>")

    all_ts = sorted(_ts(r["ts"]) for r in all_rows)
    src = collections.Counter(e["source"] for e in ext)
    src["Internal"] = internal_n
    ips = collections.Counter(e["ip"] for e in ext)
    ip_class = {}
    for e in ext:
        ip_class[e["ip"]] = e["source"]
    lures = {e["path"] for e in ext if _is_lure(e["path"]) and e["path"] != "/"}
    mitre = collections.Counter((e["tid"], e["tname"]) for e in ext)
    cats = collections.Counter((e["category"], e["tid"], e["tname"]) for e in ext)
    methods = collections.Counter(r.get("method") or "?" for r in all_rows)
    paths = collections.Counter(e["path"] for e in ext)
    uas = collections.Counter(_short_ua(e["ua"]) for e in ext)
    creds = sum(1 for e in ext if e["creds"])

    kpi = [(len(all_rows), "Requests logged", ""), (len(ext), "External requests", ""), (len(ips), "Unique external IPs", ""),
           (len({i for i, c in ip_class.items() if c == "Third-party scanner"}), "Third-party scanners", BLUE),
           (len(lures), "Lure endpoints hit", AMBER), (creds, "Credential attempts", "")]
    body = (f"<h1>Honeypot Telemetry Dashboard</h1><p class=sub>telemetrytreathanlysis · Render + Supabase · "
            f"{all_ts[0]:%d %b %H:%M} – {all_ts[-1]:%d %b %H:%M} UTC · live from the <code>events</code> table, refreshed {gen} UTC</p>{_nav()}"
            "<div class=cards style='margin-top:16px'>" + "".join(
                f"<div class=card><b style='color:{c or 'var(--fg)'}'>{v}</b><span>{l}</span></div>" for v, l, c in kpi) + "</div>")
    body += "<div class=grid>" + _source_bars(src) + _histogram(ext) + "</div>"
    body += "<div class=grid3>"
    body += _donut("Source IP classification (external)", [(k, src[k], CLASS_COLOR[k]) for k in ("Third-party scanner", "Researcher test", "Platform check") if src[k]], len(ext))
    pal = [PURPLE, BLUE, ORANGE, AMBER, GREEN, PINK, GREY]
    body += _donut("MITRE ATT&CK technique (external)", [(f"{t} {n.split(':')[-1].strip()[:22]}", v, pal[i % 7]) for i, ((t, n), v) in enumerate(mitre.most_common(6))], len(ext))
    body += _donut("HTTP methods (all)", [(m, v, [BLUE, GREY, GREEN, ORANGE, PURPLE][i % 5]) for i, (m, v) in enumerate(methods.most_common(5))], len(all_rows))
    body += "</div><div class=grid3>"
    body += _hbars("Top requested paths (external)", [(p[:28], v) for p, v in paths.most_common(8)], BLUE,
                   {p[:28]: AMBER for p in paths if _is_lure(p) and p != "/"})
    body += _hbars("Top user-agents (external)", uas.most_common(6), PURPLE)
    iprows = "".join(f"<tr><td><code>{escape(mask_ip(ip))}</code></td><td style='color:{CLASS_COLOR[ip_class[ip]]}'>● {ip_class[ip]}</td><td class=n>{v}</td></tr>"
                     for ip, v in ips.most_common(8))
    body += f"<div class=panel><h3>Top source IPs (external, masked)</h3><table><tr><th>IP</th><th>Class</th><th>Req</th></tr>{iprows}</table></div></div>"

    body += "<h2>Attack categories → MITRE ATT&amp;CK</h2>" + _table(
        ["Category (what the client was doing)", "Technique", "Name", "Events"],
        [(escape(c), f"<span class='tag hot'>{escape(t)}</span>", escape(n), k) for (c, t, n), k in cats.most_common()], num_cols=(3,))
    body += ("<h2>How to read this</h2><p class=note>Every request to a non-reserved path is stored by <code>app.py</code> (UTC time, resolved client IP, raw "
             "X-Forwarded-For, method, path, query, user-agent, header names, body ≤ 4 KB). <code>classify.py</code> maps each event to a MITRE ATT&amp;CK "
             "technique. <b>Source classes:</b> <i>Internal</i> = Render's own 127.0.0.1 health probes (counted in “requests logged”, excluded from "
             "external); <i>Platform check</i> = Go-http-client / Google-Cloud (34.x, 35.x) post-deploy checks; <i>Researcher test</i> = the owner's IPs "
             "(<code>MY_IPS</code>) or a normal browser user-agent; <i>Third-party scanner</i> = everything else. IPs are masked on this public page. "
             "Raw rows: <a href='/logs' style='color:var(--acc)'>/logs</a> · JSON: <a href='/logs.json' style='color:var(--acc)'>/logs.json</a> · "
             "written report: <a href='/report.pdf' style='color:var(--acc)'>PDF</a>.</p>")
    return _page("Honeypot telemetry dashboard", body)


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
