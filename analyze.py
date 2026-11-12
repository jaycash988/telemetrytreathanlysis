#!/usr/bin/env python3
"""
Turn honeypot telemetry (stored in Supabase Postgres) into report numbers, tables and charts.
Usage:
  export DATABASE_URL="postgresql://postgres.xxxx:[PASSWORD]@...pooler.supabase.com:6543/postgres"
  python analyze.py --exclude 1.2.3.4,5.6.7.8     # drop your own test IPs
  python analyze.py --file events.jsonl           # fall back to a JSONL export instead of the DB
Outputs: report_data.md, events_enriched.csv, top_paths.csv, charts/*.png
Geolocation uses ip-api.com (needs internet, free, HTTP, ~45 req/min; batched).
"""
import argparse, collections, csv, json, os, re, time, urllib.request
from datetime import datetime

import psycopg

# ---- MITRE ATT&CK mapping -------------------------------------------------
PAYLOAD_RULES = [  # checked against path+query+body
    (r"\$\{jndi:", "Log4Shell exploit attempt", "T1190", "Exploit Public-Facing Application"),
    (r"(\.\./|%2e%2e%2f|/etc/passwd)", "Path traversal / LFI", "T1190", "Exploit Public-Facing Application"),
    (r"(union\s+select|or\s+1=1|sleep\(\d)", "SQL injection probe", "T1190", "Exploit Public-Facing Application"),
    (r"(;|\||`|\$\()\s*(wget|curl|sh|bash|nc|chmod|tftp)", "Command injection / malware dropper", "T1059.004", "Unix Shell"),
]
PATH_RULES = [  # checked against lower-cased path
    (r"\.env|\.aws|\.git|\.ssh|\.npmrc|\.docker|credentials|secrets|config\.(json|php|yml)|wp-config",
     "Exposed config / secrets hunting", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (r"\.sql|backup|\.bak|\.zip|\.tar|dump", "Backup / DB dump hunting", "T1595.003", "Active Scanning: Wordlist Scanning"),
    (r"boaform|cgi-bin|hnap1|gponform|setup\.cgi|tmunblock|/shell|\.cgi", "IoT / router exploitation (Mirai-style)", "T1190", "Exploit Public-Facing Application"),
    (r"eval-stdin|webshell|c99|r57|/shell\.php|/cmd\.php|/wso", "Web-shell / RCE probing", "T1505.003", "Server Software Component: Web Shell"),
    (r"wp-login|wp-admin|xmlrpc|wp-content|wp-includes", "WordPress scanning", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"phpmyadmin|pma|adminer|myadmin", "DB admin portal probing", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"actuator|jenkins|manager/html|solr|console|server-status|/api/v", "Framework / service enumeration", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"^/(admin|administrator|login|signin|cpanel|user/login)", "Admin portal probing", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"^/(robots\.txt|sitemap\.xml|favicon\.ico|)$", "Basic recon / fingerprinting", "T1592", "Gather Victim Host Information"),
]
SCANNER_UA = re.compile(r"zgrab|masscan|nmap|nikto|sqlmap|censys|shodan|internet-measurement|"
                        r"python-requests|go-http-client|curl|wget|libwww|hello, world|dirbuster|gobuster|"
                        r"fuzz|nuclei|expanse|leakix|netcraft|palo alto", re.I)

def classify(ev):
    target = (ev["path"] + "?" + ev.get("query", "") + " " + ev.get("body", "")).lower()
    for pat, cat, tid, tname in PAYLOAD_RULES:
        if re.search(pat, target):
            return cat, tid, tname
    if ev.get("creds"):
        return "Credential attack (login attempt)", "T1110", "Brute Force"
    for pat, cat, tid, tname in PATH_RULES:
        if re.search(pat, ev["path"].lower()):
            return cat, tid, tname
    return "Generic directory / wordlist scan", "T1595.003", "Active Scanning: Wordlist Scanning"

# ---- helpers ---------------------------------------------------------------
def load_from_db(limit=200000):
    """Pull every logged event from the Supabase `events` table."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is not set. export DATABASE_URL=\"postgresql://...\" first, "
                          "or use --file to read a JSONL export instead.")
    with psycopg.connect(database_url) as conn:
        cur = conn.execute(
            "select id, ts, ip, xff, peer, method, path, query, ua, host, referer, "
            "content_type, header_names, body, creds, is_mine from events "
            "order by ts asc limit %s", (limit,))
        cols = [c.name for c in cur.description]
        rows = cur.fetchall()
    out = []
    for r in rows:
        ev = dict(zip(cols, r))
        ev["ts"] = ev["ts"].isoformat()
        ev["ip"] = str(ev["ip"]) if ev["ip"] is not None else "unknown"
        # jsonb columns come back as Python objects already via psycopg3's json support
        ev["header_names"] = ev["header_names"] or []
        ev["creds"] = ev["creds"] or {}
        out.append(ev)
    return out

def load_from_file(path):
    seen, out = set(), []
    for line in open(path, encoding="utf-8", errors="replace"):
        i = line.find("{")
        if i < 0:
            continue
        try:
            ev = json.loads(line[i:])
        except json.JSONDecodeError:
            continue
        if "ip" in ev and "path" in ev and ev.get("id") not in seen:
            seen.add(ev.get("id")); out.append(ev)
    return out

def geolocate(ips, cache_file="geo_cache.json"):
    cache = json.load(open(cache_file)) if os.path.exists(cache_file) else {}
    todo = [i for i in ips if i not in cache]
    for n in range(0, len(todo), 100):
        batch = todo[n:n + 100]
        req = urllib.request.Request("http://ip-api.com/batch?fields=status,country,countryCode,query",
                                     data=json.dumps(batch).encode(), headers={"Content-Type": "application/json"})
        try:
            for r in json.load(urllib.request.urlopen(req, timeout=20)):
                cache[r["query"]] = {"country": r.get("country", "Unknown"), "cc": r.get("countryCode", "??")} \
                    if r.get("status") == "success" else {"country": "Unknown/Private", "cc": "??"}
        except Exception as e:
            print("geo lookup failed:", e)
        time.sleep(1.5)
    json.dump(cache, open(cache_file, "w"))
    return cache

def table(rows, headers):
    s = "| " + " | ".join(headers) + " |\n|" + "---|" * len(headers) + "\n"
    return s + "".join("| " + " | ".join(str(c) for c in r) + " |\n" for r in rows)

# ---- main ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="read a JSONL export instead of querying the Supabase DATABASE_URL")
    ap.add_argument("--exclude", default="", help="comma-separated IPs to drop (your own tests)")
    ap.add_argument("--no-geo", action="store_true")
    a = ap.parse_args()
    excl = {x.strip() for x in a.exclude.split(",") if x.strip()}
    raw = load_from_file(a.file) if a.file else load_from_db()
    events = [e for e in raw if e["ip"] not in excl and not e.get("is_mine")]
    if not events:
        raise SystemExit("No events found.")
    events.sort(key=lambda e: e["ts"])

    ips = sorted({e["ip"] for e in events})
    geo = {} if a.no_geo else geolocate(ips)
    country = lambda ip: geo.get(ip, {}).get("country", "Unknown")

    # credential attack refinement per IP: spraying vs brute force
    users, pwds = collections.defaultdict(set), collections.defaultdict(set)
    for e in events:
        c = e.get("creds") or {}
        if c.get("username"): users[e["ip"]].add(c["username"])
        if c.get("password"): pwds[e["ip"]].add(c["password"])
    for e in events:
        e["category"], e["tid"], e["tname"] = classify(e)
        if e["tid"] == "T1110":
            u, p = len(users[e["ip"]]), len(pwds[e["ip"]])
            if u >= 5 and p <= max(2, u // 2):
                e["category"], e["tid"], e["tname"] = "Credential attack: password spraying", "T1110.003", "Password Spraying"
            else:
                e["category"], e["tid"], e["tname"] = "Credential attack: brute force / guessing", "T1110.001", "Password Guessing"
        e["country"] = country(e["ip"])
        e["scanner_ua"] = bool(SCANNER_UA.search(e.get("ua", "")))

    t0, t1 = datetime.fromisoformat(events[0]["ts"]), datetime.fromisoformat(events[-1]["ts"])
    per_ip = collections.Counter(e["ip"] for e in events)
    per_country = collections.Counter(e["country"] for e in events)
    ips_per_country = collections.defaultdict(set)
    for e in events: ips_per_country[e["country"]].add(e["ip"])
    paths = collections.Counter(e["path"] for e in events)
    cats = collections.Counter((e["category"], e["tid"], e["tname"]) for e in events)
    uas = collections.Counter(e.get("ua", "")[:80] or "(empty)" for e in events)
    methods = collections.Counter(e["method"] for e in events)
    cred_pairs = collections.Counter((e["creds"].get("username", ""), e["creds"].get("password", "")) for e in events if e.get("creds"))
    hourly = collections.Counter(e["ts"][:13] for e in events)

    md = "# Honeypot telemetry summary\n\n"
    md += f"- Observation window: {t0} -> {t1} UTC ({(t1 - t0).total_seconds() / 3600:.1f} hours)\n"
    md += f"- **Total attempts (requests):** {len(events)}\n- **Unique source IPs:** {len(ips)}\n"
    md += f"- **Countries observed:** {len([c for c in per_country if c not in ('Unknown','Unknown/Private')])}\n"
    md += f"- **Credential submissions:** {sum(cred_pairs.values())} ({len(cred_pairs)} unique user/pass pairs)\n"
    md += f"- Requests with scanner/tool user-agent: {sum(e['scanner_ua'] for e in events)}\n\n"
    md += "## Attempts by country\n" + table([(c, n, len(ips_per_country[c])) for c, n in per_country.most_common(15)], ["Country", "Requests", "Unique IPs"])
    md += "\n## Top source IPs\n" + table([(i, n, country(i)) for i, n in per_ip.most_common(15)], ["IP", "Requests", "Country"])
    md += "\n## Most requested files / routes\n" + table(paths.most_common(25), ["Path", "Hits"])
    md += "\n## Attack categories -> MITRE ATT&CK\n" + table([(c, t, tn, n) for (c, t, tn), n in cats.most_common()], ["Category", "Technique ID", "Technique", "Events"])
    md += "\n## HTTP methods\n" + table(methods.most_common(), ["Method", "Count"])
    md += "\n## Top user-agents\n" + table(uas.most_common(12), ["User-Agent", "Count"])
    md += "\n## Top credential pairs tried\n" + table([(u, p, n) for (u, p), n in cred_pairs.most_common(15)], ["Username", "Password", "Count"])
    open("report_data.md", "w", encoding="utf-8").write(md)

    with open("events_enriched.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["ts", "ip", "country", "method", "path", "ua", "category", "mitre_id", "mitre_name"])
        for e in events: w.writerow([e["ts"], e["ip"], e["country"], e["method"], e["path"], e.get("ua", ""), e["category"], e["tid"], e["tname"]])
    with open("top_paths.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["path", "hits"]); w.writerows(paths.most_common())

    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        os.makedirs("charts", exist_ok=True)
        def bar(data, title, fn, horizontal=True):
            labels, vals = zip(*data)
            plt.figure(figsize=(9, 5))
            (plt.barh if horizontal else plt.bar)(labels[::-1] if horizontal else labels, vals[::-1] if horizontal else vals)
            plt.title(title); plt.tight_layout(); plt.savefig(f"charts/{fn}", dpi=150); plt.close()
        bar(per_country.most_common(10), "Requests by country (top 10)", "countries.png")
        bar(paths.most_common(15), "Most requested paths (top 15)", "paths.png")
        bar([(f"{c[1]} {c[0][:35]}", n) for c, n in cats.most_common(10)], "Attack categories (MITRE technique)", "mitre.png")
        hrs = sorted(hourly); bar([(h[5:], hourly[h]) for h in hrs], "Requests per hour (UTC)", "timeline.png", horizontal=False)
    except ImportError:
        print("matplotlib not installed - skipped charts")
    print(md)

if __name__ == "__main__":
    main()
