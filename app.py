
from collections import Counter
from flask import Flask, request
from datetime import datetime, timezone
import json
import os
from html import escape
import psycopg2

app = Flask(__name__)

LOG_FILE = "telemetry.jsonl"


def ensure_table():
    """Create the telemetry table on startup if it does not already exist."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return
    try:
        with psycopg2.connect(database_url, sslmode="require", connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS public.telemetry_events (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ NOT NULL,
                        ip_address TEXT,
                        method TEXT,
                        path TEXT,
                        user_agent TEXT,
                        classification TEXT
                    )
                    """
                )
        app.logger.warning("PostgreSQL telemetry table is ready")
    except Exception:
        app.logger.exception("Could not create or check the PostgreSQL telemetry table")


ensure_table()


def classify_request(path):
    suspicious_paths = {
        "/admin": "Possible admin panel discovery",
        "/administrator": "Possible administrator panel discovery",
        "/admin/login": "Possible administrative login probing",

        "/login": "Possible login endpoint probing",
        "/wp-admin": "Possible WordPress admin probing",
        "/wp-login.php": "Possible WordPress login probing",

        "/phpmyadmin": "Possible database administration probing",
        "/server-status": "Possible server status probing",
        "/server-info": "Possible server information probing",

        "/.env": "Possible configuration file probing",
        "/.git/config": "Possible exposed Git repository probing",
        "/config.php": "Possible configuration file probing",
        "/configuration.php": "Possible configuration file probing",
        "/database.sql": "Possible database backup probing",
        "/backup.zip": "Possible backup archive probing",

        "/api": "Possible API endpoint discovery",
        "/api/login": "Possible API login probing",
        "/api/v1/login": "Possible API login probing",

        "/xmlrpc.php": "Possible XML-RPC endpoint probing",
        "/manager/html": "Possible application manager probing",

        "/actuator": "Possible application actuator probing",
        "/actuator/env": "Possible environment information probing",

        "/console": "Possible application console probing",
        "/debug": "Possible debug endpoint probing",
        "/test": "Possible test endpoint probing",
        "/phpinfo.php": "Possible PHP information probing",

        "/robots.txt": "Possible site reconnaissance",
        "/robot.txt": "Possible site reconnaissance",
        "/reboot.txt": "Unusual file probing"
    }

    return suspicious_paths.get(path, "Normal request")

def log_request():
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent"),
        # Render supplies X-Forwarded-For. Use the first address in the chain.
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip(),
        "classification": classify_request(request.path)
    }

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        # Keep local development usable if DATABASE_URL is not configured.
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
        return

    try:
        with psycopg2.connect(database_url, sslmode="require", connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.telemetry_events
                        (timestamp, ip_address, method, path, user_agent, classification)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event["timestamp"],
                        event["ip"],
                        event["method"],
                        event["path"],
                        event["user_agent"],
                        event["classification"],
                    ),
                )
    except Exception:
        app.logger.exception("Could not save telemetry to PostgreSQL")
        # Preserve a local fallback record if the database is temporarily unavailable.
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as file:
                file.write(json.dumps(event) + "\n")
        except OSError:
            app.logger.exception("Could not save telemetry to the local fallback log")


@app.before_request
def record_request():
    log_request()


@app.route("/")
def home():
    return "Telemetry & Threat Analysis Honeypot"


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/admin")
def admin():
    return {
        "message": "Admin portal detected",
        "status": "restricted"
    }, 403


@app.route("/administrator")
def administrator():
    return {
        "message": "Administrator portal detected",
        "status": "restricted"
    }, 403


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return {
        "message": "Administrative login endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/login", methods=["GET", "POST"])
def login():
    return {
        "message": "Login endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/wp-admin")
def wp_admin():
    return {
        "message": "WordPress administration area detected",
        "status": "restricted"
    }, 403


@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    return {
        "message": "WordPress login endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/phpmyadmin")
def phpmyadmin():
    return {
        "message": "Database administration interface detected",
        "status": "restricted"
    }, 403


@app.route("/server-status")
def server_status():
    return {
        "message": "Server status endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/server-info")
def server_info():
    return {
        "message": "Server information endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/.env")
def env_file():
    return {
        "message": "Configuration file access monitored",
        "status": "restricted"
    }, 403


@app.route("/.git/config")
def git_config():
    return {
        "message": "Repository configuration access monitored",
        "status": "restricted"
    }, 403


@app.route("/config.php")
def config_php():
    return {
        "message": "Configuration file access monitored",
        "status": "restricted"
    }, 403


@app.route("/configuration.php")
def configuration_php():
    return {
        "message": "Configuration file access monitored",
        "status": "restricted"
    }, 403


@app.route("/database.sql")
def database_sql():
    return {
        "message": "Database backup access monitored",
        "status": "restricted"
    }, 403


@app.route("/backup.zip")
def backup_zip():
    return {
        "message": "Backup archive access monitored",
        "status": "restricted"
    }, 403


@app.route("/api")
def api():
    return {
        "message": "API endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/api/login", methods=["GET", "POST"])
def api_login():
    return {
        "message": "API login endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/api/v1/login", methods=["GET", "POST"])
def api_v1_login():
    return {
        "message": "API v1 login endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    return {
        "message": "XML-RPC endpoint monitored",
        "status": "disabled"
    }, 403


@app.route("/manager/html")
def manager_html():
    return {
        "message": "Application manager endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/actuator")
def actuator():
    return {
        "message": "Application actuator endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/actuator/env")
def actuator_env():
    return {
        "message": "Application environment endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/console")
def console():
    return {
        "message": "Application console endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/debug")
def debug():
    return {
        "message": "Debug endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/test")
def test():
    return {
        "message": "Test endpoint monitored",
        "status": "restricted"
    }, 403


@app.route("/phpinfo.php")
def phpinfo():
    return {
        "message": "PHP information endpoint monitored",
        "status": "restricted"
    }, 403

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\n"


@app.route("/dashboard")
def dashboard():
    total_requests = 0
    ips = set()
    routes = Counter()
    classifications = Counter()
    recent_events = []

    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        try:
            with psycopg2.connect(database_url, sslmode="require", connect_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT timestamp, ip_address, method, path, user_agent, classification
                        FROM public.telemetry_events
                        ORDER BY timestamp ASC
                        """
                    )
                    rows = cur.fetchall()

            for timestamp, ip_address, method, path, user_agent, classification in rows:
                event = {
                    "timestamp": timestamp.isoformat() if timestamp else "Unknown",
                    "ip": ip_address,
                    "method": method,
                    "path": path,
                    "user_agent": user_agent,
                    "classification": classification or "Unknown (older log)",
                }
                recent_events.append(event)
                total_requests += 1
                if ip_address:
                    ips.add(ip_address)
                routes[path or "Unknown"] += 1
                classifications[event["classification"]] += 1

        except Exception:
            app.logger.exception("Could not read telemetry from PostgreSQL")
            # Show local fallback records if the database is temporarily unavailable.
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as file:
                    for line in file:
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        recent_events.append(event)
                        total_requests += 1
                        if event.get("ip"):
                            ips.add(event["ip"])
                        routes[event.get("path") or "Unknown"] += 1
                        classifications[event.get("classification") or "Unknown (older log)"] += 1
            except FileNotFoundError:
                pass
    else:
        # Local development mode uses the JSONL file.
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                for line in file:
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    recent_events.append(event)
                    total_requests += 1
                    if event.get("ip"):
                        ips.add(event["ip"])
                    routes[event.get("path") or "Unknown"] += 1
                    classifications[event.get("classification") or "Unknown (older log)"] += 1
        except FileNotFoundError:
            pass

    normal_requests = classifications.get("Normal request", 0)
    suspicious_requests = sum(
        count
        for name, count in classifications.items()
        if name not in ["Normal request", "Unknown (older log)"]
    )

    recent_rows = ""

    for event in recent_events[-10:][::-1]:
        recent_rows += f"""
        <tr>
            <td>{escape(str(event.get("timestamp", "Unknown")))}</td>
            <td>{escape(str(event.get("ip", "Unknown")))}</td>
            <td>{escape(str(event.get("method", "Unknown")))}</td>
            <td>{escape(str(event.get("path", "Unknown")))}</td>
            <td>
    <span class="classification">
        {escape(str(event.get("classification") or "Unknown"))}
    </span>
</td>
        </tr>
        """

    route_rows = "".join(
        f"<tr><td>{escape(str(route))}</td><td>{count}</td></tr>"
        for route, count in routes.most_common()
    )

    classification_rows = "".join(
        f"<tr><td>{escape(str(name))}</td><td>{count}</td></tr>"
        for name, count in classifications.most_common()
    )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Telemetry Dashboard</title>
        <link rel="stylesheet" href="/static/css/style.css">

        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                margin: 0;
                padding: 30px;
            }}

            h1 {{
                color: #172033;
            }}

            .cards {{
                display: flex;
                gap: 20px;
                flex-wrap: wrap;
                margin-bottom: 30px;
            }}

            .card {{
                background: white;
                padding: 20px;
                border-radius: 12px;
                width: 200px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }}

            .card h3 {{
                margin-top: 0;
                color: #555;
            }}

            .number {{
                font-size: 32px;
                font-weight: bold;
                color: #146ee8;
            }}

            .section {{
                background: white;
                padding: 20px;
                margin-top: 20px;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                overflow-x: auto;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            th, td {{
                padding: 10px;
                border-bottom: 1px solid #ddd;
                text-align: left;
            }}

            th {{
                background: #eef3f9;
            }}
        </style>
    </head>

    <body>

        <h1>Telemetry & Threat Analysis Dashboard</h1>

        <div class="cards">

            <div class="card">
                <h3>Total Requests</h3>
                <div class="number">{total_requests}</div>
            </div>

            <div class="card">
                <h3>Unique IPs</h3>
                <div class="number">{len(ips)}</div>
            </div>

            <div class="card">
                <h3>Suspicious Requests</h3>
                <div class="number">{suspicious_requests}</div>
            </div>

            <div class="card">
                <h3>Normal Requests</h3>
                <div class="number">{normal_requests}</div>
            </div>

        </div>

        <div class="section">
            <h2>Top Requested Routes</h2>

            <table>
                <tr>
                    <th>Route</th>
                    <th>Requests</th>
                </tr>

                {route_rows}
            </table>
        </div>

        <div class="section">
            <h2>Request Classifications</h2>

            <table>
                <tr>
                    <th>Classification</th>
                    <th>Count</th>
                </tr>

                {classification_rows}
            </table>
        </div>

        <div class="section">
            <h2>Recent Requests</h2>

            <table>
                <tr>
                    <th>Time</th>
                    <th>IP Address</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Classification</th>
                </tr>

                {recent_rows}
            </table>
        </div>

    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(debug=False)