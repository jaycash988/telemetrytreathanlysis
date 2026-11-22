"""Shared event classification (MITRE ATT&CK mapping) used by analyze.py and the live /report page."""
import re

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
