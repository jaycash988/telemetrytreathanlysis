"""Attack classification: request -> (tags, category, MITRE ATT&CK id, severity 0-10).
Pure functions, no I/O, so they are easy to unit test."""
import re
from urllib.parse import unquote_plus

RULES = [  # (tag, regex, mitre, severity)
    ("log4shell",      r"\$\{\s*(jndi|env|lower|upper)[:\w]*", "T1190", 10),
    ("rce",            r"(;|\||`|\$\()\s*(wget|curl|bash|sh|nc|python|perl|powershell|cmd)\b|/bin/(ba)?sh|cmd\.exe|\beval\(|base64\s+-d|\.execute\(\)|runtime\.getruntime|processbuilder", "T1059", 9),
    ("sqli",           r"union(\s|\+|/\*.*?\*/)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d|benchmark\(|information_schema|;\s*drop\s+table|--\s*$", "T1190", 8),
    ("path_traversal", r"\.\./|\.\.\\|%2e%2e|/etc/(passwd|shadow)|c:\\windows|boot\.ini", "T1083", 7),
    ("xss",            r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*svg[^>]*on\w+\s*=", "T1059.007", 5),
    ("ssrf",           r"(url|uri|target|dest|redirect)=https?://(127\.|169\.254\.|localhost|10\.|192\.168\.)", "T1190", 7),
    ("webshell_probe", r"(c99|r57|shell|cmd|wso|b374k)\.php|eval-stdin\.php", "T1505.003", 8),
    ("secret_hunt",    r"\.env|\.git/|\.aws/|id_rsa|\.ssh/|wp-config|\.htpasswd|credentials|secrets?\.(json|ya?ml)", "T1552.001", 5),
    ("admin_probe",    r"wp-login|wp-admin|phpmyadmin|adminer|/admin|manager/html|/console|jenkins|/actuator|boaform|cgi-bin", "T1595.002", 3),
]
UA_SCANNERS = r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|acunetix|nessus|burp|hydra|python-requests|go-http-client|curl/|wget/|libwww|axios"

CATEGORY = {  # tag -> human category
    "log4shell": "Exploit attempt", "rce": "Exploit attempt", "sqli": "Injection",
    "path_traversal": "Injection", "xss": "Injection", "ssrf": "Exploit attempt",
    "webshell_probe": "Exploit attempt", "secret_hunt": "Credential/secret hunting",
    "admin_probe": "Reconnaissance", "scanner_ua": "Reconnaissance",
    "login_attempt": "Credential attack", "canary_reuse": "Credential reuse (CANARY)",
}
MITRE = {"login_attempt": "T1110", "scanner_ua": "T1595", "canary_reuse": "T1078"}


def classify(method, path, query, body, ua, extra_tags=()):
    blob = unquote_plus(f"{path}?{query} {body}").lower()
    tags, mitre, sev = [], {}, 0
    for tag, rx, mid, s in RULES:
        if re.search(rx, blob, re.I | re.S):
            tags.append(tag); mitre[tag] = mid; sev = max(sev, s)
    if re.search(UA_SCANNERS, ua or "", re.I):
        tags.append("scanner_ua"); mitre["scanner_ua"] = MITRE["scanner_ua"]; sev = max(sev, 2)
    for t in extra_tags:
        if t not in tags:
            tags.append(t); mitre[t] = MITRE.get(t, "T1078")
        sev = max(sev, 10 if t == "canary_reuse" else 6)
    # most severe tag decides the category / MITRE id
    order = [t for t in ("canary_reuse", "log4shell", "rce", "sqli", "webshell_probe", "ssrf", "path_traversal",
                         "xss", "login_attempt", "secret_hunt", "admin_probe", "scanner_ua") if t in tags]
    top = order[0] if order else None
    return tags, (CATEGORY.get(top, "Benign/unknown") if top else "Benign/unknown"), mitre.get(top, ""), sev
