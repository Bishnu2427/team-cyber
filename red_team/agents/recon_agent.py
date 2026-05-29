"""
Recon Agent — Phase 2

Code mode : Scans source files for debug flags, hardcoded credentials,
            exposed endpoints, and insecure configurations.
URL  mode : HTTP-probes the target for server disclosure, exposed sensitive
            files, admin panels, CORS issues, and SSL problems.
"""
import os
import re
import socket
import ssl
import datetime
from typing import List
from urllib.parse import urlparse

import httpx

_UA = "TeamCyber-Scanner/2.0 (Authorised Security Assessment)"
_TIMEOUT = 12


# ── Public entry point ─────────────────────────────────────────────

def run_recon(project_path: str, tech_stack: List[str],
              target_url: str = "") -> List[dict]:
    if target_url:
        return _recon_url(target_url)
    return _recon_code(project_path, tech_stack)


# ══════════════════════════════════════════════════════════════════
#  URL MODE
# ══════════════════════════════════════════════════════════════════

def _recon_url(url: str) -> List[dict]:
    findings: List[dict] = []
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    headers = {"User-Agent": _UA, "Accept": "text/html,application/json,*/*"}

    try:
        with httpx.Client(verify=False, timeout=_TIMEOUT,
                          headers=headers, follow_redirects=True) as client:
            try:
                resp = client.get(url)
            except Exception as exc:
                print(f"[recon] Cannot reach {url}: {exc}")
                return []

            _check_server_disclosure(resp, findings, url)
            _check_cors(client, url, findings)
            _check_https_redirect(parsed, findings, url)
            _check_sensitive_paths(client, base, findings)

    except Exception as exc:
        print(f"[recon] URL probe error: {exc}")

    _check_ssl(parsed, findings, url)
    return findings


def _check_server_disclosure(resp: httpx.Response, findings: list, url: str):
    h = resp.headers
    server  = h.get("server", "")
    powered = h.get("x-powered-by", "")

    if server and re.search(r"\d+\.\d+", server):
        findings.append(_finding(
            "Web Server Version Disclosure", "low", 0.95, url,
            "recon-agent", "A05:2021-Security Misconfiguration",
            f"Server header reveals version: '{server}'. Attackers can target known CVEs for this exact version.",
            "Configure your web server to suppress or obscure the Server header version (e.g., ServerTokens Prod in Apache).",
            f"Server: {server}",
        ))

    if powered:
        findings.append(_finding(
            "Technology Stack Disclosure (X-Powered-By)", "low", 0.95, url,
            "recon-agent", "A05:2021-Security Misconfiguration",
            f"X-Powered-By header discloses backend runtime: '{powered}'.",
            "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off.",
            f"X-Powered-By: {powered}",
        ))

    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                          resp.text[:8000], re.IGNORECASE)
    if generator:
        findings.append(_finding(
            "CMS/Framework Version in Meta Tag", "low", 0.88, url,
            "recon-agent", "A05:2021-Security Misconfiguration",
            f"Generator meta tag discloses platform version: '{generator.group(1)}'.",
            "Remove or sanitise the generator meta tag from your HTML output.",
            f'<meta name="generator" content="{generator.group(1)}">',
        ))


def _check_cors(client: httpx.Client, url: str, findings: list):
    try:
        r = client.get(url, headers={"Origin": "https://evil-attacker.com"})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "false").lower()
        if acao in ("*", "https://evil-attacker.com"):
            sev = "high" if acac == "true" else "medium"
            findings.append(_finding(
                "CORS Misconfiguration", sev, 0.92, url,
                "recon-agent", "A01:2021-Broken Access Control",
                (f"Access-Control-Allow-Origin reflects arbitrary origins ('{acao}')"
                 + (f" and Allow-Credentials is true — cross-origin credential theft is possible." if acac == "true" else ".")),
                "Implement a strict CORS allowlist. Never combine wildcard '*' with credentials=true.",
                f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            ))
    except Exception:
        pass


def _check_https_redirect(parsed, findings: list, url: str):
    if parsed.scheme == "http":
        https_url = "https://" + url[7:]
        try:
            r = httpx.get(https_url, verify=False, timeout=5, follow_redirects=True)
            if r.status_code < 400:
                findings.append(_finding(
                    "Missing HTTPS Redirect", "medium", 0.85, url,
                    "recon-agent", "A02:2021-Cryptographic Failures",
                    "The application serves content over HTTP without redirecting to HTTPS. Traffic is unencrypted and can be intercepted.",
                    "Redirect all HTTP traffic to HTTPS with a 301 permanent redirect. Enable HSTS header.",
                ))
        except Exception:
            pass


_SENSITIVE_PATHS = [
    ("/.git/config",          "Git Repository Exposure",          "critical",
     "The .git/config file is publicly accessible — may expose repository URLs and credentials."),
    ("/.env",                 "Environment File Exposure",        "critical",
     "The .env file is publicly accessible — likely contains secret keys, DB passwords, and API tokens."),
    ("/.env.local",           "Environment File Exposure",        "critical",
     "Local environment file is publicly accessible."),
    ("/.env.production",      "Environment File Exposure",        "critical",
     "Production environment file is publicly accessible."),
    ("/phpinfo.php",          "PHP Info Disclosure",              "high",
     "phpinfo() exposes server configuration, loaded modules, PHP version, and environment variables."),
    ("/server-status",        "Apache Server Status Exposed",     "medium",
     "Apache mod_status page reveals active requests, server load, and worker status."),
    ("/phpmyadmin/",          "PHPMyAdmin Exposed",               "high",
     "Database management interface is publicly accessible and a common attack target."),
    ("/adminer.php",          "Adminer DB Tool Exposed",          "high",
     "Database administration tool (Adminer) is publicly accessible."),
    ("/wp-config.php.bak",   "WordPress Config Backup Exposed",  "critical",
     "WordPress configuration backup file may contain database credentials."),
    ("/backup.sql",           "Database Backup Exposed",          "critical",
     "Database backup file may be publicly downloadable."),
    ("/swagger-ui.html",      "Swagger UI Exposed",               "medium",
     "API documentation is publicly accessible, potentially revealing internal endpoint structure."),
    ("/api/swagger.json",     "Swagger API Spec Exposed",         "medium",
     "OpenAPI specification file is publicly accessible."),
    ("/graphql",              "GraphQL Endpoint Exposed",         "medium",
     "GraphQL endpoint is publicly reachable. Check if introspection is enabled."),
    ("/actuator",             "Spring Boot Actuator Exposed",     "high",
     "Spring Boot Actuator endpoints are publicly accessible, potentially leaking metrics and environment info."),
    ("/debug",                "Debug Endpoint Exposed",           "high",
     "Debug interface is publicly accessible."),
    ("/.htaccess",            "Apache htaccess Disclosure",       "medium",
     "Apache .htaccess file may be publicly readable, revealing URL rewrite rules."),
]


def _check_sensitive_paths(client: httpx.Client, base: str, findings: list):
    for path, vuln, sev, desc in _SENSITIVE_PATHS:
        try:
            r = client.head(f"{base}{path}", follow_redirects=False)
            if r.status_code in (200, 206):
                confidence = 0.93
            elif r.status_code == 403:
                confidence = 0.62   # exists but blocked
            else:
                continue
            findings.append(_finding(
                vuln, sev, confidence, f"{base}{path}",
                "recon-agent", "A05:2021-Security Misconfiguration",
                desc,
                f"Restrict or remove {path} from the web root. Block access via server config or firewall.",
                f"HTTP {r.status_code} {base}{path}",
            ))
        except Exception:
            pass


def _check_ssl(parsed, findings: list, url: str):
    if parsed.scheme != "https":
        return
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp      = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 30:
                        sev = "critical" if days_left < 7 else "high"
                        findings.append(_finding(
                            "SSL Certificate Expiring Soon", sev, 0.99, url,
                            "recon-agent", "A02:2021-Cryptographic Failures",
                            f"SSL certificate expires in {days_left} day(s) on {exp.strftime('%Y-%m-%d')}. Users will see browser security errors.",
                            "Renew the SSL certificate immediately. Consider Let's Encrypt with auto-renewal (certbot).",
                        ))
    except ssl.SSLCertVerificationError:
        findings.append(_finding(
            "Invalid or Self-Signed SSL Certificate", "high", 0.95, url,
            "recon-agent", "A02:2021-Cryptographic Failures",
            "SSL certificate is self-signed, expired, or has a hostname mismatch. Browsers will show security warnings.",
            "Obtain a valid certificate from a trusted CA. Use Let's Encrypt for free certificates.",
        ))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
#  CODE MODE
# ══════════════════════════════════════════════════════════════════

_SKIP_DIRS  = {"node_modules", "__pycache__", ".git", "venv", "env", ".venv", "dist", "build"}
_CONFIG_EXT = {".env", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf", ".toml", ".properties"}
_CONFIG_NAMES = {"settings.py", "config.py", "app.py", "main.py", "server.js",
                 "config.js", "settings.js", "web.config", "application.properties"}

_DEBUG_PATTERNS = [
    (r'\bDEBUG\s*=\s*True\b',                      "Python DEBUG=True"),
    (r'\bdebug\s*:\s*true\b',                        "Config debug:true"),
    (r'app\.run\([^)]*debug\s*=\s*True',             "Flask debug server"),
    (r'\bDEVELOPMENT\s*=\s*True\b',                 "Development mode flag"),
    (r'"debug"\s*:\s*true',                          "JSON debug:true"),
]

_CRED_PATTERNS = [
    (r'mongodb(?:\+srv)?://[^:"\s]+:[^@"\s]+@[\w.-]+', "Database Connection String with Credentials"),
    (r'postgres(?:ql)?://[^:"\s]+:[^@"\s]+@[\w.-]+',   "PostgreSQL Connection String with Credentials"),
    (r'mysql://[^:"\s]+:[^@"\s]+@[\w.-]+',              "MySQL Connection String with Credentials"),
    (r'redis://:([^@"\s]{6,})@[\w.-]+',                 "Redis Connection String with Password"),
    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\'](?!\s*#.*env)',
     "Hardcoded Password in Config"),
]


def _recon_code(project_path: str, _tech_stack: List[str]) -> List[dict]:
    findings: List[dict] = []
    if not os.path.isdir(project_path):
        return []

    for dirpath, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for filename in files:
            fpath    = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(fpath, project_path)
            _, ext   = os.path.splitext(filename)

            if filename in _CONFIG_NAMES or ext in _CONFIG_EXT:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(50_000)
                    _scan_debug_flags(content, rel_path, findings)
                    _scan_hardcoded_creds(content, rel_path, findings)
                except Exception:
                    pass

    return findings[:25]


def _scan_debug_flags(content: str, path: str, findings: list):
    for pattern, label in _DEBUG_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(_finding(
                f"Debug Mode Enabled ({label})", "high", 0.87, path,
                "recon-agent", "A05:2021-Security Misconfiguration",
                "Debug mode is enabled. In production this exposes stack traces, internal routes, "
                "and may allow arbitrary code execution via interactive debuggers.",
                "Set DEBUG=False (or equivalent) via environment variable. Never hardcode debug=True in production code.",
            ))
            return   # one per file


def _scan_hardcoded_creds(content: str, path: str, findings: list):
    for pattern, vuln in _CRED_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            snippet = match.group(0)
            # Redact password portion for the report
            redacted = re.sub(r'(://[^:]+:)[^@]+(@)', r'\1***\2', snippet)
            findings.append(_finding(
                vuln, "critical", 0.82, path,
                "recon-agent", "A07:2021-Identification and Authentication Failures",
                f"Hardcoded credential detected in {path}. If committed to version control, "
                "any person with repo access can extract the secret.",
                "Move all credentials to environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager). "
                "Rotate any exposed secrets immediately.",
                redacted,
            ))
            return   # one per file


# ── Shared helper ──────────────────────────────────────────────────

def _finding(vuln, sev, conf, location, tool, owasp, description, fix,
             code_snippet="") -> dict:
    return {
        "vulnerability": vuln,
        "severity":      sev,
        "confidence":    conf,
        "location":      location,
        "line":          None,
        "tool":          tool,
        "team":          "red",
        "owasp":         owasp,
        "description":   description,
        "fix":           fix,
        "code_snippet":  code_snippet,
    }
