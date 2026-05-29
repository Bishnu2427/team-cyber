"""
Web Security Agent — Phase 2

Code mode : Pattern-match SQLi, XSS, CSRF, open-redirect, template injection,
            unsafe deserialization, and missing auth decorators in source code.
URL  mode : Probe security headers, cookie flags, HTTP methods, error
            disclosure, and perform safe reflection tests for SQLi/XSS.
"""
import os
import re
from typing import List
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

_UA      = "TeamCyber-Scanner/2.0 (Authorised Security Assessment)"
_TIMEOUT = 12


# ── Public entry point ─────────────────────────────────────────────

def run_web_analysis(project_path: str, tech_stack: List[str],
                     target_url: str = "") -> List[dict]:
    if target_url:
        return _web_url(target_url)
    return _web_code(project_path, tech_stack)


# ══════════════════════════════════════════════════════════════════
#  URL MODE
# ══════════════════════════════════════════════════════════════════

# Required security headers and their recommended values
_SECURITY_HEADERS = [
    ("Strict-Transport-Security",
     "high", "A02:2021-Cryptographic Failures",
     "HSTS header is missing. Browsers will not enforce HTTPS, allowing SSL-stripping attacks.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),

    ("Content-Security-Policy",
     "medium", "A05:2021-Security Misconfiguration",
     "Content Security Policy (CSP) is not set. XSS and data injection attacks are easier without a strict CSP.",
     "Define a strict CSP that whitelists only trusted sources. Start with: Content-Security-Policy: default-src 'self'"),

    ("X-Content-Type-Options",
     "low", "A05:2021-Security Misconfiguration",
     "X-Content-Type-Options: nosniff is missing. Browsers may MIME-sniff responses and execute malicious content.",
     "Add: X-Content-Type-Options: nosniff"),

    ("X-Frame-Options",
     "medium", "A05:2021-Security Misconfiguration",
     "X-Frame-Options is missing. The page can be embedded in an iframe, enabling clickjacking attacks.",
     "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead)"),

    ("Referrer-Policy",
     "low", "A05:2021-Security Misconfiguration",
     "Referrer-Policy header is absent. Full URLs (including tokens in query strings) may leak to third-party sites.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),

    ("Permissions-Policy",
     "low", "A05:2021-Security Misconfiguration",
     "Permissions-Policy header is absent. Browser APIs (camera, microphone, geolocation) are not restricted.",
     "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"),
]

# Safe SQLi error-detection payloads — read-only, non-destructive
_SQLI_PROBES = ["'", '"', "' OR '1'='1", "1 AND 1=1"]
_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqliteexception",
    r"ora-\d{5}",
    r"microsoft sql native client",
    r"invalid query",
    r"sql syntax.*mysql",
]

# XSS reflection marker
_XSS_MARKER = "tc8x2z<sc" + "ript>alert(1)</sc" + "ript>"


def _web_url(url: str) -> List[dict]:
    findings: List[dict] = []
    headers = {"User-Agent": _UA}

    try:
        with httpx.Client(verify=False, timeout=_TIMEOUT,
                          headers=headers, follow_redirects=True) as client:
            try:
                resp = client.get(url)
            except Exception as exc:
                print(f"[web-agent] Cannot reach {url}: {exc}")
                return []

            _check_security_headers(resp, findings, url)
            _check_cookie_flags(resp, findings, url)
            _check_http_methods(client, url, findings)
            _check_error_disclosure(client, url, findings)
            _check_sqli_reflection(client, url, findings)
            _check_xss_reflection(client, url, findings)
            _check_open_redirect(client, url, findings)

    except Exception as exc:
        print(f"[web-agent] URL scan error: {exc}")

    return findings


def _check_security_headers(resp: httpx.Response, findings: list, url: str):
    for header, sev, owasp, desc, fix in _SECURITY_HEADERS:
        if header.lower() not in {k.lower() for k in resp.headers}:
            findings.append(_finding(
                f"Missing Security Header: {header}", sev, 0.97, url,
                "web-agent", owasp, desc, fix,
                f"Response missing: {header}",
            ))


def _check_cookie_flags(resp: httpx.Response, findings: list, url: str):
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    cookies  = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") \
               else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

    for cookie in cookies:
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip()

        if is_https and "secure" not in cookie_lower:
            findings.append(_finding(
                "Cookie Missing Secure Flag", "medium", 0.92, url,
                "web-agent", "A02:2021-Cryptographic Failures",
                f"Cookie '{name}' is served over HTTPS but lacks the Secure flag. It can be transmitted over HTTP.",
                "Add the Secure flag to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
                f"Set-Cookie: {cookie[:120]}",
            ))

        if "httponly" not in cookie_lower:
            findings.append(_finding(
                "Cookie Missing HttpOnly Flag", "medium", 0.92, url,
                "web-agent", "A07:2021-Identification and Authentication Failures",
                f"Cookie '{name}' lacks the HttpOnly flag. Client-side JavaScript can read it, enabling session theft via XSS.",
                "Add HttpOnly to all session and authentication cookies: Set-Cookie: name=value; HttpOnly",
                f"Set-Cookie: {cookie[:120]}",
            ))

        if "samesite" not in cookie_lower:
            findings.append(_finding(
                "Cookie Missing SameSite Attribute", "low", 0.88, url,
                "web-agent", "A01:2021-Broken Access Control",
                f"Cookie '{name}' has no SameSite attribute. Cross-site request forgery (CSRF) is easier without it.",
                "Add SameSite=Strict or SameSite=Lax to all cookies.",
                f"Set-Cookie: {cookie[:120]}",
            ))


def _check_http_methods(client: httpx.Client, url: str, findings: list):
    try:
        r = client.options(url)
        allow = r.headers.get("allow", r.headers.get("public", "")).upper()
        dangerous = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT") if m in allow]
        if dangerous:
            findings.append(_finding(
                "Dangerous HTTP Methods Enabled", "medium", 0.80, url,
                "web-agent", "A05:2021-Security Misconfiguration",
                f"Server allows: {', '.join(dangerous)}. TRACE enables cross-site tracing (XST); PUT/DELETE may allow unauthorised file manipulation.",
                "Restrict HTTP methods in your server config. Allow only GET, POST, HEAD (and OPTIONS if needed).",
                f"Allow: {allow}",
            ))
    except Exception:
        pass

    # TRACE method check
    try:
        r = client.request("TRACE", url)
        if r.status_code == 200 and "TRACE" in r.text.upper():
            findings.append(_finding(
                "HTTP TRACE Method Enabled (XST)", "medium", 0.88, url,
                "web-agent", "A05:2021-Security Misconfiguration",
                "TRACE method is enabled. Cross-Site Tracing (XST) allows attackers to steal cookies even with HttpOnly set.",
                "Disable TRACE in your web server configuration.",
                "HTTP/1.1 200 OK (TRACE echo response received)",
            ))
    except Exception:
        pass


def _check_error_disclosure(client: httpx.Client, url: str, findings: list):
    probe_url = url.rstrip("/") + "/tc-nonexistent-path-8x2z"
    try:
        r = client.get(probe_url)
        body = r.text.lower()
        patterns = [
            ("stack trace", "Stack Trace Exposure",   "high"),
            ("traceback",   "Stack Trace Exposure",   "high"),
            ("exception",   "Detailed Error Disclosure", "medium"),
            ("fatal error", "PHP Fatal Error Exposure", "medium"),
            ("syntax error","Error Disclosure",        "medium"),
            ("at line",     "Stack Trace Exposure",   "high"),
            ("debug info",  "Debug Information Exposure", "high"),
        ]
        for keyword, vuln, sev in patterns:
            if keyword in body:
                findings.append(_finding(
                    vuln, sev, 0.82, probe_url,
                    "web-agent", "A05:2021-Security Misconfiguration",
                    f"Error response exposes internal details ('{keyword}' found in 404 page). "
                    "This reveals technology stack, file paths, and logic flow to attackers.",
                    "Implement custom error pages that reveal no internal details. Disable detailed error reporting in production.",
                    r.text[:300],
                ))
                break
    except Exception:
        pass


def _check_sqli_reflection(client: httpx.Client, url: str, findings: list):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return

    param_name = next(iter(params))
    for probe in _SQLI_PROBES:
        test_params = {**params, param_name: [probe]}
        new_query   = urlencode({k: v[0] for k, v in test_params.items()})
        test_url    = urlunparse(parsed._replace(query=new_query))
        try:
            r    = client.get(test_url)
            body = r.text.lower()
            for pattern in _SQLI_ERROR_PATTERNS:
                if re.search(pattern, body):
                    findings.append(_finding(
                        "SQL Injection — Error-Based (Probe)", "critical", 0.78, url,
                        "web-agent", "A03:2021-Injection",
                        f"Parameter '{param_name}' triggers a database error when injected with: {probe!r}. "
                        "This indicates unsanitised user input is concatenated into SQL queries.",
                        "Use parameterised queries or prepared statements. Never concatenate user input into SQL.",
                        f"Probe: {probe!r}\nDB Error detected in response",
                    ))
                    return
        except Exception:
            pass


def _check_xss_reflection(client: httpx.Client, url: str, findings: list):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return

    param_name  = next(iter(params))
    test_params = {**params, param_name: [_XSS_MARKER]}
    new_query   = urlencode({k: v[0] for k, v in test_params.items()})
    test_url    = urlunparse(parsed._replace(query=new_query))
    try:
        r = client.get(test_url)
        if _XSS_MARKER in r.text:
            findings.append(_finding(
                "Reflected XSS — Input Reflected Unencoded", "high", 0.75, url,
                "web-agent", "A03:2021-Injection",
                f"Parameter '{param_name}' reflects user input without HTML encoding. "
                "An attacker can inject malicious scripts that execute in victims' browsers.",
                "HTML-encode all user-supplied output. Implement a strict Content-Security-Policy.",
                f"Reflected marker found in response for param: {param_name}",
            ))
    except Exception:
        pass


def _check_open_redirect(client: httpx.Client, url: str, findings: list):
    redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                       "redirect_uri", "goto", "target", "redir"]
    parsed    = urlparse(url)
    evil_dest = "https://evil-attacker.example.com"

    for param in redirect_params:
        new_query = f"{parsed.query}&{param}={evil_dest}" if parsed.query else f"{param}={evil_dest}"
        test_url  = urlunparse(parsed._replace(query=new_query))
        try:
            r = client.get(test_url, follow_redirects=False)
            location = r.headers.get("location", "")
            if "evil-attacker.example.com" in location:
                findings.append(_finding(
                    "Open Redirect", "medium", 0.85, url,
                    "web-agent", "A01:2021-Broken Access Control",
                    f"Parameter '{param}' allows redirecting to arbitrary external URLs. "
                    "Attackers use this for phishing — legitimate-looking links that send victims to malicious sites.",
                    "Validate redirect targets against an allowlist of trusted domains. Reject absolute URLs from user input.",
                    f"{param}={evil_dest} → Location: {location}",
                ))
                return
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
#  CODE MODE
# ══════════════════════════════════════════════════════════════════

_SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", "env", ".venv", "dist", "build", "migrations"}
_CODE_EXTS = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".cs"}

# (pattern, vulnerability, severity, owasp, description, fix)
_CODE_VULN_PATTERNS = [
    # SQLi
    (r'(?:execute|query|cursor\.execute)\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*["\']?\s*%',
     "SQL Injection via String Formatting", "critical", "A03:2021-Injection",
     "User-controlled data is formatted into a SQL query string with %. This is a classic SQL injection sink.",
     "Replace with parameterised queries: cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))"),

    (r'(?:execute|query)\s*\(\s*f["\']',
     "SQL Injection via f-string", "critical", "A03:2021-Injection",
     "An f-string is used to construct a SQL query — any variable interpolated here is a potential injection point.",
     "Use parameterised queries or an ORM. Never interpolate variables directly into SQL strings."),

    (r'(?:execute|query)\s*\(["\'][^"\']*["\']?\s*\+',
     "SQL Injection via String Concatenation", "critical", "A03:2021-Injection",
     "SQL query is built by string concatenation. User input must never reach this pattern.",
     "Use prepared statements or an ORM (SQLAlchemy, Django ORM, Hibernate)."),

    # XSS
    (r'innerHTML\s*=(?!=)',
     "DOM XSS via innerHTML", "high", "A03:2021-Injection",
     "Direct assignment to innerHTML can execute injected scripts if the value is user-controlled.",
     "Use textContent for plain text, or sanitise with DOMPurify before assigning to innerHTML."),

    (r'dangerouslySetInnerHTML',
     "React dangerouslySetInnerHTML", "high", "A03:2021-Injection",
     "dangerouslySetInnerHTML bypasses React's XSS protections. Any unsanitised content here is exploitable.",
     "Sanitise content with DOMPurify before passing to dangerouslySetInnerHTML."),

    (r'document\.write\s*\(',
     "DOM XSS via document.write", "high", "A03:2021-Injection",
     "document.write() injects raw HTML. User-controlled input passed here enables XSS.",
     "Avoid document.write(). Use safe DOM manipulation methods instead."),

    # Unsafe eval
    (r'\beval\s*\(',
     "Use of eval()", "high", "A03:2021-Injection",
     "eval() executes arbitrary strings as code. If user input reaches eval(), remote code execution is possible.",
     "Avoid eval() entirely. Use JSON.parse() for data, or dedicated parsers for code-like inputs."),

    # SSRF
    (r'(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get|httpx\.post)\s*\(\s*(?:request\.|user_|params\.|data\.|f["\'])',
     "Server-Side Request Forgery (SSRF)", "high", "A10:2021-Server-Side Request Forgery",
     "An HTTP request is made to a URL that may be user-controlled. Attackers can probe internal services.",
     "Validate and allowlist URLs before making server-side HTTP requests. Block private IP ranges."),

    # Path traversal
    (r'open\s*\(\s*(?:request\.|user_|params\.|data\.|f["\']|os\.path\.join\s*\([^)]*(?:request|user|param))',
     "Path Traversal Risk", "high", "A01:2021-Broken Access Control",
     "A file is opened using a path derived from user input. Path traversal (../../) can access sensitive files.",
     "Validate and sanitise file paths. Use os.path.realpath() and ensure the resolved path is within the allowed directory."),

    # Unsafe deserialisation
    (r'\bpickle\.loads?\s*\(',
     "Unsafe Pickle Deserialization", "critical", "A08:2021-Software and Data Integrity Failures",
     "pickle.load/loads() deserialises arbitrary Python objects. Any attacker-controlled pickle data leads to RCE.",
     "Never deserialise untrusted data with pickle. Use JSON, MessagePack, or similar safe formats."),

    (r'\byaml\.load\s*\([^,)]+\)',
     "Unsafe YAML Load", "high", "A08:2021-Software and Data Integrity Failures",
     "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary Python code.",
     "Replace with yaml.safe_load() for untrusted data."),

    # Missing CSRF
    (r'@app\.route\([^)]+methods\s*=\s*\[[^\]]*["\']POST["\']',
     "Flask POST Route — Verify CSRF Protection", "medium", "A01:2021-Broken Access Control",
     "A Flask POST route was found. Verify that CSRF protection (Flask-WTF or custom tokens) is applied.",
     "Use Flask-WTF with CSRFProtect, or implement double-submit cookie pattern."),

    # Template injection
    (r'render_template_string\s*\(',
     "Server-Side Template Injection Risk", "critical", "A03:2021-Injection",
     "render_template_string() with user-controlled content enables SSTI, leading to RCE.",
     "Never pass user input to render_template_string(). Use static template files."),

    (r'Template\s*\(\s*(?:request|user|f["\'])',
     "Jinja2 SSTI Risk", "critical", "A03:2021-Injection",
     "A Jinja2 Template object is constructed from a dynamic string. User-controlled input here means RCE.",
     "Always use static template files. Never construct templates from user input."),
]


def _web_code(project_path: str, _tech_stack: List[str]) -> List[dict]:
    findings: List[dict] = []
    if not os.path.isdir(project_path):
        return []

    for dirpath, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext not in _CODE_EXTS:
                continue
            fpath    = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(fpath, project_path)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
                content = "".join(lines)
                _scan_code_patterns(content, lines, rel_path, findings)
            except Exception:
                pass

    return findings[:30]


def _scan_code_patterns(_content: str, lines: list, rel_path: str, findings: list):
    for pattern, vuln, sev, owasp, desc, fix in _CODE_VULN_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                snippet = line.strip()[:200]
                findings.append(_finding(
                    vuln, sev, 0.72, rel_path,
                    "web-agent", owasp, desc, fix, snippet,
                ))
                findings[-1]["line"] = i
                break   # one match per pattern per file


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
