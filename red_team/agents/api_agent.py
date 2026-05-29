"""
API Security Agent — Phase 2

Code mode : Detect JWT misconfigurations, missing auth decorators, BOLA
            patterns, missing rate limiting, and insecure API design in source.
URL  mode : Discover API endpoints, check for exposed docs, test for
            authentication bypass, and analyse JWT/session handling.
"""
import os
import re
import base64
import json
from typing import List
from urllib.parse import urlparse

import httpx

_UA      = "TeamCyber-Scanner/2.0 (Authorised Security Assessment)"
_TIMEOUT = 12


# ── Public entry point ─────────────────────────────────────────────

def run_api_analysis(project_path: str, tech_stack: List[str],
                     target_url: str = "") -> List[dict]:
    if target_url:
        return _api_url(target_url)
    return _api_code(project_path, tech_stack)


# ══════════════════════════════════════════════════════════════════
#  URL MODE
# ══════════════════════════════════════════════════════════════════

_API_DOC_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/api/docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/altair",
    "/playground",
    "/api/schema",
]

_API_ENDPOINT_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/v1", "/v2",
    "/json", "/data",
]


def _api_url(url: str) -> List[dict]:
    findings: List[dict] = []
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    headers = {"User-Agent": _UA, "Accept": "application/json, text/html, */*"}

    try:
        with httpx.Client(verify=False, timeout=_TIMEOUT,
                          headers=headers, follow_redirects=True) as client:

            _discover_api_docs(client, base, findings)
            _check_graphql_introspection(client, base, findings)
            _check_api_auth(client, base, url, findings)
            _check_jwt_in_response(client, url, findings)

    except Exception as exc:
        print(f"[api-agent] URL scan error: {exc}")

    return findings


def _discover_api_docs(client: httpx.Client, base: str, findings: list):
    for path in _API_DOC_PATHS:
        target = base + path
        try:
            r = client.get(target)
            if r.status_code == 200:
                content_type = r.headers.get("content-type", "").lower()
                is_api_doc   = (
                    "swagger" in r.text.lower() or
                    "openapi" in r.text.lower() or
                    "paths" in r.text.lower() and "components" in r.text.lower() or
                    path in ("/graphql", "/graphiql", "/altair", "/playground")
                )
                if is_api_doc or "json" in content_type:
                    sev = "high" if path in ("/graphql", "/graphiql") else "medium"
                    findings.append(_finding(
                        "API Documentation Publicly Exposed", sev, 0.93, target,
                        "api-agent", "A05:2021-Security Misconfiguration",
                        f"API documentation or schema is publicly accessible at {path}. "
                        "This reveals all endpoint names, parameters, authentication methods, and data models to attackers.",
                        "Restrict API documentation to internal networks or authenticated users only. "
                        "Require authentication (BasicAuth/JWT) to access Swagger/OpenAPI docs in production.",
                        f"HTTP 200 {target}",
                    ))
        except Exception:
            pass


def _check_graphql_introspection(client: httpx.Client, base: str, findings: list):
    graphql_url = base + "/graphql"
    introspection_query = json.dumps({
        "query": "{ __schema { types { name } } }"
    })
    try:
        r = client.post(graphql_url,
                        content=introspection_query,
                        headers={"Content-Type": "application/json"})
        body = r.json() if r.status_code == 200 else {}
        if "data" in body and "__schema" in str(body.get("data", {})):
            findings.append(_finding(
                "GraphQL Introspection Enabled", "medium", 0.92, graphql_url,
                "api-agent", "A05:2021-Security Misconfiguration",
                "GraphQL introspection is enabled in production. Attackers can enumerate the entire schema "
                "(all types, queries, mutations, fields) without authentication.",
                "Disable introspection in production: graphql.validation.disable_introspection. "
                "Allow only in development environments.",
                '{"query":"{ __schema { types { name } } }"} → schema returned',
            ))
    except Exception:
        pass


def _check_api_auth(client: httpx.Client, base: str, url: str, findings: list):
    for path in _API_ENDPOINT_PATHS:
        target = base + path
        try:
            r = client.get(target)
            if r.status_code == 200:
                body = r.text.lower()
                if any(k in body for k in ('"id"', '"user"', '"email"', '"token"',
                                           '"data":', '[{', '"results"')):
                    findings.append(_finding(
                        "Unauthenticated API Endpoint", "high", 0.72, target,
                        "api-agent", "A01:2021-Broken Access Control",
                        f"API endpoint at {path} returns data without requiring authentication. "
                        "Sensitive data may be accessible to unauthenticated users.",
                        "Implement authentication middleware on all API routes. "
                        "Return 401 for unauthenticated requests.",
                        f"HTTP 200 {target} (no auth header sent)",
                    ))
        except Exception:
            pass


def _check_jwt_in_response(client: httpx.Client, url: str, findings: list):
    """Check if JWT tokens appear in URL params or are insecurely configured."""
    parsed = urlparse(url)

    # JWT in URL is a security issue
    if re.search(r'[?&](?:token|jwt|access_token|auth)=[A-Za-z0-9_-]{20,}', url):
        findings.append(_finding(
            "JWT Token in URL Parameter", "high", 0.90, url,
            "api-agent", "A07:2021-Identification and Authentication Failures",
            "A JWT or authentication token is being passed as a URL parameter. "
            "Tokens in URLs are logged by servers, proxies, and browser history — this leaks credentials.",
            "Transmit tokens in the Authorization header (Bearer scheme) or a Secure+HttpOnly cookie. Never in the URL.",
            f"URL contains token parameter: {parsed.query[:100]}",
        ))

    # Try to probe a common auth endpoint
    base  = f"{parsed.scheme}://{parsed.netloc}"
    paths = ["/api/login", "/auth/login", "/login", "/api/auth", "/api/token"]
    for path in paths:
        target = base + path
        try:
            r = client.post(target,
                            json={"username": "test", "password": "test"},
                            headers={"Content-Type": "application/json"})
            if r.status_code in (200, 201):
                try:
                    body  = r.json()
                    token = (body.get("token") or body.get("access_token") or
                             body.get("jwt") or "")
                    if token and _is_jwt(token):
                        _analyse_jwt_payload(token, target, findings)
                except Exception:
                    pass
        except Exception:
            pass


def _is_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def _analyse_jwt_payload(token: str, url: str, findings: list):
    try:
        # Decode header and payload (no signature verification)
        header_b64  = token.split(".")[0]
        payload_b64 = token.split(".")[1]

        def _pad(s):
            return s + "=" * (-len(s) % 4)

        header  = json.loads(base64.urlsafe_b64decode(_pad(header_b64)))
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)))

        # None algorithm
        alg = header.get("alg", "").lower()
        if alg in ("none", ""):
            findings.append(_finding(
                "JWT Algorithm 'none' Accepted", "critical", 0.97, url,
                "api-agent", "A07:2021-Identification and Authentication Failures",
                "The JWT uses algorithm 'none', meaning the signature is not verified. "
                "An attacker can forge arbitrary tokens without knowing the secret key.",
                "Explicitly reject 'none' as a valid algorithm. Only accept RS256 or HS256 with a strong secret.",
                f"alg: {header.get('alg')}",
            ))

        # Weak algorithm
        if alg in ("hs256",) and len(token.split(".")[2]) < 32:
            findings.append(_finding(
                "JWT with Potentially Weak Signature", "high", 0.68, url,
                "api-agent", "A07:2021-Identification and Authentication Failures",
                "The JWT uses HS256 which is only as strong as the secret key. "
                "Short or common secrets are brute-forceable.",
                "Use a cryptographically random secret key of at least 256 bits. "
                "Consider RS256 (asymmetric) for better key management.",
            ))

        # No expiration
        if "exp" not in payload:
            findings.append(_finding(
                "JWT Without Expiration (exp) Claim", "high", 0.88, url,
                "api-agent", "A07:2021-Identification and Authentication Failures",
                "The JWT token has no expiration claim. Once issued, it is valid indefinitely. "
                "Stolen tokens cannot be invalidated.",
                "Always include the 'exp' claim. Set short lifetimes (15-60 min) and use refresh tokens.",
                f"JWT payload has no 'exp': {list(payload.keys())}",
            ))

        # Sensitive data in payload
        sensitive_keys = {"password", "secret", "credit_card", "ssn", "cvv", "pin"}
        found_keys = sensitive_keys & set(str(k).lower() for k in payload.keys())
        if found_keys:
            findings.append(_finding(
                "Sensitive Data in JWT Payload", "high", 0.82, url,
                "api-agent", "A02:2021-Cryptographic Failures",
                f"JWT payload contains potentially sensitive fields: {found_keys}. "
                "JWT payloads are base64-encoded — not encrypted — and can be read by anyone.",
                "Remove sensitive data from JWT claims. JWT payloads are not secret. "
                "Use opaque tokens if confidentiality is required.",
                f"Sensitive keys in payload: {found_keys}",
            ))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
#  CODE MODE
# ══════════════════════════════════════════════════════════════════

_SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", "env", ".venv", "dist", "build"}
_CODE_EXTS = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"}

_API_PATTERNS = [
    # JWT none algorithm
    (r'(?:algorithm|algorithms)\s*[=:]\s*["\']none["\']',
     "JWT Algorithm 'none' in Code", "critical",
     "A07:2021-Identification and Authentication Failures",
     "JWT algorithm is hardcoded as 'none', disabling signature verification entirely.",
     "Remove 'none' from allowed algorithms. Use HS256 or RS256 exclusively."),

    # JWT no expiration
    (r'jwt\.encode\([^)]+\)(?!.*\bexp\b)',
     "JWT Encoded Without Expiration", "high",
     "A07:2021-Identification and Authentication Failures",
     "jwt.encode() call detected without 'exp' claim in the payload. Tokens will never expire.",
     "Always include 'exp' in the JWT payload: payload['exp'] = datetime.utcnow() + timedelta(hours=1)"),

    # Hardcoded JWT secret
    (r'(?:jwt\.encode|jwt\.decode)\([^)]+,\s*["\'][^"\']{3,30}["\']',
     "Hardcoded JWT Secret Key", "critical",
     "A07:2021-Identification and Authentication Failures",
     "The JWT secret key is hardcoded in source code. Anyone with code access can forge tokens.",
     "Load the JWT secret from an environment variable: os.getenv('JWT_SECRET_KEY')"),

    # Missing auth decorator (Flask)
    (r'@app\.route\([^)]+\)\s*\n(?!.*@(?:jwt_required|login_required|auth_required|requires_auth))',
     "Flask Route Without Auth Decorator", "medium",
     "A01:2021-Broken Access Control",
     "A Flask route is defined without an authentication decorator immediately following. "
     "Verify this endpoint is intentionally public.",
     "Add @jwt_required() or @login_required before sensitive route handlers."),

    # BOLA pattern — user ID from request used directly
    (r'(?:user_id|userId|account_id)\s*=\s*request\.',
     "Potential BOLA (Broken Object Level Authorisation)", "high",
     "A01:2021-Broken Access Control",
     "A user identifier is taken directly from the request and used to look up data. "
     "Without verifying the requester owns that ID, this is an Insecure Direct Object Reference (IDOR/BOLA).",
     "Always verify that the authenticated user is authorised to access the requested resource. "
     "Compare request ID against the JWT's own subject claim."),

    # No rate limiting
    (r'@app\.route\([^)]*(?:login|register|reset|password)[^)]*\)',
     "Auth Endpoint Without Explicit Rate Limiting", "medium",
     "A07:2021-Identification and Authentication Failures",
     "Authentication endpoint found without visible rate limiting. Brute-force attacks are possible.",
     "Apply rate limiting to all auth endpoints: @limiter.limit('10/minute') with Flask-Limiter."),

    # Mass assignment
    (r'(?:User|Model)\s*\(\s*\*\*request\.(?:json|form|get_json)',
     "Mass Assignment Vulnerability", "high",
     "A03:2021-Injection",
     "A model is instantiated directly with all request fields (**request.json). "
     "Attackers can set admin=True or other privileged fields.",
     "Use an explicit allowlist of accepted fields. Never pass raw request data directly to model constructors."),
]


def _api_code(project_path: str, _tech_stack: List[str]) -> List[dict]:
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
                _scan_api_patterns(lines, rel_path, findings)
            except Exception:
                pass

    return findings[:25]


def _scan_api_patterns(lines: list, rel_path: str, findings: list):
    content = "".join(lines)
    for pattern, vuln, sev, owasp, desc, fix in _API_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        if match:
            # Find line number
            line_no = content[:match.start()].count("\n") + 1
            findings.append(_finding(
                vuln, sev, 0.74, rel_path,
                "api-agent", owasp, desc, fix,
                lines[line_no - 1].strip()[:200] if line_no <= len(lines) else "",
            ))
            findings[-1]["line"] = line_no


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
