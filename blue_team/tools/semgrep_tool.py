import json
import re
import subprocess
from typing import List


def run_semgrep(project_path: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", project_path],
            capture_output=True, text=True, timeout=300,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        return [_parse_result(r) for r in data.get("results", [])]
    except Exception as exc:
        print(f"[semgrep] {exc}")
        return []


def _parse_result(r: dict) -> dict:
    extra    = r.get("extra", {})
    meta     = extra.get("metadata", {})
    check_id = r.get("check_id", "")

    # ── Vulnerability name ─────────────────────────────────────────
    # Prefer the human-readable message from the rule; fall back to
    # cleaning the check_id. Both hyphens AND underscores are replaced.
    raw_name   = extra.get("message", "").strip()
    if not raw_name:
        raw_name = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title()
    # Truncate very long messages to a concise title
    vuln_name = raw_name.split(".")[0].split("\n")[0][:120].strip()

    # ── OWASP ──────────────────────────────────────────────────────
    owasp = _extract_owasp(meta, check_id)

    # ── CWE ───────────────────────────────────────────────────────
    cwe = _extract_cwe(meta)

    return {
        "vulnerability": vuln_name,
        "severity":      _sev(extra.get("severity", "WARNING")),
        "confidence":    _conf(meta.get("confidence", "MEDIUM")),
        "location":      r.get("path", ""),
        "line":          r.get("start", {}).get("line", 0),
        "code_snippet":  extra.get("lines", "")[:400],
        "tool":          "semgrep",
        "team":          "blue",
        "category":      check_id,
        "owasp":         owasp,
        "cwe":           cwe,
    }


# ── OWASP extraction ────────────────────────────────────────────────
# Priority: rule metadata → keyword fallback (much tighter keywords)

_OWASP_NORMALISE = re.compile(r"A0?(\d+):?\d*\s*[-–]?\s*", re.IGNORECASE)

def _extract_owasp(meta: dict, check_id: str) -> str:
    # 1. Rule metadata may contain owasp as list or string
    raw = meta.get("owasp", meta.get("OWASP", ""))
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if raw:
        # Normalise to "AXX:2021-Name" format
        m = re.search(r"A0?(\d+)", str(raw), re.IGNORECASE)
        if m:
            idx = m.group(1).zfill(2)
            _OWASP_MAP = {
                "01":"A01:2021-Broken Access Control",
                "02":"A02:2021-Cryptographic Failures",
                "03":"A03:2021-Injection",
                "04":"A04:2021-Insecure Design",
                "05":"A05:2021-Security Misconfiguration",
                "06":"A06:2021-Vulnerable and Outdated Components",
                "07":"A07:2021-Identification and Authentication Failures",
                "08":"A08:2021-Software and Data Integrity Failures",
                "09":"A09:2021-Security Logging and Monitoring Failures",
                "10":"A10:2021-Server-Side Request Forgery",
            }
            if idx in _OWASP_MAP:
                return _OWASP_MAP[idx]

    # 2. Keyword fallback on check_id — STRICT, no false "audit" matches
    return _owasp_from_id(check_id)


def _owasp_from_id(check_id: str) -> str:
    cid = check_id.lower()

    # A03 Injection — explicit attack keywords only
    if any(k in cid for k in ("sql", "injection", "sqli", "xss",
                               "command-inject", "ldap-inject", "xpath",
                               "code-inject", "template-inject", "ssti",
                               "xxe", "exec", "eval", "os-command",
                               "innerHTML", "innerhtml", "document.write")):
        return "A03:2021-Injection"

    # A02 Cryptographic Failures
    if any(k in cid for k in ("hardcoded-secret", "hardcoded-password",
                               "weak-crypto", "weak-cipher", "md5", "sha1",
                               "insecure-random", "cleartext", "plaintext",
                               "insecure-hash", "weak-ssl", "weak-tls")):
        return "A02:2021-Cryptographic Failures"

    # A07 Auth failures
    if any(k in cid for k in ("broken-auth", "jwt-none", "jwt-weak",
                               "insecure-jwt", "weak-password",
                               "default-password", "improper-auth")):
        return "A07:2021-Identification and Authentication Failures"

    # A08 Deserialization
    if any(k in cid for k in ("deserializ", "pickle", "yaml-load",
                               "unsafe-deserial", "java-deserial",
                               "object-inject")):
        return "A08:2021-Software and Data Integrity Failures"

    # A10 SSRF
    if any(k in cid for k in ("ssrf", "server-side-request")):
        return "A10:2021-Server-Side Request Forgery"

    # A01 Access Control
    if any(k in cid for k in ("path-traversal", "directory-traversal",
                               "open-redirect", "broken-access",
                               "idor", "missing-auth", "cors")):
        return "A01:2021-Broken Access Control"

    # A05 Misconfiguration — bind/host/debug/config issues
    if any(k in cid for k in ("bind-all", "all-interfaces", "debug-mode",
                               "bad-host", "insecure-config", "misconfigur",
                               "default-cred", "stack-trace", "verbose-error")):
        return "A05:2021-Security Misconfiguration"

    # A09 Security Logging — ONLY true logging/monitoring keywords
    # (never match "audit" alone — that word appears in Semgrep rule paths)
    if any(k in cid for k in ("missing-log", "no-log", "disable-log",
                               "insufficient-log", "missing-audit-log")):
        return "A09:2021-Security Logging and Monitoring Failures"

    return ""


# ── CWE extraction ──────────────────────────────────────────────────

def _extract_cwe(meta: dict) -> str:
    raw = meta.get("cwe", meta.get("CWE", ""))
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if raw:
        # Normalise to "CWE-XXX" format
        m = re.search(r"CWE-(\d+)", str(raw), re.IGNORECASE)
        if m:
            return f"CWE-{m.group(1)}"
    return ""


# ── Helpers ─────────────────────────────────────────────────────────

def _sev(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(s.upper(), "medium")


def _conf(c) -> float:
    if isinstance(c, (int, float)):
        return float(c)
    return {"HIGH": 0.88, "MEDIUM": 0.72, "LOW": 0.55}.get(str(c).upper(), 0.72)
