import json
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
        return [
            {
                "vulnerability": r.get("check_id", "").split(".")[-1].replace("-", " ").title(),
                "severity":      _sev(r.get("extra", {}).get("severity", "WARNING")),
                "confidence":    0.80,
                "location":      r.get("path", ""),
                "line":          r.get("start", {}).get("line", 0),
                "code_snippet":  r.get("extra", {}).get("lines", ""),
                "tool":          "semgrep",
                "category":      r.get("check_id", ""),
                "owasp":         _owasp_from_id(r.get("check_id", "")),
            }
            for r in data.get("results", [])
        ]
    except Exception as exc:
        print(f"[semgrep] {exc}")
        return []


def _sev(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(s.upper(), "medium")


def _owasp_from_id(check_id: str) -> str:
    cid = check_id.lower()
    if any(k in cid for k in ("injection", "sqli", "xss", "ssrf", "xxe", "exec")):
        return "A03:2021-Injection"
    if any(k in cid for k in ("secret", "hardcoded", "password", "crypto", "weak")):
        return "A02:2021-Cryptographic Failures"
    if any(k in cid for k in ("auth", "session", "jwt", "token")):
        return "A07:2021-Identification and Authentication Failures"
    if any(k in cid for k in ("deseri", "pickle", "yaml.load")):
        return "A08:2021-Software and Data Integrity Failures"
    if any(k in cid for k in ("log", "audit")):
        return "A09:2021-Security Logging and Monitoring Failures"
    return ""
