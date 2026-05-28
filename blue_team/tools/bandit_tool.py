import json
import subprocess
from typing import List


def run_bandit(project_path: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["bandit", "-r", project_path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=300,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        return [
            {
                "vulnerability": r.get("test_name", "").replace("_", " ").title(),
                "severity":      r.get("issue_severity", "MEDIUM").lower(),
                "confidence":    _conf(r.get("issue_confidence", "MEDIUM")),
                "location":      r.get("filename", ""),
                "line":          r.get("line_number", 0),
                "code_snippet":  r.get("code", ""),
                "tool":          "bandit",
                "category":      r.get("test_id", ""),
                "owasp":         _bandit_owasp(r.get("test_id", "")),
                "root_cause":    r.get("issue_text", ""),
            }
            for r in data.get("results", [])
        ]
    except Exception as exc:
        print(f"[bandit] {exc}")
        return []


def _conf(c: str) -> float:
    return {"HIGH": 0.90, "MEDIUM": 0.70, "LOW": 0.50}.get(c.upper(), 0.70)


def _bandit_owasp(test_id: str) -> str:
    t = test_id.upper()
    if t.startswith("B1"):  return "A03:2021-Injection"
    if t.startswith("B2"):  return "A02:2021-Cryptographic Failures"
    if t.startswith("B3"):  return "A08:2021-Software and Data Integrity Failures"
    if t.startswith("B5"):  return "A02:2021-Cryptographic Failures"
    if t.startswith("B6"):  return "A03:2021-Injection"
    return ""
