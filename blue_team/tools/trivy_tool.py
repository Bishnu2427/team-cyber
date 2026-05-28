import json
import os
import subprocess
from typing import List


def run_trivy(project_path: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", "--quiet", project_path],
            capture_output=True, text=True, timeout=300,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        findings = []
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:
                fixed = v.get("FixedVersion", "")
                findings.append({
                    "vulnerability": v.get("VulnerabilityID", "Unknown CVE"),
                    "severity":      v.get("Severity", "MEDIUM").lower(),
                    "confidence":    0.95,
                    "location":      res.get("Target", ""),
                    "line":          0,
                    "tool":          "trivy",
                    "category":      "dependency",
                    "cve":           v.get("VulnerabilityID", ""),
                    "owasp":         "A06:2021-Vulnerable and Outdated Components",
                    "root_cause":    (
                        f"{v.get('PkgName','')} {v.get('InstalledVersion','')} — "
                        f"{v.get('Title','')}: {v.get('Description','')[:200]}"
                    ),
                    "fix":           f"Upgrade to {fixed}" if fixed else "No fix available yet",
                })
        return findings
    except Exception as exc:
        print(f"[trivy] {exc}")
        return []


def run_pip_audit(project_path: str) -> List[dict]:
    req = os.path.join(project_path, "requirements.txt")
    if not os.path.exists(req):
        return []
    try:
        result = subprocess.run(
            ["pip-audit", "-r", req, "-f", "json"],
            capture_output=True, text=True, timeout=300,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        findings = []
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                findings.append({
                    "vulnerability": v.get("id", "Unknown"),
                    "severity":      "high",
                    "confidence":    0.95,
                    "location":      "requirements.txt",
                    "line":          0,
                    "tool":          "pip-audit",
                    "category":      "dependency",
                    "cve":           v.get("id", ""),
                    "owasp":         "A06:2021-Vulnerable and Outdated Components",
                    "root_cause":    f"{dep.get('name','')} {dep.get('version','')} — {v.get('description','')}",
                    "fix":           f"Upgrade {dep.get('name','')} to a patched version",
                })
        return findings
    except Exception as exc:
        print(f"[pip-audit] {exc}")
        return []
