from typing import List
from tools.trivy_tool import run_trivy, run_pip_audit


def run_dependency_scan(project_path: str, tech_stack: List[str]) -> List[dict]:
    findings: List[dict] = []
    findings.extend(run_trivy(project_path))
    if "Python" in tech_stack:
        findings.extend(run_pip_audit(project_path))
    return findings
