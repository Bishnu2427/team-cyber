from typing import List
from tools.semgrep_tool import run_semgrep
from tools.bandit_tool import run_bandit


def run_sast(project_path: str, tech_stack: List[str]) -> List[dict]:
    findings: List[dict] = []
    findings.extend(run_semgrep(project_path))
    if "Python" in tech_stack:
        findings.extend(run_bandit(project_path))
    return findings
