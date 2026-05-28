"""
Blue Team Supervisor — coordinates all defensive security agents.

Pipeline (parallel where possible):
  [SAST Agent + Dependency Agent] → Fix Agent → Compliance Agent
"""
from concurrent.futures import ThreadPoolExecutor
from typing import List

from agents.sast_agent import run_sast
from agents.dependency_agent import run_dependency_scan
from agents.fix_agent import run_fix_recommendations
from agents.compliance_agent import run_compliance_check


def run_blue_team(scan_id: str, project_path: str, tech_stack: List[str]) -> dict:
    print(f"[blue-team] Starting analysis for scan {scan_id}")

    # Stage 1: SAST + Dependency in parallel
    with ThreadPoolExecutor(max_workers=2) as pool:
        sast_future = pool.submit(run_sast, project_path, tech_stack)
        dep_future  = pool.submit(run_dependency_scan, project_path, tech_stack)
        sast_findings = sast_future.result()
        dep_findings  = dep_future.result()

    raw = sast_findings + dep_findings
    print(f"[blue-team] Raw findings: {len(sast_findings)} SAST + {len(dep_findings)} dep = {len(raw)}")

    # Stage 2: AI enrichment (root cause + fix recommendations)
    enriched = run_fix_recommendations(raw, tech_stack)

    # Stage 3: OWASP compliance mapping
    compliance = run_compliance_check(enriched)

    print(f"[blue-team] Done — {len(enriched)} findings, compliance {compliance['score']}%")
    return {"findings": enriched, "compliance": compliance}
