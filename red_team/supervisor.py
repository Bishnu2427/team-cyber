"""
Red Team Supervisor — Phase 2

Pipeline (parallel where possible):
  [Recon Agent + Web Agent + API Agent] → Exploit Validation
"""
from concurrent.futures import ThreadPoolExecutor
from typing import List

from agents.recon_agent   import run_recon
from agents.web_agent     import run_web_analysis
from agents.api_agent     import run_api_analysis
from agents.exploit_agent import run_exploit_validation


def run_red_team(scan_id: str, project_path: str, tech_stack: List[str],
                 target_url: str = "", scan_type: str = "code") -> dict:
    print(f"[red-team] Scan {scan_id} — Phase 2 ({scan_type} mode)")

    def _recon():
        try:
            return run_recon(project_path, tech_stack, target_url=target_url)
        except Exception as exc:
            print(f"[red-team] Recon error: {exc}")
            return []

    def _web():
        try:
            return run_web_analysis(project_path, tech_stack, target_url=target_url)
        except Exception as exc:
            print(f"[red-team] Web agent error: {exc}")
            return []

    def _api():
        try:
            return run_api_analysis(project_path, tech_stack, target_url=target_url)
        except Exception as exc:
            print(f"[red-team] API agent error: {exc}")
            return []

    # Run the three domain agents in parallel
    with ThreadPoolExecutor(max_workers=3) as pool:
        recon_f = pool.submit(_recon)
        web_f   = pool.submit(_web)
        api_f   = pool.submit(_api)

        recon_findings = recon_f.result()
        web_findings   = web_f.result()
        api_findings   = api_f.result()

    raw = recon_findings + web_findings + api_findings
    print(f"[red-team] Raw — {len(recon_findings)} recon + "
          f"{len(web_findings)} web + {len(api_findings)} API = {len(raw)} total")

    # Exploit validation as a post-processing step
    validated = run_exploit_validation(
        project_path, tech_stack,
        findings=[f for f in raw if f.get("severity") == "critical"],
    )

    # Merge: keep validated criticals + all non-critical findings
    final = validated + [f for f in raw if f.get("severity") != "critical"]

    print(f"[red-team] Done — {len(final)} findings")
    return {"findings": final}
