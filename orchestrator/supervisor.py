"""
Main Supervisor Agent — LangGraph pipeline.

Workflow:
  detect_tech → scan (Red + Blue in parallel) → verify → finalize

Each node calls the appropriate containerised agent service via HTTP.
Results are stored in MongoDB. Progress events are published to Redis
so the backend can forward them to WebSocket clients.
"""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import TypedDict, List

import httpx
from langgraph.graph import StateGraph, END

from db.scans import update_scan
from db.findings import bulk_create_findings
from scheduler import progress, complete, error as pub_error
from memory.rag import index_findings

BLUE_TEAM_URL = os.getenv("BLUE_TEAM_URL", "http://blue-team:8002")
RED_TEAM_URL  = os.getenv("RED_TEAM_URL",  "http://red-team:8001")
VERIFIER_URL  = os.getenv("VERIFIER_URL",  "http://verifier:8003")

_TIMEOUT = httpx.Timeout(600.0, connect=10.0)   # scans can take a while

# ── State ─────────────────────────────────────────────────────────

class ScanState(TypedDict):
    scan_id: str
    project_path: str
    tech_stack: List[str]
    blue_findings: List[dict]
    red_findings: List[dict]
    verified_findings: List[dict]
    compliance: dict
    error: str


# ── Tech stack detection (runs locally inside orchestrator) ───────

def _detect_tech(path: str) -> List[str]:
    indicators = {
        "Python":     ["requirements.txt", "setup.py", "pyproject.toml"],
        "JavaScript": ["package.json"],
        "TypeScript": ["tsconfig.json"],
        "Java":       ["pom.xml", "build.gradle"],
        "Go":         ["go.mod"],
        "Ruby":       ["Gemfile"],
        "PHP":        ["composer.json"],
        "Rust":       ["Cargo.toml"],
        "Docker":     ["Dockerfile", "docker-compose.yml"],
    }
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust",
    }
    found_files: set = set()
    found_exts: set = set()
    limit = 3000

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in
                   ("node_modules", "__pycache__", ".git", "venv", "env", ".venv")]
        for f in files:
            found_files.add(f)
            found_exts.add(os.path.splitext(f)[1].lower())
            limit -= 1
            if limit <= 0:
                break
        if limit <= 0:
            break

    stack: set = set()
    for tech, markers in indicators.items():
        if any(m in found_files for m in markers):
            stack.add(tech)
    for ext, tech in ext_map.items():
        if ext in found_exts:
            stack.add(tech)
    return sorted(stack)


# ── Graph nodes ───────────────────────────────────────────────────

def node_detect(state: ScanState) -> ScanState:
    stack = _detect_tech(state["project_path"])
    update_scan(state["scan_id"], status="running", progress=8, tech_stack=stack)
    progress(state["scan_id"], 8, f"Tech stack: {', '.join(stack) or 'unknown'}")
    return {**state, "tech_stack": stack}


def node_scan(state: ScanState) -> ScanState:
    """Dispatch Blue Team and Red Team agents in parallel."""
    progress(state["scan_id"], 15, "Dispatching Red Team and Blue Team agents…")

    payload = {
        "scan_id":      state["scan_id"],
        "project_path": state["project_path"],
        "tech_stack":   state["tech_stack"],
    }

    def call_blue():
        try:
            r = httpx.post(f"{BLUE_TEAM_URL}/analyze", json=payload, timeout=_TIMEOUT)
            return r.json().get("findings", [])
        except Exception as exc:
            print(f"[supervisor] Blue Team error: {exc}")
            return []

    def call_red():
        try:
            r = httpx.post(f"{RED_TEAM_URL}/analyze", json=payload, timeout=_TIMEOUT)
            return r.json().get("findings", [])
        except Exception as exc:
            print(f"[supervisor] Red Team error: {exc}")
            return []

    with ThreadPoolExecutor(max_workers=2) as pool:
        blue_future = pool.submit(call_blue)
        red_future  = pool.submit(call_red)
        blue = blue_future.result()
        red  = red_future.result()

    total = len(blue) + len(red)
    update_scan(state["scan_id"], progress=60)
    progress(state["scan_id"], 60,
             f"Scan complete — {len(blue)} Blue Team + {len(red)} Red Team findings ({total} total)")

    return {**state, "blue_findings": blue, "red_findings": red}


def node_verify(state: ScanState) -> ScanState:
    """Send all raw findings to the Verifier (Verification + Reflection + Consensus)."""
    raw = state["blue_findings"] + state["red_findings"]
    progress(state["scan_id"], 65, f"Sending {len(raw)} findings to Verifier…")

    try:
        r = httpx.post(
            f"{VERIFIER_URL}/verify",
            json={"scan_id": state["scan_id"], "findings": raw, "tech_stack": state["tech_stack"]},
            timeout=_TIMEOUT,
        )
        body = r.json()
        verified   = body.get("verified_findings", raw)
        compliance = body.get("compliance", {})
    except Exception as exc:
        print(f"[supervisor] Verifier error: {exc}")
        verified, compliance = raw, {}

    update_scan(state["scan_id"], progress=85)
    progress(state["scan_id"], 85,
             f"Verification done — {len(verified)} confirmed findings, "
             f"compliance score {compliance.get('score', 'N/A')}%")

    return {**state, "verified_findings": verified, "compliance": compliance}


def node_finalize(state: ScanState) -> ScanState:
    """Persist findings, update scan record, index into RAG, emit completion."""
    findings = state["verified_findings"]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1

    bulk_create_findings(state["scan_id"], findings)

    try:
        index_findings(findings, state["scan_id"])
    except Exception as exc:
        print(f"[supervisor] RAG indexing error (non-fatal): {exc}")

    update_scan(
        state["scan_id"],
        status="completed",
        progress=100,
        findings_count=counts,
        compliance_results=state["compliance"],
        completed_at=datetime.utcnow(),
    )

    score = state["compliance"].get("score", 0)
    complete(state["scan_id"], counts, score)
    return {**state}


# ── Build LangGraph ───────────────────────────────────────────────

def _build_graph():
    g = StateGraph(ScanState)
    g.add_node("detect", node_detect)
    g.add_node("scan",   node_scan)
    g.add_node("verify", node_verify)
    g.add_node("finalize", node_finalize)

    g.set_entry_point("detect")
    g.add_edge("detect",   "scan")
    g.add_edge("scan",     "verify")
    g.add_edge("verify",   "finalize")
    g.add_edge("finalize", END)
    return g.compile()


_graph = _build_graph()


# ── Public entry point ────────────────────────────────────────────

def run_scan_pipeline(scan_id: str, project_path: str) -> None:
    initial: ScanState = {
        "scan_id":          scan_id,
        "project_path":     project_path,
        "tech_stack":       [],
        "blue_findings":    [],
        "red_findings":     [],
        "verified_findings": [],
        "compliance":       {},
        "error":            "",
    }
    try:
        _graph.invoke(initial)
    except Exception as exc:
        update_scan(scan_id, status="failed", error=str(exc))
        pub_error(scan_id, str(exc))
        raise
