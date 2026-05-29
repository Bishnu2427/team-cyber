"""
Main Supervisor Agent — LangGraph pipeline.

Workflow (code scans):
  detect_tech → scan (Red + Blue in parallel) → verify → finalize

Workflow (URL scans):
  detect_url → scan_url (Red Team only) → verify → finalize

Each node calls the appropriate containerised agent service via HTTP.
Results are stored in MongoDB. Progress events are published to Redis.
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

_TIMEOUT = httpx.Timeout(600.0, connect=10.0)


# ── State ──────────────────────────────────────────────────────────

class ScanState(TypedDict):
    scan_id:           str
    scan_type:         str        # "code" | "url"
    project_path:      str
    target_url:        str
    tech_stack:        List[str]
    blue_findings:     List[dict]
    red_findings:      List[dict]
    verified_findings: List[dict]
    compliance:        dict
    error:             str


# ── Tech stack detection ───────────────────────────────────────────

def _detect_tech_from_files(path: str) -> List[str]:
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
    found_exts:  set = set()
    limit = 3000

    for _, dirs, files in os.walk(path):
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


def _detect_tech_from_url(url: str) -> List[str]:
    """Best-effort tech detection via HTTP headers for URL scans."""
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True,
                      headers={"User-Agent": "TeamCyber-Scanner/2.0"}, verify=False)
        stack: set = set()
        server = r.headers.get("server", "").lower()
        powered = r.headers.get("x-powered-by", "").lower()
        body = r.text[:10000].lower()

        if "php" in powered or "php" in server or "<?php" in body:   stack.add("PHP")
        if "node" in powered or "express" in powered:                 stack.add("Node.js")
        if "django" in body or "csrfmiddlewaretoken" in body:         stack.add("Django/Python")
        if "laravel" in body or "laravel_session" in str(r.cookies):  stack.add("Laravel/PHP")
        if "wp-content" in body or "wordpress" in body:               stack.add("WordPress")
        if "react" in body or "_next" in body:                        stack.add("React/Next.js")
        if "nginx" in server:                                          stack.add("Nginx")
        if "apache" in server:                                         stack.add("Apache")
        stack.add("Web Application")
        return sorted(stack)
    except Exception:
        return ["Web Application"]


# ── Graph nodes ────────────────────────────────────────────────────

def node_detect(state: ScanState) -> ScanState:
    if state["scan_type"] == "url":
        stack = _detect_tech_from_url(state["target_url"])
        progress(state["scan_id"], 8, f"Target fingerprinted: {', '.join(stack)}")
    else:
        stack = _detect_tech_from_files(state["project_path"])
        progress(state["scan_id"], 8, f"Tech stack: {', '.join(stack) or 'unknown'}")

    update_scan(state["scan_id"], status="running", progress=8, tech_stack=stack)
    return {**state, "tech_stack": stack}


def node_scan(state: ScanState) -> ScanState:
    """Dispatch agents in parallel. URL scans skip Blue Team (no source code)."""
    scan_type = state["scan_type"]

    payload = {
        "scan_id":      state["scan_id"],
        "project_path": state["project_path"],
        "target_url":   state["target_url"],
        "tech_stack":   state["tech_stack"],
        "scan_type":    scan_type,
    }

    def call_blue():
        if scan_type == "url":
            return []   # Blue Team requires source code
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

    if scan_type == "url":
        progress(state["scan_id"], 15, "Dispatching Red Team agents against target…")
    else:
        progress(state["scan_id"], 15, "Dispatching Red Team and Blue Team agents…")

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
    raw = state["blue_findings"] + state["red_findings"]
    progress(state["scan_id"], 65, f"Sending {len(raw)} findings to Verifier…")

    try:
        r = httpx.post(
            f"{VERIFIER_URL}/verify",
            json={"scan_id": state["scan_id"], "findings": raw, "tech_stack": state["tech_stack"]},
            timeout=_TIMEOUT,
        )
        body       = r.json()
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


# ── Build graph ────────────────────────────────────────────────────

def _build_graph():
    g = StateGraph(ScanState)
    g.add_node("detect",   node_detect)
    g.add_node("scan",     node_scan)
    g.add_node("verify",   node_verify)
    g.add_node("finalize", node_finalize)

    g.set_entry_point("detect")
    g.add_edge("detect",   "scan")
    g.add_edge("scan",     "verify")
    g.add_edge("verify",   "finalize")
    g.add_edge("finalize", END)
    return g.compile()


_graph = _build_graph()


# ── Public entry point ─────────────────────────────────────────────

def run_scan_pipeline(
    scan_id: str,
    project_path: str,
    scan_type: str = "code",
    target_url: str = "",
) -> None:
    initial: ScanState = {
        "scan_id":           scan_id,
        "scan_type":         scan_type,
        "project_path":      project_path,
        "target_url":        target_url,
        "tech_stack":        [],
        "blue_findings":     [],
        "red_findings":      [],
        "verified_findings": [],
        "compliance":        {},
        "error":             "",
    }
    try:
        _graph.invoke(initial)
    except Exception as exc:
        update_scan(scan_id, status="failed", error=str(exc))
        pub_error(scan_id, str(exc))
        raise
