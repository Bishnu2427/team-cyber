"""
Verification + Reflection + Consensus Layer.

Pipeline:
  1. Filter  — drop findings below confidence threshold
  2. Deduplicate — merge identical vulnerability+location pairs
  3. Reflect — LLM double-checks uncertain findings for false positives
  4. Consensus — generate final confidence scores
  5. Compliance — OWASP Top 10 mapping
"""
import json
from typing import List, Tuple

from models.model_router import router

CONFIDENCE_THRESHOLD = 0.45   # drop anything below this
REFLECT_THRESHOLD    = 0.72   # LLM re-evaluates anything below this

OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

_REFLECT_PROMPT = """You are a senior security researcher performing peer review.
Assess whether this finding is a real vulnerability or a false positive.

Finding:
{finding}

Tech stack: {tech_stack}

Respond ONLY with JSON:
{{
  "is_valid": true,
  "adjusted_confidence": 0.85,
  "reason": "brief justification"
}}"""


# ── Stage 1: Filter ───────────────────────────────────────────────

def _filter(findings: List[dict]) -> List[dict]:
    return [f for f in findings if f.get("confidence", 0) >= CONFIDENCE_THRESHOLD]


# ── Stage 2: Deduplicate ──────────────────────────────────────────

def _deduplicate(findings: List[dict]) -> List[dict]:
    seen: set = set()
    unique: List[dict] = []
    for f in findings:
        key = (
            f.get("vulnerability", "").lower(),
            f.get("location", ""),
            f.get("line", 0),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Stage 3: Reflection (LLM peer review) ────────────────────────

def _reflect(findings: List[dict], tech_stack: List[str]) -> List[dict]:
    llm = router.fast()
    verified: List[dict] = []
    for f in findings:
        conf = f.get("confidence", 1.0)
        if conf >= REFLECT_THRESHOLD:
            f["verified"] = True
            verified.append(f)
            continue
        try:
            prompt = _REFLECT_PROMPT.format(
                finding=json.dumps(f, indent=2, default=str),
                tech_stack=tech_stack,
            )
            resp    = llm.invoke(prompt)
            content = getattr(resp, "content", str(resp))
            s, e    = content.find("{"), content.rfind("}") + 1
            if s >= 0 and e > s:
                result = json.loads(content[s:e])
                if not result.get("is_valid", True):
                    print(f"[verifier] Dropped false positive: {f.get('vulnerability')}")
                    continue
                f["confidence"] = result.get("adjusted_confidence", conf)
                f["reflect_reason"] = result.get("reason", "")
        except Exception as exc:
            print(f"[verifier] Reflection error: {exc}")

        f["verified"] = True
        verified.append(f)
    return verified


# ── Stage 4: Consensus scoring ────────────────────────────────────

def _consensus(findings: List[dict]) -> List[dict]:
    """
    Adjust severity based on confidence:
    - confidence < 0.6 → downgrade severity one level
    - confidence > 0.9 + critical → keep as critical
    """
    sev_up   = ["low", "medium", "high", "critical"]
    sev_down = {v: sev_up[max(0, i - 1)] for i, v in enumerate(sev_up)}

    for f in findings:
        conf = f.get("confidence", 0.8)
        sev  = f.get("severity", "medium").lower()
        if conf < 0.60 and sev != "low":
            f["severity"] = sev_down.get(sev, sev)
    return findings


# ── Stage 5: OWASP compliance ─────────────────────────────────────

def _compliance(findings: List[dict]) -> dict:
    status = {
        cat: {"name": name, "status": "pass", "findings": []}
        for cat, name in OWASP_TOP10.items()
    }
    for f in findings:
        owasp = f.get("owasp", "")
        if not owasp:
            continue
        cat = owasp.split(":")[0].upper()
        if cat in status:
            status[cat]["status"] = "fail"
            status[cat]["findings"].append(f.get("vulnerability", "Unknown"))

    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(OWASP_TOP10)
    return {
        "categories": status,
        "score":  round((passed / total) * 100, 1),
        "passed": passed,
        "failed": total - passed,
        "total":  total,
    }


# ── Public entry point ────────────────────────────────────────────

def verify(findings: List[dict], tech_stack: List[str]) -> Tuple[List[dict], dict]:
    """Full verification pipeline. Returns (verified_findings, compliance)."""
    print(f"[verifier] Input: {len(findings)} findings")

    step1 = _filter(findings)
    print(f"[verifier] After filter: {len(step1)}")

    step2 = _deduplicate(step1)
    print(f"[verifier] After dedup: {len(step2)}")

    step3 = _reflect(step2, tech_stack)
    print(f"[verifier] After reflection: {len(step3)}")

    step4 = _consensus(step3)
    compliance = _compliance(step4)

    print(f"[verifier] Done — {len(step4)} verified, score {compliance['score']}%")
    return step4, compliance
