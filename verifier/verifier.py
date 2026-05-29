"""
Verification + Reflection + Consensus Layer.

Pipeline:
  1. Filter      — drop findings below confidence threshold
  2. Deduplicate — merge identical vulnerability+location pairs
  3. Reflect     — LLM double-checks uncertain findings for false positives
  4. Consensus   — adjust severity by confidence score
  5. Compliance  — OWASP Top 10 + CWE Top 25 + PCI-DSS v4.0 + NIST SP 800-53
"""
import json
import re
from typing import List, Tuple, Dict

from models.model_router import router

CONFIDENCE_THRESHOLD = 0.45
REFLECT_THRESHOLD    = 0.72

# ── Framework definitions (copied here; verifier is a separate container) ─────

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

CWE_TOP25 = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-416": "Use After Free",
    "CWE-78":  "OS Command Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-125": "Out-of-bounds Read",
    "CWE-22":  "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-287": "Improper Authentication",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77":  "Command Injection",
    "CWE-119": "Buffer Over-read/Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-362": "Race Condition",
    "CWE-269": "Improper Privilege Management",
    "CWE-94":  "Code Injection",
    "CWE-863": "Incorrect Authorization",
    "CWE-276": "Incorrect Default Permissions",
}

PCIDSS_REQUIREMENTS = {
    "Req-2.2":   ("Secure configuration of system components",         ["A05"], ["CWE-276","CWE-306"]),
    "Req-3.4":   ("Protection of stored account data",                 ["A02"], ["CWE-312","CWE-798"]),
    "Req-6.2.4": ("Prevention of common software attacks",             ["A03","A01"], ["CWE-89","CWE-79","CWE-78","CWE-22"]),
    "Req-6.3.2": ("Inventory of bespoke and custom software",          ["A06"], []),
    "Req-6.4.1": ("Web-facing apps protected against known attacks",   ["A03","A01","A05"], ["CWE-79","CWE-89"]),
    "Req-8.2":   ("Unique IDs and credentials for all users",          ["A07"], ["CWE-287","CWE-798","CWE-306"]),
    "Req-8.3":   ("Strong authentication for all users",               ["A07"], ["CWE-287","CWE-521"]),
    "Req-8.6":   ("Application accounts managed via policies",         ["A07"], ["CWE-798","CWE-259"]),
    "Req-10.2":  ("Implement audit logs for all system components",    ["A09"], ["CWE-778","CWE-223"]),
    "Req-12.3":  ("Target risks identified, assessed, and managed",    ["A04"], []),
}

NIST_CONTROLS = {
    "AC": ("Access Control",                      ["A01","A07"], ["CWE-862","CWE-863","CWE-306","CWE-269"]),
    "AU": ("Audit and Accountability",            ["A09"],       ["CWE-778","CWE-223"]),
    "CM": ("Configuration Management",           ["A05","A06"], ["CWE-276","CWE-1035"]),
    "IA": ("Identification and Authentication",  ["A07"],       ["CWE-287","CWE-798","CWE-306"]),
    "SC": ("System and Communications Protection",["A02","A10"],["CWE-295","CWE-326","CWE-319","CWE-918"]),
    "SI": ("System and Information Integrity",   ["A03","A08"], ["CWE-89","CWE-79","CWE-78","CWE-502"]),
    "SA": ("System and Services Acquisition",    ["A04","A06"], []),
    "RA": ("Risk Assessment",                    ["A04"],       []),
}

_OWASP_TO_CWE: Dict[str, List[str]] = {
    "A01": ["CWE-862","CWE-863","CWE-22","CWE-269"],
    "A02": ["CWE-326","CWE-327","CWE-330","CWE-312","CWE-319","CWE-798"],
    "A03": ["CWE-89","CWE-79","CWE-78","CWE-94","CWE-77","CWE-20"],
    "A04": ["CWE-656"],
    "A05": ["CWE-276","CWE-732","CWE-16"],
    "A06": ["CWE-1035"],
    "A07": ["CWE-287","CWE-306","CWE-798","CWE-521"],
    "A08": ["CWE-502","CWE-494"],
    "A09": ["CWE-778","CWE-223"],
    "A10": ["CWE-918"],
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


# ── Stage 5: Multi-framework compliance ──────────────────────────

def _compliance(findings: List[dict]) -> dict:
    _infer_missing_cwe(findings)
    owasp = _check_owasp(findings)
    passed = sum(1 for v in owasp.values() if v["status"] == "pass")
    total  = len(OWASP_TOP10)
    return {
        "categories": owasp,
        "score":      round((passed / total) * 100, 1),
        "passed":     passed,
        "failed":     total - passed,
        "total":      total,
        "cwe_top25":  _check_cwe_top25(findings),
        "pci_dss":    _check_pcidss(findings),
        "nist_800_53": _check_nist(findings),
    }


def _check_owasp(findings: List[dict]) -> dict:
    status = {cat: {"name": name, "status": "pass", "findings": []}
              for cat, name in OWASP_TOP10.items()}
    for f in findings:
        owasp = f.get("owasp", "")
        m = re.match(r"(A\d+):", owasp.upper())
        if m and m.group(1) in status:
            status[m.group(1)]["status"] = "fail"
            status[m.group(1)]["findings"].append(f.get("vulnerability", "Unknown"))
    return status


def _check_cwe_top25(findings: List[dict]) -> dict:
    status = {k: {"name": v, "status": "pass", "findings": []} for k, v in CWE_TOP25.items()}
    for f in findings:
        m = re.search(r"CWE-(\d+)", str(f.get("cwe", "")), re.IGNORECASE)
        if m:
            key = f"CWE-{m.group(1)}"
            if key in status:
                status[key]["status"] = "fail"
                status[key]["findings"].append(f.get("vulnerability", "Unknown"))
    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(CWE_TOP25)
    return {"categories": status, "score": round((passed/total)*100, 1),
            "passed": passed, "failed": total-passed, "total": total,
            "name": "CWE Top 25 (2023)"}


def _check_pcidss(findings: List[dict]) -> dict:
    status = {}
    for req_id, (desc, owasp_cats, cwe_ids) in PCIDSS_REQUIREMENTS.items():
        hits = [f.get("vulnerability", "Unknown") for f in findings
                if _owasp_cat(f) in owasp_cats or _cwe_in(f, cwe_ids)]
        status[req_id] = {"name": desc, "status": "fail" if hits else "pass",
                          "findings": list(dict.fromkeys(hits))[:5]}
    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(PCIDSS_REQUIREMENTS)
    return {"categories": status, "score": round((passed/total)*100, 1),
            "passed": passed, "failed": total-passed, "total": total,
            "name": "PCI-DSS v4.0"}


def _check_nist(findings: List[dict]) -> dict:
    status = {}
    for ctrl_id, (desc, owasp_cats, cwe_ids) in NIST_CONTROLS.items():
        hits = [f.get("vulnerability", "Unknown") for f in findings
                if _owasp_cat(f) in owasp_cats or _cwe_in(f, cwe_ids)]
        status[ctrl_id] = {"name": desc, "status": "fail" if hits else "pass",
                           "findings": list(dict.fromkeys(hits))[:5]}
    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(NIST_CONTROLS)
    return {"categories": status, "score": round((passed/total)*100, 1),
            "passed": passed, "failed": total-passed, "total": total,
            "name": "NIST SP 800-53 Rev 5"}


def _infer_missing_cwe(findings: List[dict]) -> None:
    for f in findings:
        if f.get("cwe"):
            continue
        cat = _owasp_cat(f)
        if cat:
            cwes = _OWASP_TO_CWE.get(cat, [])
            if cwes:
                f["cwe"] = cwes[0]


def _owasp_cat(f: dict) -> str:
    m = re.match(r"(A\d+):", f.get("owasp", "").upper())
    return m.group(1) if m else ""


def _cwe_in(f: dict, cwe_list: List[str]) -> bool:
    m = re.search(r"CWE-(\d+)", str(f.get("cwe", "")), re.IGNORECASE)
    return bool(m) and f"CWE-{m.group(1)}" in cwe_list


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
