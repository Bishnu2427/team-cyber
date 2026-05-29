"""
Compliance Agent — maps findings to multiple security frameworks.

Frameworks:
  • OWASP Top 10 2021
  • CWE Top 25 Most Dangerous Software Weaknesses (2023)
  • PCI-DSS v4.0 (relevant requirements)
  • NIST SP 800-53 Rev 5 (key control families)
"""
import re
from typing import List, Dict

# ══════════════════════════════════════════════════════════════════
#  Framework definitions
# ══════════════════════════════════════════════════════════════════

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

# CWE Top 25 (2023) — maps CWE-ID → description
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
    "CWE-77":  "Improper Neutralization of Special Elements in a Command",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-362": "Concurrent Execution using Shared Resource (Race Condition)",
    "CWE-269": "Improper Privilege Management",
    "CWE-94":  "Improper Control of Generation of Code (Code Injection)",
    "CWE-863": "Incorrect Authorization",
    "CWE-276": "Incorrect Default Permissions",
}

# PCI-DSS v4.0 key requirements and their OWASP/CWE associations
PCIDSS_REQUIREMENTS = {
    "Req-2.2":  ("Secure configuration of system components",
                 ["A05"], ["CWE-276", "CWE-306"]),
    "Req-3.4":  ("Protection of stored account data",
                 ["A02"], ["CWE-312", "CWE-798"]),
    "Req-6.2.4":("Prevention of common software attacks (injection, XSS, etc.)",
                 ["A03", "A01"], ["CWE-89", "CWE-79", "CWE-78", "CWE-22"]),
    "Req-6.3.2":("Maintain an inventory of bespoke and custom software",
                 ["A06"], ["CWE-1035"]),
    "Req-6.4.1":("Web-facing apps protected against known attacks",
                 ["A03", "A01", "A05"], ["CWE-79", "CWE-89"]),
    "Req-8.2":  ("Unique IDs and credentials for all users",
                 ["A07"], ["CWE-287", "CWE-798", "CWE-306"]),
    "Req-8.3":  ("Strong authentication for all users",
                 ["A07"], ["CWE-287", "CWE-521"]),
    "Req-8.6":  ("Application and system accounts managed via policies",
                 ["A07"], ["CWE-798", "CWE-259"]),
    "Req-10.2": ("Implement audit logs for all system components",
                 ["A09"], ["CWE-778", "CWE-223"]),
    "Req-12.3": ("Target risks identified, assessed, and managed",
                 ["A04"], []),
}

# NIST SP 800-53 Rev 5 key control families
NIST_CONTROLS = {
    "AC": ("Access Control",
           ["A01", "A07"], ["CWE-862", "CWE-863", "CWE-306", "CWE-269"]),
    "AU": ("Audit and Accountability",
           ["A09"], ["CWE-778", "CWE-223"]),
    "CM": ("Configuration Management",
           ["A05", "A06"], ["CWE-276", "CWE-1035"]),
    "IA": ("Identification and Authentication",
           ["A07"], ["CWE-287", "CWE-798", "CWE-306"]),
    "SC": ("System and Communications Protection",
           ["A02", "A10"], ["CWE-295", "CWE-326", "CWE-319", "CWE-918"]),
    "SI": ("System and Information Integrity",
           ["A03", "A08"], ["CWE-89", "CWE-79", "CWE-78", "CWE-502"]),
    "SA": ("System and Services Acquisition (Secure Coding)",
           ["A04", "A06"], ["CWE-1035"]),
    "RA": ("Risk Assessment",
           ["A04"], []),
}


# ══════════════════════════════════════════════════════════════════
#  OWASP ↔ CWE inferred mapping (for findings without explicit CWE)
# ══════════════════════════════════════════════════════════════════

_OWASP_TO_CWE: Dict[str, List[str]] = {
    "A01": ["CWE-862", "CWE-863", "CWE-22",  "CWE-269", "CWE-284"],
    "A02": ["CWE-326", "CWE-327", "CWE-330", "CWE-312", "CWE-319", "CWE-798"],
    "A03": ["CWE-89",  "CWE-79",  "CWE-78",  "CWE-94",  "CWE-77",  "CWE-20"],
    "A04": ["CWE-656", "CWE-657"],
    "A05": ["CWE-276", "CWE-732", "CWE-16",  "CWE-601"],
    "A06": ["CWE-1035","CWE-937"],
    "A07": ["CWE-287", "CWE-306", "CWE-798", "CWE-521", "CWE-384"],
    "A08": ["CWE-502", "CWE-494", "CWE-829"],
    "A09": ["CWE-778", "CWE-223", "CWE-117"],
    "A10": ["CWE-918"],
}


# ══════════════════════════════════════════════════════════════════
#  Public entry point
# ══════════════════════════════════════════════════════════════════

def run_compliance_check(findings: List[dict]) -> dict:
    # Enrich each finding with inferred CWE if missing
    _infer_missing_cwe(findings)

    owasp   = _check_owasp(findings)
    cwe25   = _check_cwe_top25(findings)
    pci     = _check_pcidss(findings)
    nist    = _check_nist(findings)

    # Overall OWASP score (backward-compat primary score)
    passed_owasp = sum(1 for v in owasp.values() if v["status"] == "pass")
    total_owasp  = len(OWASP_TOP10)

    return {
        "categories":   owasp,                          # kept for existing UI/PDF
        "score":        round((passed_owasp / total_owasp) * 100, 1),
        "passed":       passed_owasp,
        "failed":       total_owasp - passed_owasp,
        "total":        total_owasp,
        # Extended frameworks
        "cwe_top25":    cwe25,
        "pci_dss":      pci,
        "nist_800_53":  nist,
    }


# ══════════════════════════════════════════════════════════════════
#  OWASP Top 10
# ══════════════════════════════════════════════════════════════════

def _check_owasp(findings: List[dict]) -> dict:
    status = {
        cat: {"name": name, "status": "pass", "findings": []}
        for cat, name in OWASP_TOP10.items()
    }
    for f in findings:
        owasp = f.get("owasp", "")
        if not owasp:
            continue
        m = re.match(r"(A\d+):", owasp.upper())
        if m:
            cat = m.group(1)
            if cat in status:
                status[cat]["status"] = "fail"
                status[cat]["findings"].append(f.get("vulnerability", "Unknown"))
    return status


# ══════════════════════════════════════════════════════════════════
#  CWE Top 25
# ══════════════════════════════════════════════════════════════════

def _check_cwe_top25(findings: List[dict]) -> dict:
    status = {
        cwe_id: {"name": name, "status": "pass", "findings": []}
        for cwe_id, name in CWE_TOP25.items()
    }
    for f in findings:
        cwe_raw = f.get("cwe", "")
        if not cwe_raw:
            continue
        # Normalise CWE-XXX
        m = re.search(r"CWE-(\d+)", str(cwe_raw), re.IGNORECASE)
        if m:
            key = f"CWE-{m.group(1)}"
            if key in status:
                status[key]["status"] = "fail"
                status[key]["findings"].append(f.get("vulnerability", "Unknown"))

    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(CWE_TOP25)
    return {
        "categories": status,
        "score":  round((passed / total) * 100, 1),
        "passed": passed,
        "failed": total - passed,
        "total":  total,
        "name":   "CWE Top 25 (2023)",
    }


# ══════════════════════════════════════════════════════════════════
#  PCI-DSS v4.0
# ══════════════════════════════════════════════════════════════════

def _check_pcidss(findings: List[dict]) -> dict:
    status = {}
    for req_id, (desc, owasp_cats, cwe_ids) in PCIDSS_REQUIREMENTS.items():
        failed_vuln = []
        for f in findings:
            owasp = f.get("owasp", "")
            cwe   = f.get("cwe", "")
            owasp_cat = owasp.split(":")[0] if owasp else ""
            if owasp_cat in owasp_cats or _cwe_in_list(cwe, cwe_ids):
                failed_vuln.append(f.get("vulnerability", "Unknown"))

        status[req_id] = {
            "name":     desc,
            "status":   "fail" if failed_vuln else "pass",
            "findings": list(dict.fromkeys(failed_vuln))[:5],  # deduplicate, max 5
        }

    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(PCIDSS_REQUIREMENTS)
    return {
        "categories": status,
        "score":  round((passed / total) * 100, 1),
        "passed": passed,
        "failed": total - passed,
        "total":  total,
        "name":   "PCI-DSS v4.0",
    }


# ══════════════════════════════════════════════════════════════════
#  NIST SP 800-53 Rev 5
# ══════════════════════════════════════════════════════════════════

def _check_nist(findings: List[dict]) -> dict:
    status = {}
    for ctrl_id, (desc, owasp_cats, cwe_ids) in NIST_CONTROLS.items():
        failed_vuln = []
        for f in findings:
            owasp     = f.get("owasp", "")
            cwe       = f.get("cwe", "")
            owasp_cat = owasp.split(":")[0] if owasp else ""
            if owasp_cat in owasp_cats or _cwe_in_list(cwe, cwe_ids):
                failed_vuln.append(f.get("vulnerability", "Unknown"))

        status[ctrl_id] = {
            "name":     desc,
            "status":   "fail" if failed_vuln else "pass",
            "findings": list(dict.fromkeys(failed_vuln))[:5],
        }

    passed = sum(1 for v in status.values() if v["status"] == "pass")
    total  = len(NIST_CONTROLS)
    return {
        "categories": status,
        "score":  round((passed / total) * 100, 1),
        "passed": passed,
        "failed": total - passed,
        "total":  total,
        "name":   "NIST SP 800-53 Rev 5",
    }


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def _infer_missing_cwe(findings: List[dict]) -> None:
    """Add a representative CWE for findings that have OWASP but no CWE."""
    for f in findings:
        if f.get("cwe"):
            continue
        owasp = f.get("owasp", "")
        m = re.match(r"(A\d+):", owasp.upper())
        if m:
            cat = m.group(1)
            cwes = _OWASP_TO_CWE.get(cat, [])
            if cwes:
                f["cwe"] = cwes[0]   # assign the most representative CWE




def _cwe_in_list(cwe_raw: str, cwe_list: List[str]) -> bool:
    m = re.search(r"CWE-(\d+)", str(cwe_raw), re.IGNORECASE)
    if not m:
        return False
    key = f"CWE-{m.group(1)}"
    return key in cwe_list
