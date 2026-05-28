from typing import List

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


def run_compliance_check(findings: List[dict]) -> dict:
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
