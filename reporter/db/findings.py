import os
from pymongo import MongoClient

_client = None


def _db():
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/teamcyber"))
    return _client["teamcyber"]


def get_scan_findings(scan_id: str) -> list:
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = list(_db().findings.find({"scan_id": scan_id}))
    for f in findings:
        f["_id"] = str(f["_id"])
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 9))
    return findings
