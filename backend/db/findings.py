from datetime import datetime
from bson import ObjectId
from backend.extensions import mongo


def bulk_create_findings(scan_id: str, findings: list) -> list:
    if not findings:
        return []
    for f in findings:
        f["scan_id"] = scan_id
        f.setdefault("created_at", datetime.utcnow())
    result = mongo.db.findings.insert_many(findings)
    return [str(i) for i in result.inserted_ids]


def get_scan_findings(scan_id: str) -> list:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = list(mongo.db.findings.find({"scan_id": scan_id}))
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 9))
    for f in findings:
        f["_id"] = str(f["_id"])
    return findings


def get_finding(finding_id: str) -> dict | None:
    return mongo.db.findings.find_one({"_id": ObjectId(finding_id)})
