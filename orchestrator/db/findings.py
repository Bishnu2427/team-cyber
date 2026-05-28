import os
from datetime import datetime
from pymongo import MongoClient

_client = None


def _db():
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/teamcyber"))
    return _client["teamcyber"]


def bulk_create_findings(scan_id: str, findings: list) -> None:
    if not findings:
        return
    for f in findings:
        f["scan_id"] = scan_id
        f.setdefault("created_at", datetime.utcnow())
    _db().findings.insert_many(findings)
