from datetime import datetime
from bson import ObjectId
from backend.extensions import mongo


def create_scan(user_id: str, project_name: str, source_type: str, source_value: str) -> str:
    doc = {
        "user_id": user_id,
        "project_name": project_name,
        "source_type": source_type,   # 'zip' | 'github'
        "source_value": source_value,
        "status": "queued",            # queued | running | completed | failed
        "progress": 0,
        "tech_stack": [],
        "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "compliance_results": {},
        "error": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "completed_at": None,
    }
    result = mongo.db.scans.insert_one(doc)
    return str(result.inserted_id)


def get_scan(scan_id: str) -> dict | None:
    return mongo.db.scans.find_one({"_id": ObjectId(scan_id)})


def get_user_scans(user_id: str) -> list:
    return list(mongo.db.scans.find({"user_id": user_id}).sort("created_at", -1))


def update_scan(scan_id: str, **fields) -> None:
    fields["updated_at"] = datetime.utcnow()
    mongo.db.scans.update_one({"_id": ObjectId(scan_id)}, {"$set": fields})
