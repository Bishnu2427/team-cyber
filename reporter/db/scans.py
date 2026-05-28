import os
from bson import ObjectId
from pymongo import MongoClient

_client = None


def _db():
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/teamcyber"))
    return _client["teamcyber"]


def get_scan(scan_id: str) -> dict | None:
    return _db().scans.find_one({"_id": ObjectId(scan_id)})
