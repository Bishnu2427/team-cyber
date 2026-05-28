from datetime import datetime
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from backend.extensions import mongo


def create_user(username: str, email: str, password: str) -> str:
    doc = {
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "role": "analyst",
        "created_at": datetime.utcnow(),
    }
    result = mongo.db.users.insert_one(doc)
    return str(result.inserted_id)


def get_user_by_email(email: str) -> dict | None:
    return mongo.db.users.find_one({"email": email})


def get_user_by_id(user_id: str) -> dict | None:
    return mongo.db.users.find_one({"_id": ObjectId(user_id)})


def verify_password(user: dict, password: str) -> bool:
    return check_password_hash(user["password_hash"], password)


def email_exists(email: str) -> bool:
    return mongo.db.users.find_one({"email": email}) is not None
