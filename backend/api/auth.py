from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from backend.db.users import create_user, get_user_by_email, get_user_by_id, verify_password, email_exists

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if email_exists(email):
        return jsonify({"error": "Email already registered"}), 409

    user_id = create_user(username, email, password)
    token = create_access_token(identity=user_id)
    return jsonify({"token": token, "user_id": user_id, "username": username}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = get_user_by_email(email)
    if not user or not verify_password(user, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user["_id"]))
    return jsonify({
        "token": token,
        "user_id": str(user["_id"]),
        "username": user["username"],
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user = get_user_by_id(get_jwt_identity())
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "user_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }), 200
