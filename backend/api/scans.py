import os
import zipfile
import threading
import httpx
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.db.scans import create_scan, get_scan, get_user_scans, update_scan
from backend.db.findings import get_scan_findings
import git

scans_bp = Blueprint("scans", __name__)

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/app/uploads")


def _serialize(scan: dict) -> dict:
    scan["_id"] = str(scan["_id"])
    for key in ("created_at", "updated_at", "completed_at"):
        if scan.get(key):
            scan[key] = scan[key].isoformat()
    return scan


@scans_bp.route("/", methods=["GET"])
@jwt_required()
def list_scans():
    scans = get_user_scans(get_jwt_identity())
    return jsonify([_serialize(s) for s in scans]), 200


@scans_bp.route("/<scan_id>", methods=["GET"])
@jwt_required()
def scan_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan": _serialize(scan), "findings": get_scan_findings(scan_id)}), 200


@scans_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_zip():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename.endswith(".zip"):
        return jsonify({"error": "Only ZIP files are supported"}), 400

    project_name = request.form.get("project_name", file.filename.replace(".zip", ""))
    scan_id = create_scan(get_jwt_identity(), project_name, "zip", file.filename)

    extract_path = os.path.join(UPLOAD_FOLDER, scan_id)
    os.makedirs(extract_path, exist_ok=True)
    zip_path = os.path.join(extract_path, "project.zip")
    file.save(zip_path)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_path)
    os.remove(zip_path)

    orchestrator_url = current_app.config["ORCHESTRATOR_URL"]
    threading.Thread(target=_dispatch_scan, args=(scan_id, extract_path, orchestrator_url), daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


@scans_bp.route("/github", methods=["POST"])
@jwt_required()
def scan_github():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url.startswith("https://github.com/"):
        return jsonify({"error": "Invalid GitHub URL"}), 400

    project_name = data.get("project_name", url.rstrip("/").split("/")[-1])
    scan_id = create_scan(get_jwt_identity(), project_name, "github", url)
    clone_path = os.path.join(UPLOAD_FOLDER, scan_id)
    orchestrator_url = current_app.config["ORCHESTRATOR_URL"]

    def clone_and_dispatch():
        try:
            git.Repo.clone_from(url, clone_path, depth=1)
            _dispatch_scan(scan_id, clone_path, orchestrator_url)
        except Exception as exc:
            update_scan(scan_id, status="failed", error=str(exc))

    threading.Thread(target=clone_and_dispatch, daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


def _dispatch_scan(scan_id: str, project_path: str, orchestrator_url: str) -> None:
    """Tell the orchestrator (Main Supervisor) to start the pipeline."""
    try:
        httpx.post(
            f"{orchestrator_url}/scan/start",
            json={"scan_id": scan_id, "project_path": project_path},
            timeout=30,
        )
    except Exception as exc:
        update_scan(scan_id, status="failed", error=f"Orchestrator unreachable: {exc}")
