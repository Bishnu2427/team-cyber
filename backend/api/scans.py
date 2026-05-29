import ipaddress
import os
import socket
import threading
import zipfile
from urllib.parse import urlparse

import git
import httpx
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from backend.db.findings import get_scan_findings
from backend.db.scans import create_scan, get_scan, get_user_scans, update_scan

scans_bp = Blueprint("scans", __name__)

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/app/uploads")

# ── SSRF protection ────────────────────────────────────────────────
_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal",          # GCP metadata
    "169.254.169.254",                    # AWS/Azure metadata
    "100.100.100.200",                    # Alibaba metadata
})

def _is_safe_url(url: str) -> bool:
    """Block private/internal URLs to prevent SSRF."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host or len(host) > 253:
            return False
        if host.lower() in _BLOCKED_HOSTS:
            return False
        # Reject anything with path traversal attempts
        if ".." in url or "%2e" in url.lower():
            return False
        try:
            ip = socket.gethostbyname(host)
            addr = ipaddress.ip_address(ip)
            if (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_reserved or
                    addr.is_multicast or addr.is_unspecified):
                return False
        except socket.gaierror:
            return False   # Can't resolve → reject
        return True
    except Exception:
        return False


# ── Serialisation helper ───────────────────────────────────────────

def _serialize(scan: dict) -> dict:
    scan["_id"] = str(scan["_id"])
    for key in ("created_at", "updated_at", "completed_at"):
        if scan.get(key):
            scan[key] = scan[key].isoformat()
    return scan


# ── List / detail ──────────────────────────────────────────────────

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


# ── ZIP upload ─────────────────────────────────────────────────────

@scans_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_zip():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename.endswith(".zip"):
        return jsonify({"error": "Only ZIP files are supported"}), 400

    # 100 MB limit
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > 100 * 1024 * 1024:
        return jsonify({"error": "File exceeds 100 MB limit"}), 400

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
    threading.Thread(
        target=_dispatch_scan,
        args=(scan_id, extract_path, orchestrator_url),
        daemon=True,
    ).start()
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


# ── GitHub clone ───────────────────────────────────────────────────

@scans_bp.route("/github", methods=["POST"])
@jwt_required()
def scan_github():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    if not url.startswith("https://github.com/"):
        return jsonify({"error": "Invalid GitHub URL"}), 400

    project_name = data.get("project_name", url.rstrip("/").split("/")[-1])
    scan_id      = create_scan(get_jwt_identity(), project_name, "github", url)
    clone_path   = os.path.join(UPLOAD_FOLDER, scan_id)
    orchestrator_url = current_app.config["ORCHESTRATOR_URL"]

    def clone_and_dispatch():
        try:
            git.Repo.clone_from(url, clone_path, depth=1)
            _dispatch_scan(scan_id, clone_path, orchestrator_url)
        except Exception as exc:
            update_scan(scan_id, status="failed", error=str(exc))

    threading.Thread(target=clone_and_dispatch, daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


# ── URL / live-site scan ───────────────────────────────────────────

@scans_bp.route("/url", methods=["POST"])
@jwt_required()
def scan_url():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not _is_safe_url(url):
        return jsonify({
            "error": (
                "Invalid or unsafe URL. Only publicly reachable http/https URLs are "
                "supported. Private IPs, localhost, and cloud metadata endpoints are blocked."
            )
        }), 400

    parsed       = urlparse(url)
    project_name = data.get("project_name") or parsed.netloc or url
    scan_id      = create_scan(get_jwt_identity(), project_name, "url", url)
    orchestrator_url = current_app.config["ORCHESTRATOR_URL"]

    threading.Thread(
        target=_dispatch_url_scan,
        args=(scan_id, url, orchestrator_url),
        daemon=True,
    ).start()
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


# ── Internal dispatch helpers ──────────────────────────────────────

def _dispatch_scan(scan_id: str, project_path: str, orchestrator_url: str) -> None:
    try:
        httpx.post(
            f"{orchestrator_url}/scan/start",
            json={"scan_id": scan_id, "scan_type": "code", "project_path": project_path},
            timeout=30,
        )
    except Exception as exc:
        update_scan(scan_id, status="failed", error=f"Orchestrator unreachable: {exc}")


def _dispatch_url_scan(scan_id: str, target_url: str, orchestrator_url: str) -> None:
    try:
        httpx.post(
            f"{orchestrator_url}/scan/start",
            json={"scan_id": scan_id, "scan_type": "url", "target_url": target_url},
            timeout=30,
        )
    except Exception as exc:
        update_scan(scan_id, status="failed", error=f"Orchestrator unreachable: {exc}")
