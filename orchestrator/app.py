"""
Orchestrator — Main Supervisor service.
Accepts scan requests from the backend and drives the LangGraph pipeline.
"""
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from supervisor import run_scan_pipeline
from scheduler import start_monitor

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "orchestrator"}), 200


@app.route("/scan/start", methods=["POST"])
def start_scan():
    data         = request.get_json(silent=True) or {}
    scan_id      = data.get("scan_id")
    scan_type    = data.get("scan_type", "code")   # "code" | "url"
    project_path = data.get("project_path", "")
    target_url   = data.get("target_url", "")

    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    if scan_type == "code" and not project_path:
        return jsonify({"error": "project_path required for code scans"}), 400
    if scan_type == "url" and not target_url:
        return jsonify({"error": "target_url required for URL scans"}), 400

    threading.Thread(
        target=run_scan_pipeline,
        args=(scan_id, project_path, scan_type, target_url),
        daemon=True,
    ).start()

    return jsonify({"status": "started", "scan_id": scan_id}), 202


if __name__ == "__main__":
    start_monitor()
    app.run(host="0.0.0.0", port=8000, threaded=True)
