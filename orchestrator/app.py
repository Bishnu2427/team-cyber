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
    data = request.get_json(silent=True) or {}
    scan_id      = data.get("scan_id")
    project_path = data.get("project_path")

    if not scan_id or not project_path:
        return jsonify({"error": "scan_id and project_path required"}), 400

    # Run the pipeline in a background thread — return 202 immediately
    threading.Thread(
        target=run_scan_pipeline,
        args=(scan_id, project_path),
        daemon=True,
    ).start()

    return jsonify({"status": "started", "scan_id": scan_id}), 202


if __name__ == "__main__":
    start_monitor()   # background health-check loop
    app.run(host="0.0.0.0", port=8000, threaded=True)
