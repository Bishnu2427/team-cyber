"""Red Team microservice — internal container, not exposed to public."""
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from supervisor import run_red_team

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "red-team", "phase": 1}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    data         = request.get_json(silent=True) or {}
    scan_id      = data.get("scan_id", "")
    project_path = data.get("project_path", "")
    tech_stack   = data.get("tech_stack", [])

    result = run_red_team(scan_id, project_path, tech_stack)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, threaded=True)
