"""Verifier microservice — Verification + Reflection + Consensus layer."""
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from verifier import verify

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "verifier"}), 200


@app.route("/verify", methods=["POST"])
def verify_findings():
    data       = request.get_json(silent=True) or {}
    findings   = data.get("findings", [])
    tech_stack = data.get("tech_stack", [])

    verified, compliance = verify(findings, tech_stack)
    return jsonify({"verified_findings": verified, "compliance": compliance}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003, threaded=True)
