"""Reporter microservice — Report Generator + Dashboard Engine."""
from flask import Flask, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from db.scans import get_scan
from db.findings import get_scan_findings
from pdf_report import generate_pdf

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "reporter"}), 200


@app.route("/report/<scan_id>/pdf", methods=["GET"])
def download_pdf(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.get("status") != "completed":
        return jsonify({"error": "Scan not yet complete"}), 400

    findings = get_scan_findings(scan_id)
    scan["_id"] = str(scan["_id"])  # make serialisable

    pdf_path = generate_pdf(scan, findings)
    filename = f"teamcyber_{scan['project_name']}_{scan_id[:8]}.pdf"

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@app.route("/report/<scan_id>/summary", methods=["GET"])
def summary(scan_id: str):
    """JSON summary used by the dashboard engine."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = get_scan_findings(scan_id)
    scan["_id"] = str(scan["_id"])
    return jsonify({"scan": scan, "findings": findings}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8004, threaded=True)
