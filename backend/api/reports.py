import httpx
from flask import Blueprint, jsonify, Response, current_app
from flask_jwt_extended import jwt_required
from backend.db.scans import get_scan

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/<scan_id>/pdf", methods=["GET"])
@jwt_required()
def download_pdf(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan["status"] != "completed":
        return jsonify({"error": "Scan not yet complete"}), 400

    reporter_url = current_app.config["REPORTER_URL"]
    try:
        resp = httpx.get(f"{reporter_url}/report/{scan_id}/pdf", timeout=60)
        if resp.status_code != 200:
            return jsonify({"error": "Report generation failed"}), 500

        filename = f"teamcyber_{scan['project_name']}_{scan_id[:8]}.pdf"
        return Response(
            resp.content,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        return jsonify({"error": f"Reporter service unreachable: {exc}"}), 503
