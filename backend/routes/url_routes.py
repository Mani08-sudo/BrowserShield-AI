"""
url_routes.py — URL Analysis API Endpoint
==========================================
POST /api/analyze-url
Accepts a URL, runs analysis, logs the incident, returns risk decision.
"""

from flask import Blueprint, request, jsonify
from backend.analysis.url_analysis import analyze_url
from backend.database.db import log_incident

url_bp = Blueprint("url_bp", __name__)


@url_bp.route("/api/analyze-url", methods=["POST", "OPTIONS"])
def analyze_url_api():

    # ── Step 1: Parse and validate input ─────────────────────────────
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing required field: url"}), 400

    if len(url) > 2000:
        return jsonify({"error": "URL too long (max 2000 characters)"}), 400

    # ── Step 2: Run analysis ──────────────────────────────────────────
    try:
        risk, reason, details = analyze_url(url)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    # ── Step 3: Log forensic evidence ────────────────────────────────
    # Only log medium and high risk to avoid flooding DB with safe URLs
    # Log ALL scans (useful for monitoring & demo)
    log_incident(
    type_   = "URL",
    value   = url,
    risk    = risk,
    reason  = reason,
    details = details,
    score   = details.get("score", 0),
    action  = "blocked" if risk == "high"
             else "warned" if risk == "medium"
             else "logged"
    )

    # ── Step 4: Return decision to extension ─────────────────────────
    return jsonify({
        "url":     url,
        "risk":    risk,
        "reason":  reason,
        "details": details
    }), 200