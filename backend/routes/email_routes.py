"""
email_routes.py — Email Analysis API Endpoint
==============================================
POST /api/analyze-email
Accepts email subject, sender, and body.
Runs AI + rule-based phishing analysis.
Logs the incident and returns risk decision.
"""

from flask import Blueprint, request, jsonify
from backend.analysis.email_analysis import analyze_email
from backend.database.db import log_incident


email_bp = Blueprint("email_bp", __name__)


@email_bp.route("/api/analyze-email", methods=["POST", "OPTIONS"])
def analyze_email_api():

    # ── Step 1: Parse and validate input ─────────────────────────────
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    subject = data.get("subject", "").strip()
    sender  = data.get("sender",  "").strip()
    body    = data.get("body",    "").strip()

    # At least subject or body must be present — can't analyze empty email
    if not subject and not body:
        return jsonify({"error": "At least one of 'subject' or 'body' is required"}), 400

    # Enforce size limits — prevents abuse and very slow analysis
    if len(body) > 50000:
        body = body[:50000]     # Truncate silently, don't reject

    # ── Step 2: Run phishing analysis ────────────────────────────────
    try:
        risk, reason, details = analyze_email(subject, sender, body)
    except Exception as e:
        return jsonify({"error": f"Email analysis failed: {str(e)}"}), 500

    # ── Step 3: Log forensic evidence ────────────────────────────────
    if risk in ("medium", "high"):
        log_incident(
            type_   = "EMAIL",
            value   = subject or "(no subject)",
            risk    = risk,
            reason  = reason,
            details = {
                **details,
                "sender": sender      # include sender in stored details
            },
            score   = details.get("rule_score", 0),
            action  = "warned"        # emails are always warned, never auto-blocked
        )

    # ── Step 4: Return decision ───────────────────────────────────────
    return jsonify({
        "risk":    risk,
        "reason":  reason,
        "details": details
    }), 200