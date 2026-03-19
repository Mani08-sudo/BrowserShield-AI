"""
file_routes.py — File Analysis API Endpoint
============================================
POST /api/analyze-file
Accepts a filename (and optional file path), runs analysis + sandbox,
logs the incident, returns risk decision.
"""

import os
from flask import Blueprint, request, jsonify
from backend.analysis.file_analysis import analyze_file
from backend.analysis.sandbox import run_sandbox
from backend.database.db import log_incident


file_bp = Blueprint("file_bp", __name__)


@file_bp.route("/api/analyze-file", methods=["POST", "OPTIONS"])
def analyze_file_api():

    # ── Step 1: Parse and validate input ─────────────────────────────
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    file_name = data.get("file_name", "").strip()
    file_path = data.get("file_path", "").strip()   # optional full path

    if not file_name:
        return jsonify({"error": "Missing required field: file_name"}), 400

    if len(file_name) > 500:
        return jsonify({"error": "Filename too long (max 500 characters)"}), 400

    # ── Step 2: Run file extension + content analysis ─────────────────
    try:
        # Pass file_path for deep inspection if provided and exists
        safe_path = file_path if file_path and os.path.exists(file_path) else None
        risk, reason, details = analyze_file(file_name, file_path=safe_path)
    except Exception as e:
        return jsonify({"error": f"File analysis failed: {str(e)}"}), 500

    # ── Step 3: Run sandbox if file is high-risk executable ───────────
    sandbox_result = None

    if details.get("score", 0) >= 4 and safe_path:
        # File is suspicious AND we have the actual file — run sandbox
        try:
            sandbox_result = run_sandbox(safe_path, file_name=file_name)

            # Sandbox can upgrade or confirm the risk level
            if sandbox_result["verdict"] == "malicious":
                risk   = "high"
                reason = f"Sandbox: {sandbox_result['summary']}"
            elif sandbox_result["verdict"] == "suspicious" and risk == "low":
                risk   = "medium"
                reason = f"Sandbox: {sandbox_result['summary']}"

            # Merge sandbox findings into details
            details["sandbox"] = {
                "verdict":  sandbox_result["verdict"],
                "score":    sandbox_result["score"],
                "entropy":  sandbox_result["entropy"],
                "findings": sandbox_result["findings"][:5],   # top 5
                "summary":  sandbox_result["summary"]
            }

        except Exception as e:
            # Sandbox failure should not stop the response
            details["sandbox"] = {"error": str(e)}

    elif details.get("score", 0) >= 4 and not safe_path:
        # High-risk extension but no file to scan — flag it
        details["sandbox"] = {
            "verdict": "not_run",
            "reason":  "File path not provided for deep inspection"
        }

    # ── Step 4: Log forensic evidence ────────────────────────────────
    if risk in ("medium", "high"):
        log_incident(
            type_   = "FILE",
            value   = file_name,
            risk    = risk,
            reason  = reason,
            details = details,
            score   = details.get("score", 0),
            action  = "blocked" if risk == "high" else "warned"
        )

    # ── Step 5: Return decision ───────────────────────────────────────
    return jsonify({
        "file_name":     file_name,
        "risk":          risk,
        "reason":        reason,
        "details":       details,
        "sandbox_run":   sandbox_result is not None
    }), 200