"""
BrowserShield — URL Prediction Route
backend/routes/predict_url.py

Handles HTTP requests only.
Detection logic lives in url_analysis.py.
"""

from flask import Blueprint, request, jsonify
from urllib.parse import urlparse

from backend.analysis.url_analysis import analyze_url
from backend.database.db import log_incident   # match your db.py

predict_url_bp = Blueprint("predict_url", __name__)


# ═══════════════════════════════════════════════════════════════
# ACTION MAPPING
# ═══════════════════════════════════════════════════════════════

def _action(risk: str) -> str:
    """Convert risk level to extension action."""
    return {
        "high": "blocked",
        "medium": "warned",
        "low": "logged"
    }.get(risk, "logged")


# ═══════════════════════════════════════════════════════════════
# URL VALIDATION
# ═══════════════════════════════════════════════════════════════

def _valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc != ""
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# ROUTE
# ═══════════════════════════════════════════════════════════════

@predict_url_bp.route("/api/predict/url", methods=["POST"])
def predict_url():

    data = request.get_json(silent=True)

    # ── Validate request body ───────────────────────────────────
    if not data:
        return jsonify({
            "status": "error",
            "error": "Request body must be JSON"
        }), 400

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "error": "Missing field: url"
        }), 400

    if not _valid_url(url):
        return jsonify({
            "status": "error",
            "error": "Invalid URL format"
        }), 400

    # Prevent extremely large URLs
    if len(url) > 2000:
        return jsonify({
            "status": "error",
            "error": "URL too long"
        }), 400


    # ── ML confidence (optional) ────────────────────────────────
    try:
        ml_confidence = float(data.get("ml_confidence", 0.0))
        ml_confidence = max(0.0, min(ml_confidence, 1.0))
    except (ValueError, TypeError):
        ml_confidence = 0.0


    # ── Run analysis ────────────────────────────────────────────
    try:
        result = analyze_url(url, ml_confidence=ml_confidence)
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"Analysis failed: {str(e)}"
        }), 500


    # ── Save incident (non-blocking) ────────────────────────────
    try:
        log_incident(
          type_="URL",
          value=url,
          risk=result["risk"],
          reason=result["reason"],
          score=result["score"],
          action=_action(result["risk"]),
        )
    except Exception as e:
        print(f"[WARNING] Failed to save incident: {e}")


    # ── Response ────────────────────────────────────────────────
    return jsonify({
        "status": "ok",
        **result
    }), 200