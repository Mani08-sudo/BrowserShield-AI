"""
BrowserShield — URL Analysis Orchestrator
backend/analysis/url_analysis.py

Responsibility:
    Control the detection flow only.

Scoring logic   → backend/security/threat_engine.py
VirusTotal      → backend/analysis/virustotal.py
ML confidence   → passed in as parameter
"""

import re
from urllib.parse import urlparse

from backend.security.threat_engine import analyze_url_security
from backend.analysis.virustotal import check_url as vt_check


# ═══════════════════════════════════════════════════════════════
# PRIVATE NETWORK DETECTION
# ═══════════════════════════════════════════════════════════════

_LOCAL_PATTERNS = [
    r"^127\.",                      # loopback
    r"^localhost",
    r"^192\.168\.",                 # private class C
    r"^10\.",                       # private class A
    r"^172\.(1[6-9]|2\d|3[01])\.",  # private class B
]


def _is_local(url: str) -> bool:
    """Detect local / private network addresses."""
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        return any(re.match(p, host) for p in _LOCAL_PATTERNS)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# URL VALIDATION
# ═══════════════════════════════════════════════════════════════

def _valid_url(url: str) -> bool:
    """Basic URL sanity check."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc != ""
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# MAIN ANALYSIS
# ═══════════════════════════════════════════════════════════════

def analyze_url(url: str, ml_confidence: float = 0.0) -> dict:
    """
    Runs all detection layers and returns unified result.

    Parameters
    ----------
    url           : URL to analyze
    ml_confidence : ML phishing probability (0.0–1.0)

    Returns
    -------
    dict
        risk
        score
        reason
        vt_detections
        layers_used
    """

    # ── Normalize URL input ────────────────────────────────────
    url = url.strip()

    # ── Validate URL format ────────────────────────────────────
    if not _valid_url(url):
        return {
            "risk": "low",
            "score": 0,
            "reason": "Invalid URL format",
            "vt_detections": 0,
            "layers_used": [],
        }

    # ── Skip local / development URLs ──────────────────────────
    if _is_local(url):
        return {
            "risk": "low",
            "score": 0,
            "reason": "Local / private network URL — analysis skipped",
            "vt_detections": 0,
            "layers_used": [],
        }

    # Clamp ML confidence safely
    ml_confidence = max(0.0, min(ml_confidence, 1.0))

    vt_detections = 0
    layers_used = []

    # ── Layer 1: VirusTotal reputation check ───────────────────
    try:
        vt_result = vt_check(url)

        if vt_result:
            # handle multiple possible VT response formats
            vt_detections = int(
                vt_result.get("malicious")
                or vt_result.get("detection_rate")
                or vt_result.get("positives")
                or 0
            )

            layers_used.append("VirusTotal")

    except Exception as e:
        print(f"[WARNING] VirusTotal failed: {e}")

    # ── Layer 2: Heuristic + ML scoring engine ─────────────────
    result = analyze_url_security(
        url,
        vt_malicious=vt_detections,
        ml_confidence=ml_confidence,
    )

    layers_used.append("Heuristic Engine")

    if ml_confidence > 0:
        layers_used.append("ML Model")

    # ── Attach metadata ────────────────────────────────────────
    result["vt_detections"] = vt_detections
    result["layers_used"] = layers_used

    return result