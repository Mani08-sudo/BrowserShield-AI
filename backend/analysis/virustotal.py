"""
virustotal.py — NON-BLOCKING VirusTotal Reputation Intelligence
===============================================================

Design Goals:
• NEVER delay user browsing (no sleep / no waiting)
• NEVER spam VT API (quota safe)
• Treat unknown files as suspicious
• Act as reputation layer on top of rule-based detection

Security Model:
Rule Engine  → primary detection
VirusTotal   → reputation confirmation
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import hashlib
import logging
import time
import base64

import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

logger = logging.getLogger(__name__)

# Quota protection (FREE PLAN SAFE)
VT_COOLDOWN = 15  # seconds between requests
LAST_VT_CALL = 0


# ─────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────

def _is_configured():
    return VT_API_KEY and VT_API_KEY != "YOUR_KEY_HERE" and len(VT_API_KEY) > 10


def _rate_limit():
    """Prevent API ban"""
    global LAST_VT_CALL
    now = time.time()

    if now - LAST_VT_CALL < VT_COOLDOWN:
        return False

    LAST_VT_CALL = now
    return True


def _vt_get(endpoint):
    """Safe GET request (never throws)"""

    if not _is_configured():
        return None

    if not _rate_limit():
        logger.info("VT skipped (cooldown active)")
        return None

    try:
        req = urllib.request.Request(
            VT_BASE_URL + endpoint,
            headers={
                "x-apikey": VT_API_KEY,
                "Accept": "application/json"
            }
        )

        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())

    except urllib.error.HTTPError as e:
        if e.code in (404, 429):
            return None
        logger.warning(f"VT HTTP error {e.code}")
        return None

    except Exception:
        return None


# ─────────────────────────────────────────────
# Parse VT engine stats
# ─────────────────────────────────────────────

def _parse_stats(stats):

    if not stats:
        return None

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return None

    detection_rate = round(((malicious + suspicious) / total) * 100, 1)

    if malicious >= 5:
        risk = "high"
        verdict = f"{malicious} engines flagged malware"

    elif malicious >= 1 or suspicious >= 3:
        risk = "medium"
        verdict = f"{malicious} malicious / {suspicious} suspicious detections"

    else:
        risk = "low"
        verdict = f"{harmless} engines clean"

    return {
        "risk": risk,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "detection_rate": detection_rate
    }


# ─────────────────────────────────────────────
# URL reputation lookup (NON-BLOCKING)
# ─────────────────────────────────────────────

def check_url(url):
    """
    Only checks EXISTING VirusTotal reports.
    Does NOT submit URL (prevents delay & quota abuse)
    """

    if not _is_configured():
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report = _vt_get(f"/urls/{url_id}")

        if not report or "data" not in report:
            # Unknown reputation
            return {
                "risk": "medium",
                "verdict": "Unknown reputation (not scanned before)",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_engines": 0,
                "detection_rate": 0,
                "source": "unknown"
            }

        stats = report["data"]["attributes"]["last_analysis_stats"]
        result = _parse_stats(stats)

        if result:
            result["source"] = "cached"
            result["url"] = url

        return result

    except Exception:
        return None


# ─────────────────────────────────────────────
# FILE HASH reputation lookup
# ─────────────────────────────────────────────

def check_file_hash(file_path):

    if not _is_configured():
        return None

    try:
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)

        file_hash = sha256.hexdigest()

    except Exception:
        return None

    report = _vt_get(f"/files/{file_hash}")

    if not report or "data" not in report:
        # Unknown file → suspicious
        return {
            "risk": "medium",
            "verdict": "Unknown file (not in VT database)",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_engines": 0,
            "detection_rate": 0,
            "hash": file_hash,
            "known": False
        }

    stats = report["data"]["attributes"]["last_analysis_stats"]
    result = _parse_stats(stats)

    if result:
        result["hash"] = file_hash
        result["known"] = True

    return result