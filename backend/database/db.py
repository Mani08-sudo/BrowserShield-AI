"""
db.py — Forensics Evidence Store
=================================
Handles all database operations for BrowserShield.
Every detected threat is stored here as forensic evidence.

Database location: backend/database/incidents.db
"""

import sqlite3
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  ABSOLUTE PATH — always saves in the right place
#  regardless of where you run the Flask app from
# ─────────────────────────────────────────────

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "backend", "database", "incidents.db")


def get_connection():
    """
    Returns a SQLite connection with:
    - Row factory so results come back as dicts, not plain tuples
    - Foreign keys enabled
    - WAL mode for better concurrent read performance
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row        # access columns by name: row["risk"]
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Creates all tables and indexes if they don't exist.
    Safe to call every time the server starts.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # ── Main incidents table ──────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER  PRIMARY KEY AUTOINCREMENT,
            type        TEXT     NOT NULL,          -- URL | EMAIL | FILE
            value       TEXT     NOT NULL,          -- the URL / subject / filename
            risk        TEXT     NOT NULL,          -- low | medium | high
            reason      TEXT,                       -- human-readable explanation
            details     TEXT,                       -- JSON: full analysis details
            score       INTEGER  DEFAULT 0,         -- numeric threat score
            action      TEXT     DEFAULT 'logged',  -- logged | warned | blocked
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Indexes for fast dashboard queries ───────────────────────────
    # Without indexes, every filter does a full table scan
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_timestamp
        ON incidents (timestamp DESC)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_risk
        ON incidents (risk)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_type
        ON incidents (type)
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at: {DB_PATH}")


# ─────────────────────────────────────────────
#  WRITE OPERATIONS
# ─────────────────────────────────────────────

def log_incident(type_, value, risk, reason, details=None, score=0, action="logged"):
    """
    Inserts a new forensic incident record.

    Args:
        type_   : "URL" | "EMAIL" | "FILE"
        value   : The actual URL, email subject, or filename
        risk    : "low" | "medium" | "high"
        reason  : Short human-readable explanation
        details : dict — full analysis output (stored as JSON string)
        score   : int  — numeric threat score from analysis
        action  : "logged" | "warned" | "blocked"

    Returns:
        int: ID of the newly created incident row
    """
    import json

    # Sanitize inputs — never log None values
    type_   = str(type_).upper().strip()  if type_   else "UNKNOWN"
    value   = str(value).strip()[:1000]  if value   else "(empty)"
    risk    = str(risk).lower().strip()   if risk    else "low"
    reason  = str(reason).strip()[:500]  if reason  else ""
    details = json.dumps(details)         if isinstance(details, dict) else None
    score   = int(score)                  if score   else 0
    action  = str(action).lower().strip() if action  else "logged"

    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (type, value, risk, reason, details, score, action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (type_, value, risk, reason, details, score, action))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()
        logger.info(f"Incident logged: [{risk.upper()}] {type_} — {value[:60]}")
        return new_id

    except Exception as e:
        logger.error(f"Failed to log incident: {e}")
        return None


# ─────────────────────────────────────────────
#  READ OPERATIONS
# ─────────────────────────────────────────────

def get_incidents(limit=100, offset=0, risk_filter=None, type_filter=None):
    """
    Fetches incidents for the forensics dashboard.

    Args:
        limit       : Max records to return (default 100 — prevents huge payloads)
        offset      : For pagination (page 2 = offset 100)
        risk_filter : "low" | "medium" | "high" | None (all)
        type_filter : "URL" | "EMAIL" | "FILE" | None (all)

    Returns:
        list of dicts
    """
    query  = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if risk_filter:
        query  += " AND risk = ?"
        params.append(risk_filter.lower())

    if type_filter:
        query  += " AND type = ?"
        params.append(type_filter.upper())

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    except Exception as e:
        logger.error(f"Failed to fetch incidents: {e}")
        return []


def get_incident_by_id(incident_id):
    """Fetches a single incident by ID."""
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Failed to fetch incident {incident_id}: {e}")
        return None


def get_stats():
    """
    Returns summary statistics for the dashboard.
    Counts incidents by risk level and type.

    Returns:
        dict with counts for charts and summary cards
    """
    try:
        conn   = get_connection()
        cursor = conn.cursor()

        # Total count
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total = cursor.fetchone()[0]

        # Count by risk level
        cursor.execute("""
            SELECT risk, COUNT(*) as count
            FROM incidents
            GROUP BY risk
        """)
        by_risk = {row["risk"]: row["count"] for row in cursor.fetchall()}

        # Count by type
        cursor.execute("""
            SELECT type, COUNT(*) as count
            FROM incidents
            GROUP BY type
        """)
        by_type = {row["type"]: row["count"] for row in cursor.fetchall()}

        # Last 24 hours count
        cursor.execute("""
            SELECT COUNT(*) FROM incidents
            WHERE timestamp >= datetime('now', '-24 hours')
        """)
        last_24h = cursor.fetchone()[0]

        # Most recent incident
        cursor.execute("""
            SELECT timestamp FROM incidents
            ORDER BY timestamp DESC LIMIT 1
        """)
        row = cursor.fetchone()
        last_seen = row["timestamp"] if row else None

        conn.close()

        return {
            "total":    total,
            "last_24h": last_24h,
            "last_seen":last_seen,
            "by_risk": {
                "high":   by_risk.get("high",   0),
                "medium": by_risk.get("medium", 0),
                "low":    by_risk.get("low",    0),
            },
            "by_type": {
                "URL":   by_type.get("URL",   0),
                "EMAIL": by_type.get("EMAIL", 0),
                "FILE":  by_type.get("FILE",  0),
            }
        }

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {}


def delete_incident(incident_id):
    """Deletes a single incident by ID. For dashboard management."""
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()
        return deleted
    except Exception as e:
        logger.error(f"Failed to delete incident {incident_id}: {e}")
        return False


def clear_all_incidents():
    """
    Clears all incidents. Use with caution —
    should require admin confirmation in the dashboard.
    """
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incidents")
        conn.commit()
        count = cursor.rowcount
        conn.close()
        logger.warning(f"All incidents cleared ({count} records deleted)")
        return count
    except Exception as e:
        logger.error(f"Failed to clear incidents: {e}")
        return 0