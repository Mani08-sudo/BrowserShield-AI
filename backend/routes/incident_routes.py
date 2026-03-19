"""
incident_routes.py — Forensics Dashboard API
=============================================
GET     /api/incidents          — fetch all incidents
GET     /api/incidents/stats    — dashboard statistics
GET     /api/incidents/<id>     — single incident
DELETE  /api/incidents/<id>     — delete one incident
DELETE  /api/incidents          — clear all incidents
"""

from flask import Blueprint, jsonify, request
from backend.database.db import (
    get_incidents,
    get_incident_by_id,
    get_stats,
    delete_incident,
    clear_all_incidents
)

incident_bp = Blueprint("incident_bp", __name__)


# ─────────────────────────────────────────────
# GET INCIDENT LIST
# ─────────────────────────────────────────────
@incident_bp.route("/api/incidents", methods=["GET", "OPTIONS"])
def get_incidents_api():

    risk_filter = request.args.get("risk")
    type_filter = request.args.get("type")
    limit       = request.args.get("limit", 100, type=int)
    page        = request.args.get("page", 1, type=int)

    valid_risks = {"low", "medium", "high"}
    valid_types = {"URL", "EMAIL", "FILE"}

    if risk_filter and risk_filter.lower() not in valid_risks:
        return jsonify({"status":"error","error":"Invalid risk filter"}), 400

    if type_filter and type_filter.upper() not in valid_types:
        return jsonify({"status":"error","error":"Invalid type filter"}), 400

    limit  = max(1, min(limit, 500))
    page   = max(1, page)
    offset = (page - 1) * limit

    incidents = get_incidents(
        limit=limit,
        offset=offset,
        risk_filter=risk_filter,
        type_filter=type_filter
    )

    return jsonify({
        "status":"ok",
        "incidents":incidents,
        "count":len(incidents),
        "page":page,
        "limit":limit
    })


# ─────────────────────────────────────────────
# GET DASHBOARD STATS
# ─────────────────────────────────────────────
@incident_bp.route("/api/incidents/stats", methods=["GET", "OPTIONS"])
def get_stats_api():

    stats = get_stats()

    if not stats:
        return jsonify({"status":"error","error":"Stats unavailable"}), 500

    return jsonify({
        "status":"ok",
        "stats":stats
    })


# ─────────────────────────────────────────────
# GET SINGLE INCIDENT
# ─────────────────────────────────────────────
@incident_bp.route("/api/incidents/<int:incident_id>", methods=["GET", "OPTIONS"])
def get_incident_api(incident_id):

    incident = get_incident_by_id(incident_id)

    if not incident:
        return jsonify({"status":"error","error":"Incident not found"}), 404

    return jsonify({
        "status":"ok",
        "incident":incident
    })


# ─────────────────────────────────────────────
# DELETE SINGLE INCIDENT
# ─────────────────────────────────────────────
@incident_bp.route("/api/incidents/<int:incident_id>", methods=["DELETE", "OPTIONS"])
def delete_incident_api(incident_id):

    deleted = delete_incident(incident_id)

    if not deleted:
        return jsonify({
            "status":"error",
            "error":f"Incident {incident_id} not found"
        }), 404

    return jsonify({
        "status":"ok",
        "message":f"Incident {incident_id} deleted"
    })


# ─────────────────────────────────────────────
# DELETE ALL INCIDENTS
# ─────────────────────────────────────────────
@incident_bp.route("/api/incidents", methods=["DELETE", "OPTIONS"])
def clear_incidents_api():

    count = clear_all_incidents()

    return jsonify({
        "status":"ok",
        "message":f"All incidents cleared",
        "deleted":count
    })