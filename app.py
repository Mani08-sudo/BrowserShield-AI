"""
app.py — BrowserShield Flask Application Entry Point
=====================================================
Creates the Flask server and connects extension + dashboard + database
"""

import os
import logging
from flask import Flask, render_template, jsonify

# IMPORTANT — correct package import
from backend.database.db import init_db

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("browsershield.log"),
    ]
)
logger = logging.getLogger(__name__)
logger.info("Threat analysis engine loaded")



# ─────────────────────────────────────────────
# APP FACTORY
# ─────────────────────────────────────────────

def create_app():

    # Tell Flask where templates exist
    app = Flask(__name__, template_folder="backend/templates")

    app.config["DEBUG"] = False
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

    # ── CORS (allow Chrome extension) ─────────────────────────────
    try:
        from flask_cors import CORS
        CORS(app, resources={r"/api/*": {"origins": "*"}})
        logger.info("CORS enabled using flask-cors")
    except ImportError:
        logger.warning("flask-cors not installed — using manual headers")

        CORS_HEADERS = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Accept, Origin",
        }

        @app.after_request
        def add_headers(response):
            for k, v in CORS_HEADERS.items():
                response.headers[k] = v
            return response

        @app.before_request
        def handle_options():
            from flask import request, Response
            if request.method == "OPTIONS":
                res = Response(status=200)
                for k, v in CORS_HEADERS.items():
                    res.headers[k] = v
                return res

    # ── Register Blueprints ─────────────────────────────────────────

    from backend.routes.url_routes import url_bp
    from backend.routes.file_routes import file_bp
    from backend.routes.email_routes import email_bp
    from backend.routes.incident_routes import incident_bp
    from backend.routes.predict_url import predict_url_bp

    app.register_blueprint(url_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(predict_url_bp)


    logger.info("All blueprints registered")

    # ── Dashboard Route ─────────────────────────────────────────────

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    # ── Health Check ────────────────────────────────────────────────

    @app.route("/")
    def home():
        return jsonify({
            "status": "BrowserShield backend is running",
            "version": "1.0.0"
        })

    # ── Error Handlers ──────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"error": "Internal server error"}), 500

    return app


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":

    logger.info("Initializing database...")
    init_db()
    logger.info("Database ready")

    app = create_app()

    # IMPORTANT — use localhost for extension communication
    HOST = "127.0.0.1"
    PORT = 5000

    logger.info(f"Starting BrowserShield backend on http://{HOST}:{PORT}")
    logger.info(f"Dashboard: http://{HOST}:{PORT}/dashboard")

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False
    )
