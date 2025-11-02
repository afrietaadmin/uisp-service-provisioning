import logging
import os
from flask import Flask
from app.blueprints.provisioning import provisioning_blueprint


def create_app():
    """Factory method to create Flask app."""
    app = Flask(__name__)

    # Configure logging
    log_level = os.getenv("LOG_LEVEL", "info").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Register blueprints
    app.register_blueprint(provisioning_blueprint, url_prefix="/service_activations")

    # Healthcheck endpoint
    @app.route("/healthz", methods=["GET"])
    def healthz():
        return {"status": "ok"}, 200

    return app


# Allow running via python -m flask or gunicorn
app = create_app()
