import logging
import hmac
import hashlib
from flask import Blueprint, request, jsonify
from app.core.config import load_config
from app.services.provisioning import handle_service_event

provisioning_blueprint = Blueprint("provisioning", __name__)


def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify UISP webhook signature using HMAC-SHA256."""
    if not signature or not secret:
        logging.warning("Webhook signature verification skipped: missing signature or secret")
        return True

    expected_signature = hmac.new(
        secret.encode(),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


@provisioning_blueprint.route("/", methods=["POST"])
def handle_provision():
    """Webhook endpoint for UISP service provisioning events."""

    # Verify webhook signature
    config = load_config()
    signature = request.headers.get("X-UISP-Signature", "")
    if not verify_webhook_signature(request.data, signature, config.uisp_app_key):
        logging.error("Webhook signature verification failed")
        return jsonify({"error": "Invalid webhook signature"}), 401

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    try:
        change_type = data.get("changeType")
        entity_type = data.get("entity")
        entity_id = data.get("entityId")
        event_name = data.get("eventName")
        extra_data = data.get("extraData", {})

        logging.info(
            f"Webhook received: changeType={change_type} entity={entity_type} "
            f"entityId={entity_id} eventName={event_name}"
        )

        # Handle the service event
        result = handle_service_event(change_type, entity_type, entity_id, extra_data)

        return jsonify(result), 200 if result.get("ok") else 202

    except Exception as e:
        logging.exception("Error handling provisioning webhook:")
        return jsonify({
            "detail": str(e),
            "note": "provisioning service error",
            "status": "error"
        }), 500
