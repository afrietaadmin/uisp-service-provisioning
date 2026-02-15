import logging
import hmac
import hashlib
import json
from flask import Blueprint, request, jsonify
from app.core.config import load_config
from app.services.provisioning import handle_service_event
from app.models.idempotency import IdempotencyStore

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
        webhook_uuid = data.get("uuid")
        extra_data = data.get("extraData", {})
        webhook_timestamp = data.get("timestamp")  # UISP may include timestamp
        webhook_change_time = data.get("changeTime")  # UISP may include changeTime

        logging.info(
            f"Webhook received: changeType={change_type} entity={entity_type} "
            f"entityId={entity_id} eventName={event_name} uuid={webhook_uuid}"
        )

        # Log all available fields for debugging
        logging.debug(f"Full webhook payload: {data}")

        # Check for duplicate webhook using idempotency store
        if webhook_uuid:
            idempotency_store = IdempotencyStore()
            if idempotency_store.is_duplicate(webhook_uuid):
                logging.warning(f"Duplicate webhook detected: {webhook_uuid} - returning 200 OK without processing")
                return jsonify({
                    "ok": True,
                    "message": "Webhook already processed",
                    "uuid": webhook_uuid,
                    "duplicate": True
                }), 200
        else:
            logging.warning("Webhook received without UUID - proceeding with caution (idempotency not guaranteed)")

        # Handle the service event
        result = handle_service_event(change_type, entity_type, entity_id, extra_data)

        # Mark webhook as processed in idempotency store
        if webhook_uuid:
            try:
                idempotency_store.mark_processed(
                    webhook_uuid,
                    entity_type,
                    str(entity_id),
                    change_type,
                    json.dumps(result)
                )
            except Exception as e:
                logging.error(f"Failed to mark webhook as processed: {e}")
                # Continue processing even if idempotency tracking fails

        return jsonify(result), 200 if result.get("ok") else 202

    except Exception as e:
        logging.exception("Error handling provisioning webhook:")
        return jsonify({
            "detail": str(e),
            "note": "provisioning service error",
            "status": "error"
        }), 500
