import logging
from app.core.config import load_config
from app.infra.telegram import TelegramNotifier
from app.infra.mikrotik import MikroTikClient
from app.infra.uisp import UISPClient, format_mac_address

logger = logging.getLogger(__name__)


def get_router_config(assigned_nas: str) -> dict:
    """Load router configuration from nas_config.json based on assigned NAS name."""
    import json
    import os

    config_path = os.getenv("NAS_CONFIG_PATH", "/etc/uisp/nas_config.json")
    try:
        logger.debug(f"Loading NAS config from: {config_path}")
        with open(config_path, 'r') as f:
            nas_config = json.load(f)

        logger.debug(f"Available NAS names: {list(nas_config.keys())}")
        logger.debug(f"Looking for NAS: {assigned_nas}")

        router = nas_config.get(assigned_nas)
        if not router:
            raise ValueError(f"No router found for NAS: {assigned_nas}")

        return router
    except Exception as e:
        logger.error(f"Error loading router config: {e}")
        raise


def provision_service(service_id: int, client_id: int, mac_address: str, assigned_nas: str,
                     service_identifier: str, upload_speed: int, download_speed: int,
                     tg: TelegramNotifier) -> dict:
    """Provision a service: create DHCP lease, queue, and update UISP."""
    cfg = load_config()

    try:
        # Format MAC address to standard format (xx:xx:xx:xx:xx:xx)
        formatted_mac = format_mac_address(mac_address)
        logger.info(f"Formatted MAC address: {mac_address} -> {formatted_mac}")
        tg.send(f"MAC address formatted: {mac_address} -> {formatted_mac}", level="info")

        # Initialize UISP client to fetch client details
        uisp = UISPClient(cfg.uisp_base_url, cfg.uisp_app_key)

        # Fetch client details from UISP to build proper service identifier
        logger.info(f"Fetching client details for client ID: {client_id}")
        client_data = uisp.get_client(client_id)
        company_name = client_data.get("companyName")
        first_name = client_data.get("firstName")
        last_name = client_data.get("lastName")
        logger.info(f"Client details: companyName={company_name}, firstName={first_name}, lastName={last_name}")

        # Build proper service identifier from client data
        final_service_identifier = uisp.build_service_identifier(client_id, service_id, client_data)
        logger.info(f"Built service identifier: {final_service_identifier}")
        tg.send(f"Service identifier generated: {final_service_identifier} | MAC: {formatted_mac}", level="info")

        # Get router configuration
        router_config = get_router_config(assigned_nas)
        api_url = router_config.get("api_url")
        username = router_config.get("username")
        password = router_config.get("password")
        dhcp_range = router_config.get("dhcp_range")
        router_ip = router_config.get("router_ip")

        if not all([api_url, username, password, dhcp_range, router_ip]):
            raise ValueError(f"Incomplete router configuration for NAS: {assigned_nas}")

        # Initialize MikroTik client
        mt = MikroTikClient(api_url, username, password)

        # Find free IP (excluding the router IP)
        logger.info(f"Searching for free IP in range {dhcp_range} (excluding router {router_ip})")
        free_ip = mt.find_first_free_ip(dhcp_range, exclude_ip=router_ip)
        logger.info(f"Allocated free IP: {free_ip} for Service {service_id} (MAC: {formatted_mac})")
        tg.send(f"Allocated IP {free_ip} from {dhcp_range} | Service: {final_service_identifier} | MAC: {formatted_mac}", level="info")

        # Create DHCP lease using the generated service identifier and formatted MAC
        try:
            mt.create_dhcp_lease(free_ip, formatted_mac, final_service_identifier)
            logger.info(f"DHCP lease created for {free_ip}")
            tg.send(f"DHCP lease created: {free_ip} | MAC: {formatted_mac}", level="info")
        except Exception as e:
            logger.error(f"DHCP lease creation failed for {free_ip}: {e}")
            tg.send(f"❌ DHCP lease creation failed for {free_ip}: {str(e)}", level="error")
            raise

        # Create queue on dedicated queue router (102.209.144.2) irrespective of assigned NAS
        queue_router_ip = "102.209.144.2"
        queue_router_api_url = f"https://{queue_router_ip}/rest"
        logger.info(f"Initializing MikroTik client for queue router: {queue_router_ip}")
        # Use same username/password from the assigned NAS config
        mt_queue = MikroTikClient(queue_router_api_url, username, password)

        # Create queue (traffic shaping) using the generated service identifier
        try:
            mt_queue.create_queue(free_ip, final_service_identifier, upload_speed, download_speed)
            logger.info(f"Queue created on {queue_router_ip}: {upload_speed}M/{download_speed}M")
            tg.send(f"Queue created on {queue_router_ip}: {upload_speed}M/{download_speed}M for {final_service_identifier} | MAC: {formatted_mac}", level="info")
        except Exception as e:
            logger.error(f"Queue creation failed on {queue_router_ip} for IP {free_ip}: {e}")
            logger.warning(f"Attempting to rollback DHCP lease for {free_ip} due to queue creation failure")
            tg.send(f"❌ Queue creation failed on {queue_router_ip} for {final_service_identifier}: {str(e)}", level="error")

            # Attempt rollback: delete the DHCP lease we just created
            try:
                mt.delete_dhcp_lease(free_ip)
                logger.info(f"DHCP lease rollback successful for {free_ip}")
                tg.send(f"⚠️ DHCP lease rolled back for {free_ip} due to queue failure", level="warn")
            except Exception as rollback_error:
                logger.error(f"DHCP lease rollback failed for {free_ip}: {rollback_error}")
                tg.send(f"⚠️ CRITICAL: Could not rollback DHCP lease for {free_ip}: {str(rollback_error)}", level="error")

            # Re-raise the queue creation error to fail the entire provisioning
            raise

        # Update UISP service attributes using the generated service identifier and formatted MAC
        try:
            uisp.update_service_provisioned(service_id, free_ip, final_service_identifier, formatted_mac)
            logger.info(f"UISP service {service_id} updated with IP {free_ip} and MAC {formatted_mac}")
            tg.send(f"UISP updated: Service {service_id} provisioned with IP {free_ip} | MAC: {formatted_mac}", level="info")
        except Exception as e:
            logger.error(f"UISP service update failed for {service_id}: {e}")
            logger.warning(f"Service {service_id} is provisioned on routers but UISP update failed. Manual cleanup may be needed.")
            tg.send(f"⚠️ UISP update failed for service {service_id}: {str(e)}", level="error")
            # Don't re-raise here - we've already provisioned on routers, so let it complete
            # but log the error prominently

        return {
            "ok": True,
            "message": f"Service provisioned successfully",
            "free_ip": free_ip,
            "service_identifier": final_service_identifier,
            "assigned_nas": assigned_nas
        }

    except Exception as e:
        logger.exception(f"Error provisioning service: {e}")
        tg.send(f"❌ Provisioning failed for {service_identifier}: {str(e)} | MAC: {mac_address}", level="error")
        raise


def deprovision_service(service_id: int, assigned_nas: str, target_ip: str,
                       service_identifier: str, tg: TelegramNotifier) -> dict:
    """Deprovision a service: delete DHCP lease, queue, and update UISP."""
    cfg = load_config()

    try:
        # Get router configuration
        router_config = get_router_config(assigned_nas)
        api_url = router_config.get("api_url")
        username = router_config.get("username")
        password = router_config.get("password")

        if not all([api_url, username, password]):
            raise ValueError(f"Incomplete router configuration for NAS: {assigned_nas}")

        # Initialize MikroTik client
        mt = MikroTikClient(api_url, username, password)

        # Delete DHCP lease from assigned NAS router
        logger.info(f"Attempting to delete DHCP lease for {target_ip}")
        try:
            lease_deleted = mt.delete_dhcp_lease(target_ip)
            if lease_deleted:
                logger.info(f"DHCP lease deleted for {target_ip}")
                tg.send(f"✅ DHCP lease deleted for {target_ip} ({service_identifier})", level="info")
            else:
                logger.warning(f"DHCP lease not found for {target_ip}, continuing with queue deletion")
                tg.send(f"⚠️ DHCP lease not found for {target_ip}, continuing...", level="warn")
        except Exception as e:
            logger.error(f"Error deleting DHCP lease for {target_ip}: {e}")
            tg.send(f"⚠️ Error deleting DHCP lease for {target_ip}: {str(e)}", level="error")
            lease_deleted = False
            # Continue to queue deletion attempt

        # Delete queue from dedicated queue router (102.209.144.2) irrespective of assigned NAS
        queue_router_ip = "102.209.144.2"
        queue_router_api_url = f"https://{queue_router_ip}/rest"
        logger.info(f"Initializing MikroTik client for queue router: {queue_router_ip}")
        # Use same username/password from the assigned NAS config
        mt_queue = MikroTikClient(queue_router_api_url, username, password)

        logger.info(f"Attempting to delete queue for {target_ip} from {queue_router_ip}")
        try:
            queue_deleted = mt_queue.delete_queue(target_ip)
            if queue_deleted:
                logger.info(f"Queue deleted for {target_ip}")
                tg.send(f"✅ Queue deleted for {target_ip} ({service_identifier})", level="info")
            else:
                logger.warning(f"Queue not found for {target_ip}, continuing with UISP update")
                tg.send(f"⚠️ Queue not found for {target_ip}, continuing...", level="warn")
        except Exception as e:
            logger.error(f"Error deleting queue for {target_ip} from {queue_router_ip}: {e}")
            tg.send(f"⚠️ Error deleting queue for {target_ip}: {str(e)}", level="error")
            queue_deleted = False
            # Continue to UISP update attempt

        # Update UISP service attributes
        logger.info(f"Updating UISP service {service_id}")
        uisp = UISPClient(cfg.uisp_base_url, cfg.uisp_app_key)
        uisp.update_service_deprovisioned(service_id)
        logger.info(f"UISP service {service_id} marked as deprovisioned")
        tg.send(f"✅ UISP updated: Service {service_id} deprovisioned ({service_identifier})", level="info")

        return {
            "ok": True,
            "message": f"Service deprovisioned successfully",
            "service_identifier": service_identifier,
            "target_ip": target_ip,
            "assigned_nas": assigned_nas,
            "lease_deleted": lease_deleted,
            "queue_deleted": queue_deleted
        }

    except Exception as e:
        logger.exception(f"Error deprovisioning service: {e}")
        tg.send(f"❌ Deprovisioning failed for {service_identifier}: {str(e)}", level="error")
        raise


def handle_service_event(change_type: str, entity_type: str, entity_id: str, extra_data: dict) -> dict:
    """
    Handle service provisioning events from UISP.

    Status codes:
    - 1: Active (provision)
    - 2: Suspended/Inactive (deprovision)

    Args:
        change_type: Type of change (create, edit, delete, etc.)
        entity_type: Type of entity (service, etc.)
        entity_id: ID of the entity
        extra_data: Extra data containing entity details

    Returns:
        Dictionary with operation result
    """
    cfg = load_config()
    tg = TelegramNotifier(cfg.telegram_token, cfg.telegram_chat_id)

    if entity_type != "service":
        msg = f"Unsupported entity type: {entity_type}"
        logger.warning(msg)
        return {"ok": False, "message": msg}

    try:
        entity = extra_data.get("entity", {})
        service_id = int(entity.get("id"))
        client_id = entity.get("clientId")
        service_name = entity.get("name")
        status = entity.get("status")
        attributes = entity.get("attributes", [])

        # Extract key attributes
        mac_address = next(
            (a.get("value") for a in attributes if a.get("key") == "macAddress"),
            "N/A"
        )
        service_identifier = next(
            (a.get("value") for a in attributes if a.get("key") == "serviceIdentifier"),
            None
        )
        assigned_nas = next(
            (a.get("value") for a in attributes if a.get("key") == "assignedNas"),
            None
        )
        ip_address = next(
            (a.get("value") for a in attributes if a.get("key") == "ipAddress"),
            None
        )
        provisioning_action = next(
            (a.get("value") for a in attributes if a.get("key") == "provisioningAction"),
            None
        )
        download_speed = entity.get("downloadSpeed", 0)
        upload_speed = entity.get("uploadSpeed", 0)

        logger.info(
            f"Service {change_type}: {service_name} "
            f"(ID: {service_id}, Client: {client_id}, Status: {status}, MAC: {mac_address}, ProvisioningAction: {provisioning_action})"
        )

        # Provision only if status is 1 (active)
        if status == 1:
            # Check provisioning action only for provisioning
            if provisioning_action != "NAS-Provision":
                logger.info(f"Service {service_id} provisioningAction is '{provisioning_action}' (not NAS-Provision), skipping provisioning")
                return {
                    "ok": True,
                    "message": "Request did not invoke any operation - informational only",
                    "service_id": service_id,
                    "status": status,
                    "provisioning_action": provisioning_action
                }

            if not all([assigned_nas, mac_address]):
                raise ValueError("Missing required attributes for provisioning (assignedNas, macAddress)")

            logger.info(f"Provisioning service {service_id}: {service_identifier} (status={status})")
            tg.send(f"🚀 Provisioning started: {service_name} (CID: {client_id}) | Status: Active | MAC: {mac_address}", level="info")

            result = provision_service(
                service_id, client_id, mac_address, assigned_nas, service_identifier,
                upload_speed, download_speed, tg
            )

            return {
                "ok": True,
                "message": result["message"],
                "service_id": service_id,
                "client_id": client_id,
                "status": status,
                "provisioning": result
            }

        # Deprovision only if status is 2 (ended) - no provisioning_action check needed
        elif status == 2:
            if not all([assigned_nas, ip_address, service_identifier]):
                logger.warning(f"Cannot deprovision: missing required attributes")
                tg.send(f"⚠️ Deprovision event received but missing info for {service_name} (CID: {client_id})", level="warn")
                return {
                    "ok": False,
                    "message": "Missing deprovisioning information",
                    "service_id": service_id,
                    "status": status
                }

            logger.info(f"Deprovisioning service {service_id}: {service_identifier} (status={status})")
            tg.send(f"🗑️ Deprovisioning: {service_name} (CID: {client_id}) | Status: Ended | MAC: {mac_address}", level="warn")

            result = deprovision_service(
                service_id, assigned_nas, ip_address, service_identifier, tg
            )

            return {
                "ok": True,
                "message": result["message"],
                "service_id": service_id,
                "client_id": client_id,
                "status": status,
                "deprovisioning": result
            }

        else:
            # Status is neither 1 nor 2, skip processing
            logger.warning(f"Service {service_id} has status {status}, skipping provisioning/deprovisioning")
            tg.send(f"⏭️ Service {service_name} (CID: {client_id}) status {status} - no action taken", level="info")
            return {
                "ok": True,
                "message": f"Service status {status} - no provisioning/deprovisioning action required",
                "service_id": service_id,
                "status": status,
                "action": "skipped"
            }

    except Exception as e:
        msg = f"Service event processing failed: {e}"
        logger.exception(msg)
        tg.send(f"❌ {msg}", level="error")
        return {"ok": False, "message": msg}
