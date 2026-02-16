import uuid
import requests
import logging

logger = logging.getLogger(__name__)


def format_mac_address(mac_address: str) -> str:
    """
    Format MAC address to standard format xx:xx:xx:xx:xx:xx.

    Handles various input formats:
    - xxxxxxxx (8 chars) -> xx:xx:xx:xx (assuming first 4 pairs needed, but formats full)
    - xxxxxxxxxxxx (12 chars) -> xx:xx:xx:xx:xx:xx
    - xx:xx:xx:xx:xx:xx (already formatted) -> returns as-is
    - xx-xx-xx-xx-xx-xx (dash separated) -> converts to colon separated

    Args:
        mac_address: MAC address in various formats

    Returns:
        Formatted MAC address as xx:xx:xx:xx:xx:xx
    """
    try:
        # Remove any existing separators (colons or dashes)
        clean_mac = mac_address.replace(":", "").replace("-", "").upper()

        # Validate length (should be 12 hex characters for 6 octets)
        if len(clean_mac) != 12:
            logger.warning(f"MAC address has unexpected length: {len(clean_mac)}. Expected 12 hex characters. Input: {mac_address}")
            # Still attempt to format if we have the right characters
            if len(clean_mac) < 12:
                # Pad with zeros if too short (unlikely but handle it)
                clean_mac = clean_mac.ljust(12, "0")
            elif len(clean_mac) > 12:
                # Truncate if too long
                clean_mac = clean_mac[:12]

        # Validate it's all hex characters
        try:
            int(clean_mac, 16)
        except ValueError:
            raise ValueError(f"MAC address contains non-hexadecimal characters: {mac_address}")

        # Format as xx:xx:xx:xx:xx:xx
        formatted = ":".join(clean_mac[i:i+2] for i in range(0, 12, 2))
        logger.debug(f"Formatted MAC address: {mac_address} -> {formatted}")
        return formatted

    except Exception as e:
        logger.error(f"Error formatting MAC address {mac_address}: {e}")
        raise ValueError(f"Invalid MAC address format: {mac_address}. Error: {e}")


class UISPClient:
    """UISP REST API client for service and client attribute updates."""

    def __init__(self, base_url: str, app_key: str):
        self.base_url = base_url.rstrip("/")
        self.app_key = app_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-Auth-App-Key": app_key,
            "Content-Type": "application/json"
        })
        logger.debug(f"Initialized UISPClient for {self.base_url}")

    def get_client(self, client_id: int) -> dict:
        """
        Fetch client details from UISP to get company name and contact info.

        Args:
            client_id: UISP client ID

        Returns:
            Client data dictionary with companyName, firstName, lastName, etc.
        """
        try:
            endpoint = f"clients/{client_id}"
            logger.info(f"Fetching client details for client ID: {client_id}")
            result = self._req("GET", endpoint)
            logger.debug(f"Client details retrieved: companyName={result.get('companyName')}")
            return result
        except Exception as e:
            logger.error(f"Error fetching client details: {e}")
            raise

    def build_service_identifier(self, client_id: int, service_id: int, client_data: dict = None) -> str:
        """
        Build service identifier in format: {clientId}_{name}_{serviceId}

        If client_data is provided, uses companyName (if available) or firstName+lastName.
        Otherwise, uses just client_id and service_id.

        Args:
            client_id: UISP client ID
            service_id: UISP service ID
            client_data: Optional client details dict from get_client()

        Returns:
            Service identifier string (e.g., "46_Afrieta_Pty_Ltd_2712")
        """
        try:
            if client_data:
                # Prefer company name, fall back to personal name
                if client_data.get("companyName"):
                    name_part = client_data["companyName"].replace(" ", "_")
                else:
                    first_name = client_data.get("firstName", "")
                    last_name = client_data.get("lastName", "")
                    name_part = f"{first_name}_{last_name}".replace(" ", "_")

                service_identifier = f"{client_id}_{name_part}_{service_id}"
                logger.info(f"Built service identifier: {service_identifier}")
                return service_identifier
            else:
                # Fallback if no client data provided
                service_identifier = f"{client_id}_{service_id}"
                logger.warning(f"Built service identifier without client data: {service_identifier}")
                return service_identifier
        except Exception as e:
            logger.error(f"Error building service identifier: {e}")
            raise

    def _req(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}/crm/api/v1.0/{endpoint.lstrip('/')}"
        logger.debug(f"UISP {method} {url}")
        if 'json' in kwargs:
            logger.debug(f"UISP request payload: {kwargs['json']}")
        try:
            response = self.session.request(method, url, timeout=15, **kwargs)
            logger.debug(f"UISP response status: {response.status_code}")
            response.raise_for_status()
            return response.json() if response.text else {}
        except Exception as e:
            logger.error(f"UISP API error ({url}): {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"UISP response body: {e.response.text}")
            raise RuntimeError(f"UISP operation failed: {e}")

    def update_service_attributes(self, service_id: int, attributes: list) -> dict:
        """
        Update service attributes in UISP.

        Args:
            service_id: Service ID
            attributes: List of attribute dicts with 'customAttributeId' and 'value'

        Returns:
            Updated service data
        """
        try:
            endpoint = f"clients/services/{service_id}"
            data = {"attributes": attributes}
            logger.info(f"Updating service {service_id} with attributes: {attributes}")
            logger.info(f"Full endpoint URL will be: {self.base_url}/crm/api/v1.0/{endpoint}")
            logger.info(f"Request method: PATCH")
            logger.info(f"Request payload: {data}")
            result = self._req("PATCH", endpoint, json=data)
            logger.info(f"Service {service_id} attributes updated")
            return result
        except Exception as e:
            logger.error(f"Error updating service attributes: {e}")
            raise

    def update_service_provisioned(self, service_id: int, ip_address: str, service_identifier: str, mac_address: str = None) -> dict:
        """
        Update service with provisioning details.

        Attributes:
        - 8: IP Address
        - 24: Service Identifier
        - 21: MAC Address (if provided)
        - 39: Provisioning Action (clear after successful provisioning)
        - 42: Send Welcome Message (set to 1 to trigger welcome message)
        """
        attributes = [
            {"value": ip_address, "customAttributeId": 8},
            {"value": service_identifier, "customAttributeId": 24},
            {"value": "", "customAttributeId": 39},  # Clear provisioning action
            {"value": "1", "customAttributeId": 42}  # Enable sending welcome message
        ]

        # Add MAC address if provided
        if mac_address:
            attributes.append({"value": mac_address, "customAttributeId": 21})
            logger.info(f"Including MAC address in UISP update: {mac_address}")

        try:
            return self.update_service_attributes(service_id, attributes)
        except Exception as e:
            # If MAC attribute causes validation error, try without it
            if "customAttributeId" in str(e) and "25" in str(e):
                logger.warning(f"MAC address attribute (ID 25) validation failed: {e}. Retrying without MAC attribute...")
                # Remove MAC attribute and retry
                attributes = [a for a in attributes if a.get("customAttributeId") != 25]
                return self.update_service_attributes(service_id, attributes)
            else:
                raise

    def update_service_deprovisioned(self, service_id: int) -> dict:
        """Mark service as deprovisioned by clearing provisioning attributes."""
        attributes = [
            {"value": "", "customAttributeId": 39}  # Mark as deprovisioned
        ]
        return self.update_service_attributes(service_id, attributes)

    def deregister_blackbox_devices(self, nms_auth_token: str, site_id: str,
                                     service_identifier: str) -> dict:
        """
        Remove blackbox devices from UISP NMS during deprovisioning.

        1. GET all devices at the site
        2. Delete devices where identification.hostname matches service_identifier
        3. Delete the site itself

        Args:
            nms_auth_token: x-auth-token for NMS API authentication
            site_id: unmsClientSiteId from the service entity
            service_identifier: Service identifier to match against hostname

        Returns:
            Dict with deletion results
        """
        headers = {"x-auth-token": nms_auth_token, "Content-Type": "application/json"}
        base_nms_url = f"{self.base_url}/nms/api/v2.1"

        # Step 1: Get all devices at the site
        try:
            response = requests.get(
                f"{base_nms_url}/devices",
                params={"siteId": site_id},
                headers=headers,
                timeout=15,
                verify=False
            )
            response.raise_for_status()
            devices = response.json() if response.text else []
        except Exception as e:
            logger.error(f"Failed to fetch devices for site {site_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"NMS response body: {e.response.text}")
            raise

        logger.info(f"Found {len(devices)} device(s) at site {site_id}")

        # Step 2: Delete devices where hostname matches service identifier
        deleted_devices = []
        skipped_devices = []

        for device in devices:
            identification = device.get("identification", {})
            device_id = identification.get("id")
            hostname = identification.get("hostname", "")
            device_name = identification.get("displayName", device_id)

            if hostname == service_identifier:
                try:
                    del_response = requests.delete(
                        f"{base_nms_url}/devices/{device_id}",
                        headers=headers,
                        timeout=15,
                        verify=False
                    )
                    del_response.raise_for_status()
                    deleted_devices.append(device_id)
                    logger.info(f"Deleted NMS device: {device_name} (id: {device_id})")
                except Exception as e:
                    logger.error(f"Failed to delete NMS device {device_name} (id: {device_id}): {e}")
                    if hasattr(e, 'response') and e.response is not None:
                        logger.error(f"NMS response body: {e.response.text}")
            else:
                skipped_devices.append({"id": device_id, "hostname": hostname})
                logger.warning(
                    f"Skipping NMS device {device_name} (id: {device_id}) - "
                    f"hostname '{hostname}' does not match service identifier '{service_identifier}'"
                )

        # Step 3: Delete the site
        site_deleted = False
        try:
            del_response = requests.delete(
                f"{base_nms_url}/sites/{site_id}",
                headers=headers,
                timeout=15,
                verify=False
            )
            del_response.raise_for_status()
            site_deleted = True
            logger.info(f"Deleted NMS site: {site_id}")
        except Exception as e:
            logger.error(f"Failed to delete NMS site {site_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"NMS response body: {e.response.text}")

        return {
            "devices_deleted": deleted_devices,
            "devices_skipped": skipped_devices,
            "site_deleted": site_deleted
        }

    def register_blackbox_device(self, nms_auth_token: str, site_id: str, hostname: str,
                                  ip_address: str, mac_address: str, router_serial: str) -> dict:
        """
        Register a device as a blackbox in UISP NMS after lease creation.

        Args:
            nms_auth_token: x-auth-token for NMS API authentication
            site_id: unmsClientSiteId from the service entity
            hostname: Service identifier (customAttributeId 24)
            ip_address: Allocated IP address
            mac_address: Device MAC address
            router_serial: Router serial number (customAttributeId 22)

        Returns:
            NMS API response dict
        """
        device_id = str(uuid.uuid4())
        payload = {
            "deviceId": device_id,
            "siteId": site_id,
            "hostname": hostname,
            "modelName": router_serial,
            "systemName": None,
            "vendorName": None,
            "ipAddress": ip_address,
            "macAddress": mac_address,
            "pingEnabled": False,
            "snmpCommunity": "public",
            "deviceRole": "router",
            "note": None,
            "interfaces": [
                {
                    "id": "eth1",
                    "name": "eth1",
                    "position": 1,
                    "mac": None,
                    "type": "eth",
                    "addresses": [
                        f"{ip_address}/32"
                    ]
                }
            ]
        }

        url = f"{self.base_url}/nms/api/v2.1/devices/blackboxes/config"
        logger.info(f"Registering blackbox device: {hostname} (IP: {ip_address}, siteId: {site_id})")
        logger.debug(f"Blackbox payload: {payload}")

        try:
            response = requests.post(
                url,
                json=payload,
                headers={"x-auth-token": nms_auth_token, "Content-Type": "application/json"},
                timeout=15,
                verify=False
            )
            response.raise_for_status()
            result = response.json() if response.text else {}
            logger.info(f"Blackbox device registered: {hostname} (deviceId: {device_id})")
            return result
        except Exception as e:
            logger.error(f"Failed to register blackbox device {hostname}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"NMS response body: {e.response.text}")
            raise
