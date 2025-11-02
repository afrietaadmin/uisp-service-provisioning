import requests
import json
import logging
import ipaddress

logger = logging.getLogger(__name__)


class MikroTikClient:
    """MikroTik REST API client for DHCP and queue management."""

    def __init__(self, api_url: str, username: str, password: str, verify: bool = False):
        self.api_url = api_url.rstrip("/")
        self.auth = (username, password)
        self.verify = verify
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = verify
        logger.debug(f"Initialized MikroTikClient for {self.api_url}")

    def _req(self, method: str, path: str, **kwargs):
        url = f"{self.api_url}/{path.lstrip('/')}"
        logger.debug(f"MikroTik {method} {url}")
        if 'json' in kwargs:
            logger.debug(f"Request payload: {kwargs['json']}")
        try:
            response = self.session.request(method, url, timeout=15, **kwargs)
            logger.debug(f"Response status: {response.status_code}")
            if response.text:
                logger.debug(f"Response body: {response.text}")
            response.raise_for_status()
            return response.json() if response.text else {}
        except Exception as e:
            logger.error(f"MikroTik API error ({url}): {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response body: {e.response.text}")
            raise RuntimeError(f"MikroTik operation failed: {e}")

    def get_used_ips(self, dhcp_range: str = None) -> set:
        """Get currently used IPs from DHCP leases within the specified range.

        Args:
            dhcp_range: Optional range to filter IPs. Supports:
                       - CIDR notation: 100.64.14.0/23
                       - Range notation: 100.64.14.20-100.65.15.254
        """
        try:
            leases = self._req("GET", "ip/dhcp-server/lease")
            used_ips = {lease.get("address") for lease in leases if "address" in lease}

            # Filter to only IPs within the specified range
            if dhcp_range:
                if '/' in dhcp_range:
                    # CIDR notation
                    network = ipaddress.IPv4Network(dhcp_range, strict=False)
                    used_ips = {ip for ip in used_ips
                               if ipaddress.IPv4Address(ip) in network}
                    logger.debug(f"Filtered used IPs within CIDR range {dhcp_range}: {used_ips}")
                elif '-' in dhcp_range:
                    # Range notation (e.g., 100.64.14.20-100.65.15.254)
                    start_str, end_str = dhcp_range.split('-')
                    start_ip = ipaddress.IPv4Address(start_str.strip())
                    end_ip = ipaddress.IPv4Address(end_str.strip())
                    used_ips = {ip for ip in used_ips
                               if start_ip <= ipaddress.IPv4Address(ip) <= end_ip}
                    logger.debug(f"Filtered used IPs within range {dhcp_range}: {used_ips}")

            return used_ips
        except Exception as e:
            logger.error(f"Error fetching DHCP leases: {e}")
            return set()

    def find_first_free_ip(self, dhcp_range: str, exclude_ip: str = None) -> str:
        """Find the first unused IP address within the DHCP range.

        Only searches for IPs within the specified DHCP range that are not currently in use.
        Ignores all IPs outside the range, even if they are used elsewhere.

        Supports both formats:
        - CIDR notation: 100.64.16.0/23
        - Range notation: 100.64.16.0-100.64.16.255

        Args:
            dhcp_range: The DHCP range to search within
            exclude_ip: Optional IP address to exclude (e.g., router IP)
        """
        try:
            # Get used IPs ONLY within the specified DHCP range
            used_ips = self.get_used_ips(dhcp_range=dhcp_range)

            # Add router IP to excluded IPs
            if exclude_ip:
                used_ips.add(exclude_ip)
                logger.info(f"Excluding router IP from available pool: {exclude_ip}")

            # Handle CIDR notation (e.g., 100.64.16.0/23)
            if '/' in dhcp_range:
                network = ipaddress.IPv4Network(dhcp_range, strict=False)
                # Skip network and broadcast addresses, start from .1
                start_ip = ipaddress.IPv4Address(int(network.network_address) + 1)
                end_ip = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
            # Handle range notation (e.g., 100.64.16.0-100.64.16.255)
            elif '-' in dhcp_range:
                start_ip_str, end_ip_str = dhcp_range.split('-')
                start_ip = ipaddress.IPv4Address(start_ip_str.strip())
                end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            else:
                raise ValueError(f"Invalid DHCP range format: {dhcp_range}. Use CIDR (e.g., 100.64.16.0/23) or range (e.g., 100.64.16.0-100.64.16.255)")

            logger.info(f"Searching for free IP in range {dhcp_range} ({start_ip} to {end_ip}), Used IPs in range: {used_ips}")

            for ip in range(int(start_ip), int(end_ip) + 1):
                ip_str = str(ipaddress.IPv4Address(ip))
                if ip_str not in used_ips:
                    logger.info(f"Found free IP: {ip_str} in range {dhcp_range}")
                    return ip_str

            raise ValueError(f"No free IPs found in the specified DHCP range {dhcp_range}")
        except Exception as e:
            logger.error(f"Error finding free IP: {e}")
            raise

    def create_dhcp_lease(self, ip_address: str, mac_address: str, comment: str) -> dict:
        """Create a new DHCP lease. Deletes any existing lease with the same MAC first."""
        try:
            # First, try to delete any existing lease with the same MAC address
            # This handles the case where a static lease already exists
            try:
                leases = self._req("GET", "ip/dhcp-server/lease")
                for lease in leases:
                    if lease.get("mac-address", "").upper() == mac_address.upper():
                        lease_id = lease.get(".id")
                        logger.info(f"Found existing lease with MAC {mac_address}, lease ID: {lease_id}. Deleting...")
                        self._req("DELETE", f"ip/dhcp-server/lease/{lease_id}")
                        logger.info(f"Deleted existing lease for MAC {mac_address}")
                        break
            except Exception as e:
                logger.warning(f"Could not check/delete existing leases: {e}. Continuing with creation...")

            lease_data = {
                "address": ip_address,
                "mac-address": mac_address,
                "comment": comment,
                "server": "Subscribers"
            }
            # Log the lease data for debugging
            logger.info(f"Creating DHCP lease with data: {lease_data}")
            result = self._req("POST", "ip/dhcp-server/lease/add", json=lease_data)
            logger.info(f"DHCP lease created for {ip_address} ({mac_address})")
            return result
        except Exception as e:
            logger.error(f"Error creating DHCP lease: {e}")
            raise

    def delete_dhcp_lease(self, target_ip: str) -> bool:
        """Delete a DHCP lease by IP address."""
        try:
            leases = self._req("GET", "ip/dhcp-server/lease")
            logger.debug(f"Found {len(leases)} DHCP leases, searching for IP {target_ip}")

            lease_id = None
            for lease in leases:
                address = lease.get("address")
                logger.debug(f"Checking lease: address={address}, id={lease.get('.id')}")
                if address == target_ip:
                    lease_id = lease.get(".id")
                    logger.info(f"Found lease ID {lease_id} for IP {target_ip}")
                    break

            if not lease_id:
                logger.warning(f"No DHCP lease found for IP {target_ip}")
                return False

            logger.debug(f"Deleting DHCP lease with ID: {lease_id}")
            self._req("DELETE", f"ip/dhcp-server/lease/{lease_id}")
            logger.info(f"DHCP lease deleted for {target_ip}")
            return True
        except Exception as e:
            logger.error(f"Error deleting DHCP lease: {e}")
            raise

    def create_queue(self, target_ip: str, name: str, upload_speed: int, download_speed: int) -> dict:
        """Create a traffic shaping queue."""
        try:
            queue_data = {
                "target": target_ip,
                "name": name,
                "comment": name,
                "max-limit": f"{upload_speed}M/{download_speed}M",
                "queue": "default/default"
            }
            logger.debug(f"Creating queue with data: {queue_data}")
            result = self._req("POST", "queue/simple/add", json=queue_data)
            logger.info(f"Queue created for {target_ip} ({upload_speed}M/{download_speed}M)")
            return result
        except Exception as e:
            logger.error(f"Error creating queue: {e}")
            raise

    def delete_queue(self, target_ip: str) -> bool:
        """Delete a queue by target IP."""
        try:
            queues = self._req("GET", "queue/simple")
            logger.debug(f"Found {len(queues)} queues, searching for target {target_ip}")

            queue_id = None
            for queue in queues:
                target = queue.get("target", "")
                # Handle both "100.64.12.99" and "100.64.12.99/32" formats
                queue_target = target.split('/')[0] if target else ""
                logger.debug(f"Checking queue: target={target}, queue_target={queue_target}, id={queue.get('.id')}")
                if queue_target == target_ip:
                    queue_id = queue.get(".id")
                    logger.info(f"Found queue ID {queue_id} for target {target_ip}")
                    break

            if not queue_id:
                logger.warning(f"No queue found for target IP {target_ip}")
                return False

            logger.debug(f"Deleting queue with ID: {queue_id}")
            self._req("DELETE", f"queue/simple/{queue_id}")
            logger.info(f"Queue deleted for {target_ip}")
            return True
        except Exception as e:
            logger.error(f"Error deleting queue: {e}")
            raise
