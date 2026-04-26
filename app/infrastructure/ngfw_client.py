import httpx
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class NGFWClient:
    def __init__(self, base_url: str, verify_ssl: bool = False):
        self.base_url = self._normalize_url(base_url)
        self.client = httpx.AsyncClient(verify=verify_ssl, timeout=60.0)

    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip().rstrip('/')
        if not url.startswith(('http://', 'https://')):
            host_part = url.split(':')[0]
            if host_part in ('localhost', '127.0.0.1', '::1'):
                url = f'http://{url}'
            else:
                url = f'https://{url}'
        return url

    async def login(self, username: str, password: str):
        logger.info(f"Logging in to {self.base_url} as user: '{username}'")
        try:
            resp = await self.client.post(
                f"{self.base_url}/api/v2/Login",
                json={"login": username, "password": password}
            )
            if resp.status_code == 200:
                data = resp.json()
                # Try token-based auth first
                token = data.get('id') or data.get('token') or data.get('accessToken')
                if token:
                    self.token = token
                    self.client.headers.update({
                        "X-Auth-Token": self.token,
                        "Authorization": f"Bearer {self.token}"
                    })
                # Also capture cookies (gRPC-gateway may use cookie auth)
                if resp.cookies:
                    self.client.cookies.update(resp.cookies)
                # Capture cookie from grpc-metadata-set-cookie header
                grpc_cookie = resp.headers.get("grpc-metadata-set-cookie")
                if grpc_cookie:
                    cookie_part = grpc_cookie.split(";")[0]
                    if "=" in cookie_part:
                        k, v = cookie_part.split("=", 1)
                        self.client.cookies.set(k.strip(), v.strip())
                logger.info("Login successful")
                return
            logger.error(f"Login FAILED ({resp.status_code}). Response: {resp.text}")
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Login exception: {e}")
            raise

    async def update_rule_position(self, rule_id: str, new_position: int, device_group_id: str, precedence: str):
        url = f"{self.base_url}/api/v2/MoveSecurityRule"
        payload = {
            "id": rule_id,
            "position": new_position
        }
        query_params = {}
        if device_group_id and device_group_id != "global":
            query_params["deviceGroupId"] = device_group_id

        try:
            logger.info(f"Moving rule {rule_id} -> Pos {new_position}")
            resp = await self.client.post(url, json=payload, params=query_params)
            if resp.status_code == 200:
                return True
            logger.error(f"Move failed: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            logger.error(f"Error moving rule {rule_id}: {e}")
            return False

    async def create_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a security rule. Returns dict with 'id' of created rule."""
        url = f"{self.base_url}/api/v2/CreateSecurityRule"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            # API may return {id: ...} directly or wrapped in {rule: {id: ...}}
            if 'id' in data:
                return data
            if 'rule' in data and 'id' in data['rule']:
                return data['rule']
            return data
        logger.error(f"CreateSecurityRule failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def create_network_object(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a network object (host/subnet/range/fqdn). Returns dict with 'id'."""
        url = f"{self.base_url}/api/v2/CreateNetworkObject"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateNetworkObject failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def create_network_object_group(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a network object group. Payload: {name, deviceGroupId, items: [uuid, ...]}"""
        url = f"{self.base_url}/api/v2/CreateNetworkObjectGroup"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateNetworkObjectGroup failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def create_service(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a service object. Returns dict with 'id'."""
        url = f"{self.base_url}/api/v2/CreateService"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateService failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def create_service_group(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a service group. Payload: {name, deviceGroupId, serviceIds: [uuid, ...]}"""
        url = f"{self.base_url}/api/v2/CreateServiceGroup"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateServiceGroup failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def _post_list(self, endpoint_suffix: str, device_group_id: str = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/{endpoint_suffix}"
        payload = {"limit": 5000, "offset": 0}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id

        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                combined = []
                keys = [
                    'items', 'groups', 'services', 'serviceGroups', 'zones',
                    'applications', 'users', 'userGroups', 'networkGroups',
                    'networkObjects', 'serviceObjects', 'securityRules',
                    'addresses', 'ranges', 'fqdnAddresses', 'geoAddresses',
                    'urlCategories', 'ipsProfiles', 'antivirusProfiles', 'icapProfiles',
                ]
                for k in keys:
                    if k in data and isinstance(data[k], list):
                        combined.extend(data[k])
                return combined
            logger.warning(f"List {endpoint_suffix} returned {resp.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error fetching {endpoint_suffix}: {e}")
            return []

    async def update_rule(self, rule_id: str, payload: dict) -> dict:
        url = f"{self.base_url}/api/v2/UpdateSecurityRule"
        resp = await self.client.post(url, json={"id": rule_id, **payload})
        resp.raise_for_status()
        return resp.json()

    async def get_applications(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListApplications"
        payload: Dict[str, Any] = {"limit": 5000, "offset": 0}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json().get("applications", [])
        except Exception as e:
            logger.error(f"Error fetching applications: {e}")
        return []

    async def get_url_categories(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListURLCategories"
        payload: Dict[str, Any] = {"limit": 5000, "offset": 0}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json().get("urlCategories", [])
        except Exception as e:
            logger.error(f"Error fetching URL categories: {e}")
        return []

    async def get_ips_profiles(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        return await self._post_list("ListIPSProfiles", device_group_id)

    async def get_av_profiles(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        return await self._post_list("ListAntivirusProfiles", device_group_id)

    async def get_icap_profiles(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        return await self._post_list("ListICAPProfiles", device_group_id)

    async def get_objects(self, object_type: str, device_group_id: str = None) -> List[Dict[str, Any]]:
        mapping = {
            "Network": "ListNetworkObjects",
            "Network Group": "ListNetworkObjectGroups",
            "Service": "ListServices",
            "Service Group": "ListServiceGroups",
            "Zone": "ListZones",
            "Application": "ListApplications",
            "URL Category": "ListURLCategories",
            "User": "ListUsers",
            "User Group": "ListUserGroups",
        }
        endpoint = mapping.get(object_type)
        return await self._post_list(endpoint, device_group_id) if endpoint else []

    async def get_zones(self, device_group_id: str = None) -> List[Dict[str, Any]]:
        """Fetch all zones for a device group."""
        url = f"{self.base_url}/api/v2/ListZones"
        payload: Dict[str, Any] = {"limit": 5000, "offset": 0}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json().get('zones', [])
            return []
        except Exception as e:
            logger.error(f"Error fetching zones: {e}")
            return []

    async def get_device_groups(self) -> List[Dict[str, Any]]:
        return await self._post_list("ListDeviceGroups")

    async def get_rules(self, device_group_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListSecurityRules"
        all_rules = []
        for prec in ["pre", "post", "default"]:
            payload = {
                "limit": 5000,
                "offset": 0,
                "deviceGroupId": device_group_id,
                "precedence": prec
            }
            try:
                resp = await self.client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get('items', []) or data.get('securityRules', [])
                    for item in items:
                        item['fetched_precedence'] = prec
                    all_rules.extend(items)
            except Exception as e:
                logger.warning(f"Error fetching rules for precedence {prec}: {e}")
        return all_rules

    async def fetch_single_rule(self, ext_id: str, device_group_id: str, precedence: str = None) -> Optional[Dict[str, Any]]:
        """
        Fetch a single rule by its NGFW UUID.
        Tries the given precedence first; if not found falls back to all three.
        Returns the full SecurityRule dict or None.
        """
        precs = [precedence] if precedence else ["pre", "post", "default"]
        url = f"{self.base_url}/api/v2/ListSecurityRules"
        for prec in precs:
            payload = {"limit": 5000, "offset": 0, "deviceGroupId": device_group_id, "precedence": prec}
            try:
                resp = await self.client.post(url, json=payload)
                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        if item.get("id") == ext_id:
                            item["fetched_precedence"] = prec
                            return item
            except Exception as e:
                logger.warning(f"fetch_single_rule error (prec={prec}): {e}")
        logger.warning(f"fetch_single_rule: rule {ext_id} not found on device {device_group_id}")
        return None

    async def delete_rule(self, rule_id: str) -> bool:
        url = f"{self.base_url}/api/v2/DeleteSecurityRule"
        try:
            resp = await self.client.post(url, json={"id": rule_id})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to delete rule {rule_id}: {e}")
            return False

    # ------------------------------------------------------------------ NAT
    async def get_nat_rules(self, device_group_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListNatRules"
        all_rules = []
        for prec in ["pre", "post", "default"]:
            payload = {"limit": 5000, "offset": 0, "deviceGroupId": device_group_id, "precedence": prec}
            try:
                resp = await self.client.post(url, json=payload)
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    for item in items:
                        item["fetched_precedence"] = prec
                    all_rules.extend(items)
            except Exception as e:
                logger.warning(f"NAT rules fetch error (prec={prec}): {e}")
        return all_rules

    async def create_nat_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/CreateNatRule"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateNatRule failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    async def delete_nat_rule(self, rule_id: str) -> bool:
        url = f"{self.base_url}/api/v2/DeleteNatRule"
        try:
            resp = await self.client.post(url, json={"id": rule_id})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to delete NAT rule {rule_id}: {e}")
            return False

    async def move_nat_rule(self, rule_id: str, position: int) -> bool:
        url = f"{self.base_url}/api/v2/MoveNatRule"
        try:
            resp = await self.client.post(url, json={"id": rule_id, "position": position})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Error moving NAT rule {rule_id}: {e}")
            return False

    # ------------------------------------------------------------------ Logs & Stats

    async def list_log_collectors(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListLogCollectors"
        try:
            resp = await self.client.post(url, json={"limit": 100})
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                for c in items:
                    logger.info(f"LogCollector: id={c.get('id')} name={c.get('name')} state={c.get('connectionState')} addr={c.get('address')}")
                return items
            logger.warning(f"ListLogCollectors: {resp.status_code} {resp.text[:200]}")
            return []
        except Exception as e:
            logger.error(f"ListLogCollectors error: {e}")
            return []

    async def list_virtual_contexts(self, device_group_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListVirtualContexts"
        payload: Dict[str, Any] = {"limit": 100}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json().get("virtualContexts", [])
            logger.warning(f"ListVirtualContexts: {resp.status_code} {resp.text[:200]}")
            return []
        except Exception as e:
            logger.error(f"ListVirtualContexts error: {e}")
            return []

    async def get_log_collector_for_logical_device(self, logical_device_id: str) -> Optional[str]:
        url = f"{self.base_url}/api/v2/GetLogicalDeviceLogCollector"
        try:
            resp = await self.client.post(url, json={"logicalDeviceId": logical_device_id})
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                if items:
                    return items[0].get("id")
            return None
        except Exception as e:
            logger.error(f"GetLogicalDeviceLogCollector error: {e}")
            return None

    async def _search_logs(
        self,
        endpoint: str,
        time_from: str,
        time_to: str,
        log_collector_id: str = None,
        query_filters: List[Dict[str, Any]] = None,
        limit: int = 500,
        cursor: str = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/{endpoint}"
        payload: Dict[str, Any] = {
            "limit": limit,
            "timeRange": {"from": time_from, "to": time_to},
        }
        if log_collector_id:
            payload["logCollectorId"] = log_collector_id
        if query_filters:
            payload["query"] = query_filters
        if cursor:
            payload["cursor"] = cursor
        try:
            logger.info(f"{endpoint} REQUEST: {payload}")
            resp = await self.client.post(url, json=payload)

            # If all filters rejected as a batch, try accepted ones individually
            if resp.status_code == 400 and query_filters:
                logger.warning(f"{endpoint}: {resp.status_code} {resp.text[:200]}")
                if len(query_filters) > 1:
                    good = []
                    for f in query_filters:
                        test_payload = {**payload, "query": [f]}
                        test_payload.pop("cursor", None)  # cursor may not be valid without filter
                        tr = await self.client.post(url, json=test_payload)
                        if tr.status_code == 200:
                            good.append(f)
                            logger.info(f"{endpoint}: filter accepted: {f}")
                        else:
                            logger.warning(f"{endpoint}: filter rejected: {f}")
                    if good:
                        payload["query"] = good
                    else:
                        payload.pop("query", None)
                        logger.warning(f"{endpoint}: all filters rejected, retrying without any")
                    resp = await self.client.post(url, json=payload)
                else:
                    logger.warning(f"{endpoint}: single filter rejected, retrying without filters")
                    payload.pop("query", None)
                    resp = await self.client.post(url, json=payload)

            if resp.status_code == 200:
                data = resp.json()
                if data.get('logs'):
                    logger.info(f"{endpoint} FIRST LOG SAMPLE: {str(data['logs'][0])[:1000]}")
                else:
                    logger.info(f"{endpoint} RESPONSE: {resp.text[:300]}")
                return data
            logger.warning(f"{endpoint}: {resp.status_code} {resp.text[:300]}")
            return {}
        except Exception as e:
            logger.error(f"{endpoint} error: {e}")
            return {}

    async def fetch_all_logs(
        self,
        log_type: str,
        device_group_id: str,
        time_from: str = None,
        time_to: str = None,
        extra_filters: Dict[str, Any] = None,
        max_records: int = 10_000,
        batch_size: int = 500,
    ) -> List[Dict[str, Any]]:
        """Fetch log records using cursor-based + time-window pagination."""
        _ENDPOINTS = {
            'traffic': 'SearchTrafficLogs',
            'ips':     'SearchIPSLogs',
            'av':      'SearchAntivirusLogs',
            'audit':   'SearchAuditLogs',
        }
        endpoint = _ENDPOINTS.get(log_type)
        if not endpoint:
            raise ValueError(f"Unknown log_type: {log_type}")

        all_collectors: List[str] = []
        if log_type != 'audit':
            collectors = await self.list_log_collectors()
            all_collectors = [c.get('id') for c in collectors if c.get('id')]
        if not all_collectors:
            all_collectors = [None]

        # PT NGFW Filter.val is type:string that must contain valid JSON.
        # String fields (srcAddr/dstAddr/action): val = JSON string literal → json.dumps(str)
        # Integer fields (dstPort/srcPort): val = JSON number → json.dumps(int),
        #   but NGFW rejects it as "invalid value"; send as JSON string instead.
        # All ints are converted to strings so val is always a JSON string literal.
        query_filters: Optional[List[Dict[str, Any]]] = None
        if extra_filters:
            query_filters = [
                {"eq": {"key": k, "val": json.dumps(str(v) if isinstance(v, int) else v)}}
                for k, v in extra_filters.items()
            ]

        all_items: List[Dict[str, Any]] = []
        # Deduplication key: (timestamp, src, dst, dstPort, srcPort)
        seen_keys: set = set()

        for collector_id in all_collectors:
            if len(all_items) >= max_records:
                break

            current_time_to = time_to
            windows = 0

            while len(all_items) < max_records and windows < 20:
                windows += 1
                cursor: Optional[str] = None
                window_items: List[Dict[str, Any]] = []
                oldest_ts: Optional[str] = None

                # Cursor-based pagination within current time window
                while len(all_items) + len(window_items) < max_records:
                    limit = min(batch_size, max_records - len(all_items) - len(window_items))
                    raw = await self._search_logs(
                        endpoint         = endpoint,
                        time_from        = time_from,
                        time_to          = current_time_to,
                        log_collector_id = collector_id,
                        query_filters    = query_filters,
                        limit            = limit,
                        cursor           = cursor,
                    )
                    items = raw.get('logs', [])
                    if not items:
                        break

                    for item in items:
                        ts = item.get('entryGeneration') or item.get('entryReceived')
                        if ts and (oldest_ts is None or ts < oldest_ts):
                            oldest_ts = ts
                        key = (ts, item.get('srcAddr'), item.get('dstAddr'),
                               item.get('dstPort'), item.get('srcPort'))
                        if key not in seen_keys:
                            seen_keys.add(key)
                            window_items.append(item)

                    cursor = raw.get('nextCursor') or None
                    if not cursor:
                        break

                if window_items:
                    logger.info(f"Got {len(window_items)} logs from collector {collector_id} (window to={current_time_to})")
                    all_items.extend(window_items)

                    # Slide time window backward if batch was full and more records needed
                    if (len(window_items) >= batch_size
                            and oldest_ts
                            and time_from
                            and oldest_ts > time_from
                            and len(all_items) < max_records):
                        current_time_to = oldest_ts
                        continue

                break  # no data or window exhausted

            if all_items:
                break  # got data from this collector, skip others
            logger.info(f"Collector {collector_id} returned 0 logs, trying next...")

        return all_items

    async def get_rule_stats(self, device_group_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/ListMetricsRulesStats"
        try:
            resp = await self.client.post(url, json={"deviceGroupId": device_group_id})
            if resp.status_code == 200:
                data = resp.json()
                for key in ("items", "stats", "rulesStats"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
            return []
        except Exception as e:
            logger.error(f"ListMetricsRulesStats error: {e}")
            return []

    # ------------------------------------------------------------------ Object CRUD
    _DELETE_ENDPOINT_MAP = {
        'Host/Network':  'DeleteNetworkObject',
        'Network':       'DeleteNetworkObject',
        'Network Group': 'DeleteNetworkObjectGroup',
        'Service':       'DeleteService',
        'Service Group': 'DeleteServiceGroup',
        'Security Zone': 'DeleteZone',
        'Zone':          'DeleteZone',
    }

    async def delete_object(self, obj_type: str, obj_id: str) -> bool:
        endpoint = self._DELETE_ENDPOINT_MAP.get(obj_type)
        if not endpoint:
            logger.warning(f"No delete endpoint for type '{obj_type}'")
            return False
        url = f"{self.base_url}/api/v2/{endpoint}"
        try:
            resp = await self.client.post(url, json={"id": obj_id})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Delete {endpoint} {obj_id} failed: {e}")
            return False

    async def create_zone(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/CreateZone"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"CreateZone failed: {resp.status_code} {resp.text[:500]}")
        resp.raise_for_status()

    # ------------------------------------------------------------------ Generic rule helpers

    async def _list_rules(self, endpoint: str, device_group_id: str, result_keys: List[str]) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/{endpoint}"
        payload: Dict[str, Any] = {"limit": 5000, "offset": 0}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                for key in result_keys + ["items", "rules"]:
                    if key in data and isinstance(data[key], list):
                        return data[key]
            logger.warning(f"{endpoint} returned {resp.status_code}")
            return []
        except Exception as e:
            logger.error(f"{endpoint} error: {e}")
            return []

    async def _create_rule_generic(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/{endpoint}"
        resp = await self.client.post(url, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            if "id" in data:
                return data
            if "rule" in data and isinstance(data["rule"], dict):
                return data["rule"]
            return data
        logger.error(f"{endpoint} failed: {resp.status_code} {resp.text[:300]}")
        resp.raise_for_status()

    async def _delete_rule_generic(self, endpoint: str, rule_id: str) -> bool:
        url = f"{self.base_url}/api/v2/{endpoint}"
        try:
            resp = await self.client.post(url, json={"id": rule_id})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"{endpoint} delete {rule_id} failed: {e}")
            return False

    async def _move_rule_generic(self, endpoint: str, rule_id: str, position: int) -> bool:
        url = f"{self.base_url}/api/v2/{endpoint}"
        try:
            resp = await self.client.post(url, json={"id": rule_id, "position": position})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"{endpoint} move {rule_id} failed: {e}")
            return False

    async def _toggle_rule_generic(self, endpoint: str, rule_id: str, enabled: bool) -> bool:
        url = f"{self.base_url}/api/v2/{endpoint}"
        try:
            resp = await self.client.post(url, json={"id": rule_id, "enabled": enabled})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"{endpoint} toggle {rule_id} failed: {e}")
            return False

    # ---- Decryption Rules ----

    async def list_decryption_rules(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListDecryptionRules", device_group_id, ["decryptionRules"])

    async def create_decryption_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._create_rule_generic("CreateDecryptionRule", payload)

    async def delete_decryption_rule(self, rule_id: str) -> bool:
        return await self._delete_rule_generic("DeleteDecryptionRule", rule_id)

    async def move_decryption_rule(self, rule_id: str, position: int) -> bool:
        return await self._move_rule_generic("MoveDecryptionRule", rule_id, position)

    async def toggle_decryption_rule(self, rule_id: str, enabled: bool) -> bool:
        return await self._toggle_rule_generic("UpdateDecryptionRule", rule_id, enabled)

    # ---- Authentication Rules ----

    async def list_auth_rules(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListAuthenticationRules", device_group_id, ["authenticationRules"])

    async def create_auth_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._create_rule_generic("CreateAuthenticationRule", payload)

    async def delete_auth_rule(self, rule_id: str) -> bool:
        return await self._delete_rule_generic("DeleteAuthenticationRule", rule_id)

    async def move_auth_rule(self, rule_id: str, position: int) -> bool:
        return await self._move_rule_generic("MoveAuthenticationRule", rule_id, position)

    async def toggle_auth_rule(self, rule_id: str, enabled: bool) -> bool:
        return await self._toggle_rule_generic("UpdateAuthenticationRule", rule_id, enabled)

    # ---- PBR Rules ----

    async def list_pbr_rules(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListPBRRules", device_group_id, ["pbrRules", "pbr"])

    async def create_pbr_rule(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._create_rule_generic("CreatePBRRule", payload)

    async def delete_pbr_rule(self, rule_id: str) -> bool:
        return await self._delete_rule_generic("DeletePBRRule", rule_id)

    async def move_pbr_rule(self, rule_id: str, position: int) -> bool:
        return await self._move_rule_generic("MovePBRRule", rule_id, position)

    async def toggle_pbr_rule(self, rule_id: str, enabled: bool) -> bool:
        return await self._toggle_rule_generic("UpdatePBRRule", rule_id, enabled)

    # ------------------------------------------------------------------ Admins

    async def list_admins(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListAdmins", device_group_id, ["admins", "administrators"])

    async def create_admin(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._create_rule_generic("CreateAdmin", payload)

    async def delete_admin(self, admin_id: str) -> bool:
        return await self._delete_rule_generic("DeleteAdmin", admin_id)

    async def block_admin(self, admin_id: str) -> bool:
        url = f"{self.base_url}/api/v2/BlockAdmin"
        try:
            resp = await self.client.post(url, json={"id": admin_id})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"BlockAdmin {admin_id}: {e}")
            return False

    async def unblock_admin(self, admin_id: str) -> bool:
        url = f"{self.base_url}/api/v2/UnblockAdmin"
        try:
            resp = await self.client.post(url, json={"id": admin_id})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"UnblockAdmin {admin_id}: {e}")
            return False

    async def update_admin_credentials(self, admin_id: str, payload: Dict[str, Any]) -> bool:
        url = f"{self.base_url}/api/v2/UpdateAdminCredentials"
        try:
            resp = await self.client.post(url, json={"id": admin_id, **payload})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"UpdateAdminCredentials {admin_id}: {e}")
            return False

    # ------------------------------------------------------------------ Backup & Snapshot

    async def list_backups(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListBackups", device_group_id, ["backups"])

    async def create_backup(self, device_group_id: str, description: str = "") -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/CreateBackup"
        payload: Dict[str, Any] = {}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        if description:
            payload["description"] = description
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json()
            logger.error(f"CreateBackup failed: {resp.status_code} {resp.text[:300]}")
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"CreateBackup error: {e}")
            raise

    async def delete_backup(self, backup_id: str) -> bool:
        return await self._delete_rule_generic("DeleteBackups", backup_id)

    async def list_snapshots(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListSnapshots", device_group_id, ["snapshots"])

    async def commit_snapshot(self, device_group_id: str, description: str = "") -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/CommitSnapshot"
        payload: Dict[str, Any] = {}
        if device_group_id and device_group_id != "global":
            payload["deviceGroupId"] = device_group_id
        if description:
            payload["description"] = description
        try:
            resp = await self.client.post(url, json=payload)
            if resp.status_code == 200:
                return resp.json()
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"CommitSnapshot error: {e}")
            raise

    async def restore_backup(self, backup_id: str) -> bool:
        url = f"{self.base_url}/api/v2/RestoreBackup"
        try:
            resp = await self.client.post(url, json={"id": backup_id})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"RestoreBackup {backup_id}: {e}")
            return False

    # ------------------------------------------------------------------ Static Routes

    async def list_static_routes(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListStaticRoutes", device_group_id, ["routes", "staticRoutes"])

    async def create_static_route(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._create_rule_generic("CreateStaticRoute", payload)

    async def delete_static_route(self, route_id: str) -> bool:
        return await self._delete_rule_generic("DeleteStaticRoute", route_id)

    # ------------------------------------------------------------------ BGP / OSPF (read-only)

    async def get_bgp(self, device_group_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/GetBGP"
        try:
            resp = await self.client.post(url, json={"deviceGroupId": device_group_id})
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error(f"GetBGP error: {e}")
            return {}

    async def list_bgp_peers(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListBGPPeers", device_group_id, ["peers", "bgpPeers"])

    async def get_ospf(self, device_group_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/GetOSPF"
        try:
            resp = await self.client.post(url, json={"deviceGroupId": device_group_id})
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error(f"GetOSPF error: {e}")
            return {}

    async def list_ospf_areas(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListOSPFAreas", device_group_id, ["areas", "ospfAreas"])

    # ------------------------------------------------------------------ Virtual Interfaces

    async def list_virtual_interfaces(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListVirtualInterfaces", device_group_id, ["interfaces", "virtualInterfaces"])

    async def list_logical_interfaces(self, device_group_id: str) -> List[Dict[str, Any]]:
        return await self._list_rules("ListLogicalInterfaces", device_group_id, ["interfaces", "logicalInterfaces"])

    # ------------------------------------------------------------------ Session Timeouts

    async def get_device_timeouts(self, device_group_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/GetDeviceTimeouts"
        try:
            resp = await self.client.post(url, json={"deviceGroupId": device_group_id})
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error(f"GetDeviceTimeouts error: {e}")
            return {}

    async def set_device_timeouts(self, device_group_id: str, payload: Dict[str, Any]) -> bool:
        url = f"{self.base_url}/api/v2/SetDeviceTimeouts"
        try:
            resp = await self.client.post(url, json={"deviceGroupId": device_group_id, **payload})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"SetDeviceTimeouts error: {e}")
            return False

    async def close(self):
        await self.client.aclose()
