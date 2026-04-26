"""
TransferService: copies/moves a security rule from one device group to another
within the same NGFW management system.

Algorithm for each rule transfer:
1. Load source rule from local DB cache (full SecurityRule JSON).
2. Build a "target object cache" — all existing net/service/zone objects on the target device.
3. For every object reference in source rule fields (sourceAddr, destinationAddr, service):
   a. Global objects → reuse UUID as-is.
   b. Local objects → look up in target cache by fingerprint (value/protocol+ports).
      - Found  → use target UUID.
      - Not found → clone the object on the target device, generate unique name.
4. For zone references (sourceZone, destinationZone):
   - Match by zone name on the target device.
   - Not found → fall back to ANY (zones are infrastructure, cannot be created via API).
5. Build CreateSecurityRuleRequest with resolved UUIDs and send to API.
6. On success, store new rule in local DB under the target folder.
"""

import copy
import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import CachedObject, CachedRule, Folder
from app.infrastructure.ngfw_client import NGFWClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers: extract UUIDs from SecurityRule field objects
# ---------------------------------------------------------------------------

def _extract_ids_from_rule_field(field: Optional[Dict]) -> Tuple[str, List[str]]:
    """
    Parse a SecurityRule field (sourceAddr, service, sourceZone, etc.) and
    return (kind, [uuid1, uuid2, ...]).

    SecurityRule format:
      sourceAddr  → RuleFieldNetwork  → objects: [NetworkObject, ...]
        NetworkObject = {networkIpAddress: {id, name, ...}} | {networkGroup: ...} | ...
      sourceZone  → RuleFieldZone     → objects: [ObjectZone, ...]
        ObjectZone = {id, name, deviceGroupId, ...}  ← direct (not wrapped!)
      service     → RuleFieldService  → objects: [ServiceItem, ...]
        ServiceItem = {service: {id, ...}} | {serviceGroup: {id, ...}}  ← wrapped
    """
    if not field or not isinstance(field, dict):
        return "RULE_KIND_ANY", []

    kind = field.get("kind", "RULE_KIND_ANY")
    if "ANY" in kind:
        return kind, []

    objects_raw = field.get("objects", [])
    if isinstance(objects_raw, dict):
        objects = objects_raw.get("array", [])
    elif isinstance(objects_raw, list):
        objects = objects_raw
    else:
        return kind, []

    ids = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        # Try direct id (ObjectZone format)
        direct_id = obj.get("id")
        if direct_id:
            ids.append(direct_id)
            continue
        # Try wrapped format: {someKey: {id: ..., ...}}
        for k, v in obj.items():
            if isinstance(v, dict) and "id" in v:
                ids.append(v["id"])
                break

    return kind, ids


def _make_any_field(user: bool = False) -> Dict:
    if user:
        return {"kind": "RULE_USER_KIND_ANY", "objects": {"array": []}}
    return {"kind": "RULE_KIND_ANY", "objects": {"array": []}}


def _make_list_field(ids: List[str], user: bool = False) -> Dict:
    if not ids:
        return _make_any_field(user=user)
    kind = "RULE_USER_KIND_LIST" if user else "RULE_KIND_LIST"
    return {"kind": kind, "objects": {"array": ids}}


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

def _service_ports_fingerprint(ports_list: Any) -> str:
    """Canonical string from dstPorts/srcPorts list."""
    if not ports_list or not isinstance(ports_list, list):
        return ""
    parts = []
    for p in ports_list:
        if not isinstance(p, dict):
            parts.append(str(p))
            continue
        if "singlePort" in p:
            sp = p["singlePort"]
            parts.append(str(sp.get("port", sp)))
        elif "portRange" in p:
            pr = p["portRange"]
            parts.append(f"{pr.get('from', pr.get('start', ''))}-{pr.get('to', pr.get('end', ''))}")
        else:
            parts.append(str(p))
    return ",".join(sorted(parts))


def _get_fingerprint(data: Dict) -> Optional[str]:
    """
    Generate a value-based fingerprint for a network or service object.
    Works on both CachedObject.data and raw API item dicts.
    """
    if not data:
        return None

    # --- Network objects ---
    # CachedObject.data stores extracted 'value' or 'inet'
    val = data.get("value") or data.get("inet")
    if val:
        return f"net:{str(val).strip()}"

    # FQDN
    fqdn = data.get("fqdn")
    if fqdn:
        return f"fqdn:{str(fqdn).strip().lower()}"

    # IP range
    start = data.get("start") or data.get("startIp") or data.get("from")
    end = data.get("end") or data.get("endIp") or data.get("to")
    if start and end:
        return f"range:{start}-{end}"

    # --- Service objects ---
    protocol = data.get("protocol")
    if protocol is not None:
        dst_ports = data.get("dstPorts") or data.get("destinationPorts") or data.get("port")
        src_ports = data.get("srcPorts") or data.get("sourcePorts")
        dst_str = _service_ports_fingerprint(dst_ports) if isinstance(dst_ports, list) else str(dst_ports or "")
        src_str = _service_ports_fingerprint(src_ports) if isinstance(src_ports, list) else ""
        return f"svc:{protocol}:dst={dst_str}:src={src_str}"

    # --- Also try _raw_debug ---
    raw = data.get("_raw_debug")
    if raw and isinstance(raw, dict):
        return _get_fingerprint({k: v for k, v in raw.items() if k != "_raw_debug"})

    return None


# ---------------------------------------------------------------------------
# Payload builders for object creation
# ---------------------------------------------------------------------------

def _build_network_object_create_payload(src_obj: CachedObject, target_name: str, target_gid: str) -> Dict:
    """Build CreateNetworkObjectRequest payload from a cached network object."""
    data = src_obj.data or {}
    raw = data.get("_raw_debug") or {}

    # Try to determine the value from raw or extracted data
    inet_val = raw.get("inet") or data.get("inet") or data.get("value")
    fqdn_val = raw.get("fqdn") or data.get("fqdn")
    start = raw.get("startIp") or raw.get("start") or data.get("start")
    end = raw.get("endIp") or raw.get("end") or data.get("end")

    if inet_val:
        value = {"inet": {"inet": str(inet_val)}}
    elif fqdn_val:
        value = {"fqdn": str(fqdn_val)}
    elif start and end:
        value = {"ipRange": {"start": str(start), "end": str(end)}}
    else:
        raise ValueError(f"Cannot determine network value for object '{src_obj.name}'")

    payload = {
        "name": target_name,
        "deviceGroupId": target_gid,
        "value": value,
    }
    desc = raw.get("description") or data.get("description")
    if desc:
        payload["description"] = desc
    return payload


def _build_service_create_payload(src_obj: CachedObject, target_name: str, target_gid: str) -> Dict:
    """Build CreateServiceRequest payload from a cached service object."""
    data = src_obj.data or {}
    raw = data.get("_raw_debug") or {}

    protocol = raw.get("protocol") or data.get("protocol")
    if protocol is None:
        raise ValueError(f"Cannot determine protocol for service '{src_obj.name}'")

    payload: Dict[str, Any] = {
        "name": target_name,
        "deviceGroupId": target_gid,
        "protocol": int(protocol),
    }
    dst_ports = raw.get("dstPorts") or raw.get("destinationPorts") or data.get("dstPorts")
    if dst_ports:
        payload["dstPorts"] = dst_ports

    src_ports = raw.get("srcPorts") or raw.get("sourcePorts") or data.get("srcPorts")
    if src_ports:
        payload["srcPorts"] = src_ports

    desc = raw.get("description") or data.get("description")
    if desc:
        payload["description"] = desc
    return payload


# ---------------------------------------------------------------------------
# TransferService
# ---------------------------------------------------------------------------

class TransferService:
    def __init__(self, db: AsyncSession, client: NGFWClient):
        self.db = db
        self.client = client

        # Target device object cache (built once per TransferService instance)
        self._cache_built_for: Optional[str] = None  # target_gid
        # {fingerprint: target_uuid}
        self._fp_to_id: Dict[str, str] = {}
        # {name: target_uuid}
        self._name_to_id: Dict[str, str] = {}
        # {name: zone_uuid}  — zones matched by name
        self._zone_name_to_id: Dict[str, str] = {}

        # Report: objects that were cloned (name conflicts)
        self.newly_created_objects: List[Dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def transfer_rule(
        self,
        source_rule_id: str,
        target_gid: str,
        target_folder_id: Optional[str] = None,
    ) -> Dict:
        """
        Copy a rule identified by its local DB id to target_gid.
        Returns dict with created rule data and any object conflicts.
        """
        # 1. Load source rule from DB
        result = await self.db.execute(select(CachedRule).where(CachedRule.id == source_rule_id))
        rule_record = result.scalar_one_or_none()
        if not rule_record:
            raise ValueError(f"Rule {source_rule_id} not found in local DB")

        source_data = rule_record.data or {}

        # 2. Build target cache if needed
        if self._cache_built_for != target_gid:
            await self._build_target_cache(target_gid)

        # 3. Resolve object references → get mapping {source_uuid: target_uuid}
        net_mapping: Dict[str, str] = {}
        svc_mapping: Dict[str, str] = {}
        zone_mapping: Dict[str, str] = {}

        for field_name in ("sourceAddr", "destinationAddr"):
            _, src_ids = _extract_ids_from_rule_field(source_data.get(field_name))
            for src_id in src_ids:
                if src_id not in net_mapping:
                    net_mapping[src_id] = await self._resolve_net_object(src_id, target_gid)

        _, src_svc_ids = _extract_ids_from_rule_field(source_data.get("service"))
        for src_id in src_svc_ids:
            if src_id not in svc_mapping:
                svc_mapping[src_id] = await self._resolve_svc_object(src_id, target_gid)

        for field_name in ("sourceZone", "destinationZone"):
            _, src_zone_ids = _extract_ids_from_rule_field(source_data.get(field_name))
            for src_id in src_zone_ids:
                if src_id not in zone_mapping:
                    zone_mapping[src_id] = self._resolve_zone(src_id, source_data)

        # 4. Build CreateSecurityRuleRequest
        rule_name = self._ensure_unique_rule_name(source_data.get("name", "Unnamed"))
        prec_raw = source_data.get("precedence", "") or source_data.get("fetched_precedence", "pre")
        precedence = self._normalize_precedence(prec_raw)

        def build_net_field_resolved(field_name: str) -> Dict:
            kind, src_ids = _extract_ids_from_rule_field(source_data.get(field_name))
            if "ANY" in kind or not src_ids:
                return _make_any_field()
            new_ids = [net_mapping[i] for i in src_ids if net_mapping.get(i)]
            return _make_list_field(new_ids) if new_ids else _make_any_field()

        def build_svc_field_resolved() -> Dict:
            kind, src_ids = _extract_ids_from_rule_field(source_data.get("service"))
            if "ANY" in kind or not src_ids:
                return _make_any_field()
            new_ids = [svc_mapping[i] for i in src_ids if svc_mapping.get(i)]
            return _make_list_field(new_ids) if new_ids else _make_any_field()

        def build_zone_field_resolved(field_name: str) -> Dict:
            kind, src_ids = _extract_ids_from_rule_field(source_data.get(field_name))
            if "ANY" in kind or not src_ids:
                return _make_any_field()
            new_ids = [zone_mapping[i] for i in src_ids if zone_mapping.get(i)]
            return _make_list_field(new_ids) if new_ids else _make_any_field()

        create_payload = {
            "name": rule_name,
            "description": source_data.get("description", ""),
            "deviceGroupId": target_gid,
            "precedence": precedence,
            "position": 1,
            "action": source_data.get("action", "SECURITY_RULE_ACTION_ALLOW"),
            "logMode": source_data.get("logMode", "SECURITY_RULE_LOG_MODE_AT_RULE_HIT"),
            "enabled": source_data.get("enabled", True),
            "sourceZone": build_zone_field_resolved("sourceZone"),
            "destinationZone": build_zone_field_resolved("destinationZone"),
            "sourceAddr": build_net_field_resolved("sourceAddr"),
            "destinationAddr": build_net_field_resolved("destinationAddr"),
            "service": build_svc_field_resolved(),
            "application": _make_any_field(),
            "urlCategory": _make_any_field(),
            "sourceUser": _make_any_field(user=True),
        }

        logger.info(f"Creating rule '{rule_name}' on target '{target_gid}'")
        created = await self.client.create_rule(create_payload)

        # 5. Re-fetch full rule so DB stores embedded objects (not just id)
        full_data = await self.client.fetch_single_rule(
            created.get("id"), target_gid, create_payload.get("precedence")
        )
        cached_data = full_data if full_data else created

        # 6. Store in local DB
        new_local = CachedRule(
            id=str(uuid.uuid4()),
            ext_id=created.get("id"),
            name=rule_name,
            folder_id=target_folder_id,
            folder_sort_order=0,
            data=cached_data,
        )
        self.db.add(new_local)

        return {"rule": created, "conflicts": self.newly_created_objects}

    # ------------------------------------------------------------------
    # Target object cache
    # ------------------------------------------------------------------

    async def _build_target_cache(self, target_gid: str):
        logger.info(f"Building target object cache for device group '{target_gid}'...")
        self._fp_to_id.clear()
        self._name_to_id.clear()
        self._zone_name_to_id.clear()

        # Network objects + groups
        net_items = await self.client.get_objects("Network", target_gid)
        net_groups = await self.client.get_objects("Network Group", target_gid)
        # Services + groups
        svc_items = await self.client.get_objects("Service", target_gid)
        svc_groups = await self.client.get_objects("Service Group", target_gid)
        # Zones (by name)
        zones = await self.client.get_zones(target_gid)

        for item in net_items + net_groups + svc_items + svc_groups:
            obj_id = item.get("id")
            if not obj_id:
                continue
            name = item.get("name", "")
            if name:
                self._name_to_id[name] = obj_id
            fp = _get_fingerprint(item)
            if fp:
                self._fp_to_id[fp] = obj_id

        for z in zones:
            z_id = z.get("id")
            z_name = z.get("name", "")
            if z_id and z_name:
                self._zone_name_to_id[z_name] = z_id

        self._cache_built_for = target_gid
        logger.info(
            f"Target cache: {len(self._fp_to_id)} fingerprints, "
            f"{len(self._name_to_id)} names, {len(self._zone_name_to_id)} zones"
        )

    # ------------------------------------------------------------------
    # Object resolution
    # ------------------------------------------------------------------

    async def _resolve_net_object(self, src_uuid: str, target_gid: str) -> Optional[str]:
        """
        Find or create a network object on the target device.
        Returns target UUID, or None if resolution fails.
        """
        src_obj = await self.db.get(CachedObject, src_uuid)
        if not src_obj:
            logger.warning(f"Network object {src_uuid} not in local cache — skipping")
            return None

        # Global object → reuse UUID
        if src_obj.device_group_id == "global":
            logger.debug(f"Object '{src_obj.name}' is global — reusing UUID")
            return src_uuid

        # It's a group → resolve members recursively, then create group on target
        if self._is_group(src_obj):
            return await self._resolve_net_group(src_obj, target_gid)

        # Regular object → match by fingerprint
        fp = _get_fingerprint(src_obj.data or {})
        if fp and fp in self._fp_to_id:
            logger.debug(f"Object '{src_obj.name}' matched by fingerprint on target")
            return self._fp_to_id[fp]

        # Create new on target
        return await self._create_net_object(src_obj, target_gid, fp)

    async def _resolve_net_group(self, src_obj: CachedObject, target_gid: str) -> Optional[str]:
        """Recursively resolve group members, then create group on target."""
        data = src_obj.data or {}
        member_uuids = data.get("members", [])

        resolved_member_ids = []
        for m_uuid in member_uuids:
            new_id = await self._resolve_net_object(m_uuid, target_gid)
            if new_id:
                resolved_member_ids.append(new_id)

        # Check if an identical group exists on target (same sorted members)
        if resolved_member_ids:
            fp = "netgroup:" + ",".join(sorted(resolved_member_ids))
            if fp in self._fp_to_id:
                return self._fp_to_id[fp]

        # Create group
        target_name = self._unique_name(src_obj.name)
        is_conflict = target_name != src_obj.name

        try:
            res = await self.client.create_network_object_group({
                "name": target_name,
                "deviceGroupId": target_gid,
                "items": resolved_member_ids,
                "description": (src_obj.data or {}).get("_raw_debug", {}).get("description", ""),
            })
            new_id = res.get("id")
            self._name_to_id[target_name] = new_id
            if resolved_member_ids:
                self._fp_to_id["netgroup:" + ",".join(sorted(resolved_member_ids))] = new_id
            if is_conflict:
                self.newly_created_objects.append({"old": src_obj.name, "new": target_name, "type": "net_group"})
            logger.info(f"Created net group '{target_name}' on target")
            return new_id
        except Exception as e:
            logger.error(f"Failed to create net group '{target_name}': {e}")
            return None

    async def _create_net_object(self, src_obj: CachedObject, target_gid: str, fp: Optional[str]) -> Optional[str]:
        """Create a single network object on the target device."""
        target_name = self._unique_name(src_obj.name)
        is_conflict = target_name != src_obj.name

        try:
            payload = _build_network_object_create_payload(src_obj, target_name, target_gid)
        except ValueError as e:
            logger.error(f"Cannot build payload for '{src_obj.name}': {e}")
            return None

        try:
            res = await self.client.create_network_object(payload)
            new_id = res.get("id")
            self._name_to_id[target_name] = new_id
            if fp:
                self._fp_to_id[fp] = new_id
            if is_conflict:
                self.newly_created_objects.append({"old": src_obj.name, "new": target_name, "type": "net"})
            logger.info(f"Created net object '{target_name}' on target")
            return new_id
        except Exception as e:
            logger.error(f"Failed to create net object '{target_name}': {e}")
            return None

    async def _resolve_svc_object(self, src_uuid: str, target_gid: str) -> Optional[str]:
        """Find or create a service object on the target device."""
        src_obj = await self.db.get(CachedObject, src_uuid)
        if not src_obj:
            logger.warning(f"Service object {src_uuid} not in local cache — skipping")
            return None

        # Global service → reuse UUID
        if src_obj.device_group_id == "global":
            logger.debug(f"Service '{src_obj.name}' is global — reusing UUID")
            return src_uuid

        # Service group → resolve members, then create group
        if self._is_group(src_obj):
            return await self._resolve_svc_group(src_obj, target_gid)

        # Match by fingerprint
        fp = _get_fingerprint(src_obj.data or {})
        if fp and fp in self._fp_to_id:
            logger.debug(f"Service '{src_obj.name}' matched by fingerprint on target")
            return self._fp_to_id[fp]

        # Create
        return await self._create_svc_object(src_obj, target_gid, fp)

    async def _resolve_svc_group(self, src_obj: CachedObject, target_gid: str) -> Optional[str]:
        """Resolve service group members recursively, then create group on target."""
        data = src_obj.data or {}
        member_uuids = data.get("members", [])

        resolved_member_ids = []
        for m_uuid in member_uuids:
            new_id = await self._resolve_svc_object(m_uuid, target_gid)
            if new_id:
                resolved_member_ids.append(new_id)

        if resolved_member_ids:
            fp = "svcgroup:" + ",".join(sorted(resolved_member_ids))
            if fp in self._fp_to_id:
                return self._fp_to_id[fp]

        target_name = self._unique_name(src_obj.name)
        is_conflict = target_name != src_obj.name

        try:
            res = await self.client.create_service_group({
                "name": target_name,
                "deviceGroupId": target_gid,
                "serviceIds": resolved_member_ids,
            })
            new_id = res.get("id")
            self._name_to_id[target_name] = new_id
            if resolved_member_ids:
                self._fp_to_id["svcgroup:" + ",".join(sorted(resolved_member_ids))] = new_id
            if is_conflict:
                self.newly_created_objects.append({"old": src_obj.name, "new": target_name, "type": "svc_group"})
            logger.info(f"Created service group '{target_name}' on target")
            return new_id
        except Exception as e:
            logger.error(f"Failed to create service group '{target_name}': {e}")
            return None

    async def _create_svc_object(self, src_obj: CachedObject, target_gid: str, fp: Optional[str]) -> Optional[str]:
        """Create a single service object on the target device."""
        target_name = self._unique_name(src_obj.name)
        is_conflict = target_name != src_obj.name

        try:
            payload = _build_service_create_payload(src_obj, target_name, target_gid)
        except ValueError as e:
            logger.error(f"Cannot build service payload for '{src_obj.name}': {e}")
            return None

        try:
            res = await self.client.create_service(payload)
            new_id = res.get("id")
            self._name_to_id[target_name] = new_id
            if fp:
                self._fp_to_id[fp] = new_id
            if is_conflict:
                self.newly_created_objects.append({"old": src_obj.name, "new": target_name, "type": "service"})
            logger.info(f"Created service '{target_name}' on target")
            return new_id
        except Exception as e:
            logger.error(f"Failed to create service '{target_name}': {e}")
            return None

    def _resolve_zone(self, src_zone_uuid: str, source_rule_data: Dict) -> Optional[str]:
        """
        Map a source zone UUID to a target zone UUID by name.
        Zones are infrastructure — we match by name only, never create.
        Returns target zone UUID, or None (field will fall back to ANY).
        """
        # Find zone name from the source rule data embedded objects
        for field_name in ("sourceZone", "destinationZone"):
            field = source_rule_data.get(field_name, {})
            for obj in field.get("objects", []):
                obj_id = obj.get("id")
                obj_name = obj.get("name")
                if obj_id == src_zone_uuid and obj_name:
                    target_uuid = self._zone_name_to_id.get(obj_name)
                    if target_uuid:
                        logger.debug(f"Zone '{obj_name}' matched on target")
                    else:
                        logger.warning(f"Zone '{obj_name}' not found on target — will use ANY")
                    return target_uuid
        logger.warning(f"Zone {src_zone_uuid} not found in source rule data — will use ANY")
        return None

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _is_group(self, obj: CachedObject) -> bool:
        return "group" in (obj.type or "").lower()

    def _unique_name(self, base_name: str) -> str:
        """Return base_name if not taken on target, else base_name_copy, _copy_2, ..."""
        if base_name not in self._name_to_id:
            return base_name
        counter = 1
        while True:
            candidate = f"{base_name}_copy" if counter == 1 else f"{base_name}_copy_{counter}"
            if candidate not in self._name_to_id:
                return candidate
            counter += 1

    def _ensure_unique_rule_name(self, name: str) -> str:
        # Rules don't have a local name cache, just return name as-is.
        # If the API rejects it with 409 the caller will handle it.
        return name

    @staticmethod
    def _normalize_precedence(raw: str) -> str:
        raw = str(raw).lower()
        if "post" in raw:
            return "post"
        if "default" in raw:
            return "default"
        return "pre"
