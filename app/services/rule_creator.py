import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import CachedRule, Folder
from app.infrastructure.ngfw_client import NGFWClient

logger = logging.getLogger(__name__)


class RuleCreatorService:
    async def create_rule(self, db: AsyncSession, client: NGFWClient, payload: dict) -> CachedRule:
        """
        Создание правила.
        payload fields:
          folder_id       — UUID виртуальной папки (обязательно)
          name            — имя правила (обязательно)
          action          — "allow" | "drop" | "deny" (default: allow)
          source_ids      — список UUID сетевых объектов источника
          dest_ids        — список UUID сетевых объектов назначения
          service_ids     — список UUID сервис-объектов
          source_zone_ids — список UUID зон источника
          dst_zone_ids    — список UUID зон назначения
          description     — описание (опционально)
        """
        folder_id = payload.get("folder_id")
        if not folder_id:
            raise ValueError("folder_id is required")

        folder = await db.get(Folder, folder_id)
        if not folder:
            raise ValueError(f"Folder '{folder_id}' not found")

        def build_field(ids: list, kind_any: str = "RULE_KIND_ANY", kind_list: str = "RULE_KIND_LIST") -> dict:
            """Build RuleFieldSelection with OptionalStringArray format."""
            if not ids:
                return {"kind": kind_any, "objects": {"array": []}}
            return {"kind": kind_list, "objects": {"array": list(ids)}}

        def build_user_field(ids: list) -> dict:
            if not ids:
                return {"kind": "RULE_USER_KIND_ANY", "objects": {"array": []}}
            return {"kind": "RULE_USER_KIND_LIST", "objects": {"array": list(ids)}}

        # Map action string to API enum
        action_map = {
            "allow": "SECURITY_RULE_ACTION_ALLOW",
            "drop": "SECURITY_RULE_ACTION_DROP",
            "deny": "SECURITY_RULE_ACTION_DENY",
            "reset_server": "SECURITY_RULE_ACTION_RESET_SERVER",
            "reset_client": "SECURITY_RULE_ACTION_RESET_CLIENT",
            "reset_both": "SECURITY_RULE_ACTION_RESET_BOTH",
        }
        action_str = payload.get("action", "allow").lower()
        action = action_map.get(action_str, "SECURITY_RULE_ACTION_ALLOW")

        # Map section to precedence
        section = (folder.section or "pre").lower()
        prec_map = {
            "pre": "pre",
            "post": "post",
            "default": "default",
        }
        precedence = prec_map.get(section, "pre")

        src_ids      = payload.get("source_ids", [])
        dst_ids      = payload.get("dest_ids", [])
        svc_ids      = payload.get("service_ids", [])
        src_zone_ids = payload.get("source_zone_ids", [])
        dst_zone_ids = payload.get("dst_zone_ids", [])
        app_ids      = payload.get("app_ids", [])
        url_cat_ids  = payload.get("url_cat_ids", [])
        user_ids     = payload.get("user_ids", [])

        api_payload = {
            "name": payload.get("name"),
            "description": payload.get("description", ""),
            "deviceGroupId": folder.device_group_id,
            "precedence": precedence,
            "position": 1,
            "action": action,
            "enabled": payload.get("enabled", True),
            "logMode": payload.get("log_mode", "SECURITY_RULE_LOG_MODE_AT_RULE_HIT"),
            "sourceZone": build_field(src_zone_ids),
            "destinationZone": build_field(dst_zone_ids),
            "sourceAddr": build_field(src_ids),
            "destinationAddr": build_field(dst_ids),
            "service": build_field(svc_ids),
            "application": build_field(app_ids),
            "urlCategory": build_field(url_cat_ids),
            "sourceUser": build_user_field(user_ids),
        }

        if payload.get("ips_profile_id"):
            api_payload["ipsProfileId"] = payload["ips_profile_id"]
        if payload.get("av_profile_id"):
            api_payload["avProfileId"] = payload["av_profile_id"]
        if payload.get("icap_profile_id"):
            api_payload["icapProfileId"] = payload["icap_profile_id"]

        logger.info(f"Creating rule '{api_payload['name']}' in device group '{folder.device_group_id}'")
        logger.debug(f"Create rule payload: {api_payload}")

        res = await client.create_rule(api_payload)

        ext_id = res.get("id")
        if not ext_id:
            raise RuntimeError(f"API did not return rule ID. Response: {res}")

        # Re-fetch full rule from API so CachedRule.data has embedded objects
        # (CreateSecurityRule response often contains only {id}, not full objects)
        full_data = await client.fetch_single_rule(ext_id, folder.device_group_id, section)
        cached_data = full_data if full_data else res

        new_cached = CachedRule(
            id=str(uuid.uuid4()),
            ext_id=ext_id,
            name=payload.get("name"),
            folder_id=folder.id,
            folder_sort_order=0,
            data=cached_data,
        )
        db.add(new_cached)
        await db.commit()
        await db.refresh(new_cached)
        logger.info(f"Rule '{new_cached.name}' created, ext_id={ext_id}")
        return new_cached


rule_creator = RuleCreatorService()
