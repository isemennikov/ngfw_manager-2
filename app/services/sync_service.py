from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.db.models import Folder, CachedRule, CachedObject, DeviceMeta, NatFolder, CachedNatRule
from app.infrastructure.ngfw_client import NGFWClient
from datetime import datetime, timezone
import logging
import uuid

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Change detection helpers
# ---------------------------------------------------------------------------

def _field_ids(field: dict) -> tuple:
    """Extract a sorted tuple of UUIDs from a SecurityRule field for comparison."""
    if not field:
        return ("ANY",)
    kind = field.get("kind", "")
    if "ANY" in kind:
        return ("ANY",)
    objects = field.get("objects", [])
    if isinstance(objects, dict):          # OptionalStringArray format
        arr = objects.get("array", [])
        return tuple(sorted(str(x) for x in arr))
    if not isinstance(objects, list):
        return ("ANY",)
    ids = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if "id" in obj:
            ids.append(obj["id"])
        else:
            for v in obj.values():
                if isinstance(v, dict) and "id" in v:
                    ids.append(v["id"])
                    break
    return tuple(sorted(ids)) if ids else ("ANY",)


def _rule_changed(old: dict, new: dict) -> bool:
    """Return True if any meaningful field differs between two rule snapshots."""
    for key in ("name", "action", "enabled", "description"):
        if old.get(key) != new.get(key):
            return True
    for field in ("sourceAddr", "destinationAddr", "service", "sourceZone", "destinationZone",
                  "application", "urlCategory", "sourceUser"):
        if _field_ids(old.get(field)) != _field_ids(new.get(field)):
            return True
    return False

class SyncService:
    async def sync_all(self, db: AsyncSession, client: NGFWClient):
        logger.info("Starting SMART sync (Preserving Folders)...")
        
        device_groups = await client.get_device_groups()
        if not device_groups:
            device_groups = [{"id": "fallback", "name": "Global Context"}]

        processed_meta_ids = set()
        for dg in device_groups:
            dg_id = dg.get('id')
            if dg_id not in processed_meta_ids:
                await self._upsert_meta(db, dg_id, dg.get('name'))
                processed_meta_ids.add(dg_id)

        if "global" not in processed_meta_ids:
            await self._upsert_meta(db, "global", "Global Objects")
            processed_meta_ids.add("global")

        object_types = [
            ("Network", "Host/Network", "net"),
            ("Network Group", "Network Group", "net"),
            ("Service", "Service", "service"),
            ("Service Group", "Service Group", "service"),
            ("Zone", "Security Zone", "zone"),
            ("Application", "Application", "app"),
            ("URL Category", "URL Category", "urlcat"),
            ("User", "User", "user"),
            ("User Group", "User Group", "user"),
        ]

        # 1. Objects (Global & Local)
        logger.info("Fetching Global Objects...")
        for obj_name, type_lbl, cat in object_types:
            items = await client.get_objects(obj_name, device_group_id="global")
            if items: await self._save_objects(db, items, "global", type_lbl, cat)

        for dg in device_groups:
            dg_id = dg['id']
            if dg_id == "global": continue
            logger.info(f"Fetching objects for Group: {dg['name']}")
            for obj_name, type_lbl, cat in object_types:
                items = await client.get_objects(obj_name, device_group_id=dg_id)
                if items: await self._save_objects(db, items, dg_id, type_lbl, cat)

        # 2. Rules (SMART SYNC)
        for dg in device_groups:
            dg_id = dg['id']
            dg_name = dg['name']
            
            logger.info(f"Syncing rules for {dg_name} (Smart Mode)...")
            
            # РџРѕР»СѓС‡Р°РµРј РїСЂР°РІРёР»Р° СЃ СѓСЃС‚СЂРѕР№СЃС‚РІР°
            api_rules = await client.get_rules(device_group_id=dg_id)
            if not api_rules:
                continue

            # Р“Р°СЂР°РЅС‚РёСЂСѓРµРј РЅР°Р»РёС‡РёРµ Р‘Р°Р·РѕРІС‹С… РїР°РїРѕРє (РµСЃР»Рё Р±Р°Р·Р° РїСѓСЃС‚Р°СЏ РёР»Рё РЅРѕРІР°СЏ РіСЂСѓРїРїР°)
            await self._ensure_default_folders(db, dg_id)
            
            # РџРѕР»СѓС‡Р°РµРј РєР°СЂС‚Сѓ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёС… РїСЂР°РІРёР» РІ Р‘Р”: {ext_id: RuleObject}
            existing_rules_stmt = select(CachedRule).join(Folder).where(Folder.device_group_id == dg_id)
            existing_rules_res = await db.execute(existing_rules_stmt)
            db_rules_map = {r.ext_id: r for r in existing_rules_res.scalars().all()}
            
            # РџРѕР»СѓС‡Р°РµРј ID РґРµС„РѕР»С‚РЅС‹С… РїР°РїРѕРє, РєСѓРґР° РєР»Р°СЃС‚СЊ РЅРѕРІС‹Рµ РїСЂР°РІРёР»Р°
            default_folders = {}
            for sec in ['pre', 'post', 'default']:
                f_stmt = select(Folder).where(Folder.device_group_id == dg_id, Folder.section == sec, Folder.name.like(f"Policy {sec.upper()}%"))
                f_res = await db.execute(f_stmt)
                folder = f_res.scalars().first()
                if folder: default_folders[sec] = folder.id

            # РћР±СЂР°Р±Р°С‚С‹РІР°РµРј РїСЂР°РІРёР»Р°
            processed_ids = set()
            
            for i, r_data in enumerate(api_rules):
                ext_id = r_data.get('id')
                if not ext_id: continue
                
                processed_ids.add(ext_id)
                
                # РћРїСЂРµРґРµР»СЏРµРј СЃРµРєС†РёСЋ (Pre/Post/Default)
                prec = r_data.get('fetched_precedence') or r_data.get('precedence') or 'pre'
                sec = 'post' if 'post' in prec.lower() else ('default' if 'default' in prec.lower() else 'pre')
                
                if ext_id in db_rules_map:
                    # UPDATE: правило уже есть. Обновляем, но НЕ ТРОГАЕМ папку.
                    rule = db_rules_map[ext_id]
                    old_data = rule.data or {}

                    # Детектируем изменения, сделанные напрямую через СУ
                    if _rule_changed(old_data, r_data):
                        rule.is_modified = True
                        rule.modified_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                        logger.info(f"Rule '{rule.name}' changed externally — marked modified")

                    rule.name = r_data.get('name', "Rule")
                    rule.data = r_data
                    # РњС‹ РЅР°РјРµСЂРµРЅРЅРѕ РќР• РѕР±РЅРѕРІР»СЏРµРј rule.folder_id Рё rule.folder_sort_order,
                    # С‡С‚РѕР±С‹ СЃРѕС…СЂР°РЅРёС‚СЊ СЃС‚СЂСѓРєС‚СѓСЂСѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ.
                else:
                    # INSERT: РќРѕРІРѕРµ РїСЂР°РІРёР»Рѕ. РљР»Р°РґРµРј РІ РґРµС„РѕР»С‚РЅСѓСЋ РїР°РїРєСѓ СЃРµРєС†РёРё.
                    target_folder_id = default_folders.get(sec)
                    if target_folder_id:
                        new_rule = CachedRule(
                            id=str(uuid.uuid4()), 
                            ext_id=ext_id, 
                            name=r_data.get('name', "Rule"), 
                            folder_id=target_folder_id, 
                            folder_sort_order=i, # Р’СЂРµРјРµРЅРЅРѕ СЃС‚Р°РІРёРј РІ РєРѕРЅРµС†
                            data=r_data
                        )
                        db.add(new_rule)

            # DELETE: РЈРґР°Р»СЏРµРј РїСЂР°РІРёР»Р°, РєРѕС‚РѕСЂС‹С… Р±РѕР»СЊС€Рµ РЅРµС‚ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ
            for ext_id, rule in db_rules_map.items():
                if ext_id not in processed_ids:
                    logger.info(f"Deleting obsolete rule: {rule.name}")
                    await db.delete(rule)

        # 3. NAT Rules (SMART SYNC)
        for dg in device_groups:
            dg_id = dg['id']
            if dg_id == "global":
                continue
            await self._sync_nat_rules(db, client, dg_id)

        await db.commit()
        logger.info("Smart Sync complete.")

    async def _sync_nat_rules(self, db: AsyncSession, client: NGFWClient, dg_id: str):
        logger.info(f"Syncing NAT rules for {dg_id}...")
        api_rules = await client.get_nat_rules(dg_id)
        if not api_rules:
            return

        # Ensure default NAT folders exist
        await self._ensure_default_nat_folders(db, dg_id)

        # Map section → default folder id
        default_folders: dict[str, str] = {}
        for sec in ['pre', 'post', 'default']:
            stmt = select(NatFolder).where(
                NatFolder.device_group_id == dg_id,
                NatFolder.section == sec,
                NatFolder.name.like(f"NAT {sec.upper()}%")
            )
            folder = (await db.execute(stmt)).scalars().first()
            if folder:
                default_folders[sec] = folder.id

        # Existing NAT rules in DB for this device
        stmt = select(CachedNatRule).where(CachedNatRule.device_group_id == dg_id)
        db_map = {r.ext_id: r for r in (await db.execute(stmt)).scalars().all()}

        processed_ids: set[str] = set()
        for i, r_data in enumerate(api_rules):
            ext_id = r_data.get('id')
            if not ext_id:
                continue
            processed_ids.add(ext_id)

            prec = r_data.get('fetched_precedence', 'pre')
            sec = 'post' if 'post' in prec else ('default' if 'default' in prec else 'pre')

            if ext_id in db_map:
                rule = db_map[ext_id]
                old_data = rule.data or {}
                if self._nat_rule_changed(old_data, r_data):
                    rule.is_modified = True
                    rule.modified_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                rule.name = r_data.get('name', 'NAT Rule')
                rule.data = r_data
            else:
                target_folder_id = default_folders.get(sec)
                if target_folder_id:
                    db.add(CachedNatRule(
                        id=str(uuid.uuid4()),
                        ext_id=ext_id,
                        name=r_data.get('name', 'NAT Rule'),
                        folder_id=target_folder_id,
                        folder_sort_order=i,
                        device_group_id=dg_id,
                        data=r_data,
                    ))

        # Delete stale NAT rules
        for ext_id, rule in db_map.items():
            if ext_id not in processed_ids:
                logger.info(f"Deleting obsolete NAT rule: {rule.name}")
                await db.delete(rule)

        await db.flush()

    def _nat_rule_changed(self, old: dict, new: dict) -> bool:
        for key in ("name", "enabled", "srcTranslationType", "dstTranslationType"):
            if old.get(key) != new.get(key):
                return True
        for field in ("sourceAddr", "destinationAddr", "service", "sourceZone", "destinationZone"):
            if _field_ids(old.get(field)) != _field_ids(new.get(field)):
                return True
        return False

    async def _ensure_default_nat_folders(self, db: AsyncSession, dev_id: str):
        for sec in ['pre', 'post', 'default']:
            stmt = select(NatFolder).where(NatFolder.device_group_id == dev_id, NatFolder.section == sec)
            if not (await db.execute(stmt)).scalars().first():
                db.add(NatFolder(
                    id=str(uuid.uuid4()),
                    name=f"NAT {sec.upper()} (Default)",
                    device_group_id=dev_id,
                    section=sec,
                    sort_order=0,
                ))
        await db.flush()

    async def _ensure_default_folders(self, db, dev_id):
        """РЎРѕР·РґР°РµС‚ Р±Р°Р·РѕРІС‹Рµ РїР°РїРєРё Pre/Post/Default, РµСЃР»Рё РёС… РЅРµС‚"""
        for sec in ['pre', 'post', 'default']:
            stmt = select(Folder).where(Folder.device_group_id == dev_id, Folder.section == sec)
            res = await db.execute(stmt)
            if not res.scalars().first():
                f = Folder(
                    id=str(uuid.uuid4()), 
                    name=f"Policy {sec.upper()} (Default)", 
                    device_group_id=dev_id, 
                    section=sec, 
                    sort_order=0
                )
                db.add(f)
        await db.flush()

    # (РњРµС‚РѕРґС‹ _extract_members, _upsert_meta, _save_objects РѕСЃС‚Р°СЋС‚СЃСЏ Р±РµР· РёР·РјРµРЅРµРЅРёР№ - РѕРЅРё РёРґРµР°Р»СЊРЅС‹)
    def _extract_members(self, item: dict) -> list:
        members = []
        keys_to_check = ['items', 'objects', 'networkObjects', 'serviceObjects', 'members']
        for k in keys_to_check:
            if k in item and isinstance(item[k], list):
                for m in item[k]:
                    if isinstance(m, dict):
                        val = m.get('id') or m.get('name')
                        if val:
                            members.append(str(val))
                            continue
                        for sub_key, sub_val in m.items():
                            if isinstance(sub_val, dict) and ('id' in sub_val or 'name' in sub_val):
                                val = sub_val.get('id') or sub_val.get('name')
                                if val: members.append(str(val))
                                break
                    elif isinstance(m, str):
                        members.append(m)
        return list(set(members))

    async def _upsert_meta(self, db, dev_id, name):
        meta = await db.execute(select(DeviceMeta).where(DeviceMeta.device_id == dev_id))
        if not meta.scalars().first(): 
            db.add(DeviceMeta(device_id=dev_id, name=name))
            await db.flush()
        exists = await db.execute(select(CachedObject).where(CachedObject.ext_id == dev_id))
        if not exists.scalars().first(): 
            db.add(CachedObject(ext_id=dev_id, name=name, type='device_meta', category='meta', device_group_id=dev_id, data={}))
            await db.flush()

    async def _save_objects(self, db, items, requested_dev_id, type_lbl, cat):
        for item in items:
            uid = item.get('id')
            name = item.get('name')
            if not uid: continue
            
            item_dev_id = item.get('deviceGroupId')
            if requested_dev_id == "global":
                # Глобальный запрос (без фильтра): храним с реальным UUID устройства
                actual_dev_id = item_dev_id or "global"
            else:
                if item_dev_id and item_dev_id != requested_dev_id:
                    # Объект принадлежит другой (родительской) группе → глобальный
                    actual_dev_id = "global"
                else:
                    actual_dev_id = item_dev_id or requested_dev_id
            if item.get('isGlobal'):
                actual_dev_id = "global"

            members = self._extract_members(item)
            if members and "Group" not in type_lbl: type_lbl = f"{type_lbl} Group"
            
            val = item.get('value') or item.get('inet') or item.get('fqdn') or item.get('address')
            start = item.get('start') or item.get('startIp') or item.get('from')
            end = item.get('end') or item.get('endIp') or item.get('to')
            
            obj_data = {
                "value": val, "start": start, "end": end,
                "protocol": item.get('protocol'), "port": item.get('port'),
                "dstPorts": item.get('dstPorts') or item.get('destinationPorts'),
                "members": members, "_raw_debug": item
            }

            existing = await db.execute(select(CachedObject).where(CachedObject.ext_id == uid))
            ext_obj = existing.scalars().first()
            if ext_obj:
                ext_obj.name = name
                ext_obj.data = obj_data
                if actual_dev_id == "global":
                    # Повышаем до "global" если теперь знаем что объект глобальный
                    ext_obj.device_group_id = "global"
                elif ext_obj.device_group_id != "global":
                    # Не понижаем с "global" до конкретного устройства
                    ext_obj.device_group_id = actual_dev_id
                if "Group" in type_lbl and "Group" not in ext_obj.type: ext_obj.type = type_lbl
            else:
                db.add(CachedObject(ext_id=uid, name=name, type=type_lbl, category=cat, device_group_id=actual_dev_id, data=obj_data))
        await db.flush()
