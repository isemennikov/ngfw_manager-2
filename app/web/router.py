from fastapi import APIRouter, Request, Depends, Query, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete as sa_delete
from sqlalchemy.orm import selectinload
from app.db.session import get_db
from app.db.models import CachedRule, Folder, CachedObject, DeviceMeta, NatFolder, CachedNatRule, CachedLog
from app.services.deploy_service import DeployService
from app.services.sync_service import SyncService
from app.infrastructure.ngfw_client import NGFWClient
from fastapi.templating import Jinja2Templates
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
import asyncio
import logging
import uuid
import math
import json
import csv
import io
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}
GLOBAL_NAME_MAP = {}

# --- HELPER: РџСЂРѕРІРµСЂРєР° Р°РІС‚РѕСЂРёР·Р°С†РёРё ---
def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        return None
    return user

# --- РњРћР”Р•Р›Р Р”РђРќРќР«РҐ (Pydantic) ---
class AuthRequest(BaseModel):
    host: str
    username: str
    password: str
    device_id: Optional[str] = None

class ReorderRequest(BaseModel):
    folder_id: str
    rule_ids: List[str]

# --- HELPER FUNCTIONS (FORMATTERS) ---
def format_obj_details(obj: CachedObject) -> str:
    d = obj.data or {}
    cat = obj.category
    typ = str(obj.type).lower()
    
    members = d.get('members', [])
    is_group = 'group' in typ or bool(members)
    
    mem_badge = ""
    if members:
        count = len(members)
        member_names = []
        for m_id in members[:15]:
            name = GLOBAL_NAME_MAP.get(m_id, m_id)
            member_names.append(name)
        tooltip_content = chr(10).join(member_names)
        if count > 15: tooltip_content += f"\n...and {count-15} more"
        tooltip = f" title='{tooltip_content.replace(chr(39), '')}'"
        mem_badge = f" <span class='badge bg-primary text-white ms-2' data-bs-toggle='tooltip' data-bs-placement='right' {tooltip}><i class='fa-solid fa-layer-group me-1'></i>{count} items</span>"
    elif is_group:
        raw_keys = list(d.get('_raw_debug', {}).keys())
        mem_badge = f" <span class='text-muted small fst-italic' title='Keys: {raw_keys}'>[Empty Group]</span>"

    if cat == 'net':
        val = d.get('value') or d.get('inet') or d.get('fqdn') or d.get('address')
        if not val:
            start = d.get('start') or d.get('startIp') or d.get('from')
            end = d.get('end') or d.get('endIp') or d.get('to')
            if start and end:
                val = f"{start} - {end}"
        val = val or ""
        if is_group and not val: return mem_badge
        return f"{val}{mem_badge}" if val else (mem_badge or "-")
        
    elif cat == 'service':
        if is_group and not d.get('protocol'): return mem_badge or "-"
        proto_num = d.get('protocol')
        proto_str = PROTOCOL_MAP.get(int(proto_num), str(proto_num)) if str(proto_num).isdigit() else str(proto_num)
        proto_display = f"{proto_str} ({proto_num})" if str(proto_num).isdigit() and proto_str != str(proto_num) else str(proto_num) if proto_num else ""
        
        ports = []
        dst = d.get('dstPorts') or d.get('port')
        if isinstance(dst, str):
            try: dst = json.loads(dst.replace("'", '"'))
            except: ports.append(dst)
        if isinstance(dst, list):
            for p in dst:
                if isinstance(p, dict):
                    if 'singlePort' in p: ports.append(str(p['singlePort'].get('port', '')))
                    elif 'portRange' in p: ports.append(f"{p['portRange'].get('from', '')}-{p['portRange'].get('to', '')}")
                elif isinstance(p, (str, int)): ports.append(str(p))
        elif isinstance(dst, dict):
            if 'singlePort' in dst: ports.append(str(dst['singlePort'].get('port', '')))
            elif 'portRange' in dst: ports.append(f"{dst['portRange'].get('from', '')}-{dst['portRange'].get('to', '')}")
        elif isinstance(dst, (int, str)) and dst: ports.append(str(dst))
            
        ports_display = ", ".join([p for p in ports if p])
        parts = []
        if proto_display: parts.append(f"<b>Proto:</b> <span class='text-secondary'>{proto_display}</span>")
        if ports_display: parts.append(f"<b>Dst:</b> <span class='font-monospace'>{ports_display}</span>")
        res = " | ".join(parts) if parts else "-"
        return res + mem_badge
        
    else:
        return str(d.get('value') or d.get('name') or "-")

templates.env.globals['format_obj_details'] = format_obj_details

def rule_to_dict(rule: CachedRule, object_map: Dict[str, CachedObject]) -> Dict[str, Any]:
    d = rule.data or {}

    def _extract_items(field_key: str) -> list:
        """Return list of (id, name_or_none) tuples from a SecurityRule field."""
        section = d.get(field_key)
        if not section:
            return []
        kind = section.get('kind', '')
        if 'ANY' in kind:
            return []
        objects = section.get('objects', [])
        if isinstance(objects, dict):          # OptionalStringArray: {array: [...]}
            objects = objects.get('array', [])
        if not isinstance(objects, list):
            return []
        result = []
        for item in objects:
            if not isinstance(item, dict):
                continue
            # ObjectZone is direct: {id, name, ...}
            if 'id' in item:
                result.append((item['id'], item.get('name')))
                continue
            # NetworkObject / ServiceItem is wrapped: {networkIpAddress: {id, name, ...}}
            for k, v in item.items():
                if isinstance(v, dict) and 'id' in v:
                    result.append((v['id'], v.get('name')))
                    break
        return result

    def resolve_zone(field_key: str) -> str:
        items = _extract_items(field_key)
        if not items:
            return "Any"
        tags = []
        for uid, embedded_name in items[:4]:
            # Prefer embedded name (always present in ObjectZone), fallback to DB lookup
            name = embedded_name or (object_map[uid].name if uid in object_map else uid[:8])
            tags.append(f"<span class='obj-tag zone' title='{name}'>{name}</span>")
        extra = len(items) - 4
        result = "".join(tags)
        if extra > 0:
            result += f"<span class='obj-tag overflow'>+{extra}</span>"
        return result

    def resolve_objects(field_key: str, css_class: str = '') -> str:
        items = _extract_items(field_key)
        if not items:
            return "Any"
        tags = []
        for uid, embedded_name in items[:4]:
            cached = object_map.get(uid)
            name = (cached.name if cached else embedded_name) or uid[:8]
            cls = f"obj-tag {css_class}".strip()
            tags.append(f"<span class='{cls}' title='{name}'>{name}</span>")
        extra = len(items) - 4
        result = "".join(tags)
        if extra > 0:
            result += f"<span class='obj-tag overflow'>+{extra}</span>"
        return result

    def _raw_ids(field_key: str) -> List[str]:
        return [uid for uid, _ in _extract_items(field_key)]

    raw_action = d.get('action', 'allow')
    action = raw_action.split('_')[-1].title() if '_' in raw_action else raw_action

    return {
        "id":            rule.id,
        "ext_id":        rule.ext_id,
        "name":          rule.name,
        "folder_id":     rule.folder_id,
        "description":   d.get('description', ''),
        "log_mode":      d.get('logMode', 'SECURITY_RULE_LOG_MODE_AT_RULE_HIT'),
        # rendered HTML for table display
        "src_zone":      resolve_zone('sourceZone'),
        "src_net":       resolve_objects('sourceAddr'),
        "dst_zone":      resolve_zone('destinationZone'),
        "dst_net":       resolve_objects('destinationAddr'),
        "service":       resolve_objects('service', 'service'),
        "application":   resolve_objects('application', 'app'),
        "url_category":  resolve_objects('urlCategory', 'url'),
        "action":        action,
        "enabled":       d.get('enabled', True),
        "is_modified":   rule.is_modified or False,
        "modified_at":   rule.modified_at or "",
        # raw ID arrays for pre-populating edit modal
        "src_zone_ids":  _raw_ids('sourceZone'),
        "dst_zone_ids":  _raw_ids('destinationZone'),
        "src_net_ids":   _raw_ids('sourceAddr'),
        "dst_net_ids":   _raw_ids('destinationAddr'),
        "service_ids":   _raw_ids('service'),
        "app_ids":       _raw_ids('application'),
        "url_cat_ids":   _raw_ids('urlCategory'),
        "user_ids":      _raw_ids('sourceUser'),
        "ips_profile_id":  ((d.get('ipsProfile')  or {}).get('id') or ''),
        "av_profile_id":   ((d.get('avProfile')   or {}).get('id') or ''),
        "icap_profile_id": ((d.get('icapProfile') or {}).get('id') or ''),
    }

# --- AUTH ROUTES ---

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@router.post("/login")
async def login_action(request: Request, host: str = Form(...), username: str = Form(...), password: str = Form(...)):
    client = NGFWClient(host, verify_ssl=False)
    try:
        await client.login(username, password)
        await client.close()
        
        request.session["user"] = {
            "host": host,
            "username": username,
            "password": password
        }
        logger.info(f"User {username} logged in successfully.")
        return RedirectResponse(url="/", status_code=303)
        
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": f"Connection failed: {e}"})

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

# --- ACTIONS (SYNC / COMMIT / REORDER) ---

@router.post("/sync")
async def sync_data(request: Request, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user: return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        service = SyncService()
        await service.sync_all(db, client)
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()

@router.post("/commit")
async def commit_changes(request: Request, device_id: str = Form(...), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user: return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        deployer = DeployService()
        await deployer.deploy_device_policy(db, client, device_id)
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Commit failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()

# Р­РќР”РџРћРРќРў Р”Р›РЇ РџР•Р Р•РўРђРЎРљРР’РђРќРРЇ (РСЃРїСЂР°РІР»СЏРµС‚ 404 РїСЂРё Drag&Drop)
@router.post("/api/v1/rules/reorder")
async def reorder_rules(data: ReorderRequest, db: AsyncSession = Depends(get_db)):
    # 1. РџРѕР»СѓС‡Р°РµРј РІСЃРµ РїСЂР°РІРёР»Р°, РєРѕС‚РѕСЂС‹Рµ РїСЂРёСЃР»Р°Р» С„СЂРѕРЅС‚РµРЅРґ
    stmt = select(CachedRule).where(CachedRule.id.in_(data.rule_ids))
    rules = (await db.execute(stmt)).scalars().all()
    
    rule_map = {r.id: r for r in rules}
    
    # 2. РћР±РЅРѕРІР»СЏРµРј РїРѕСЂСЏРґРѕРє
    for index, r_id in enumerate(data.rule_ids):
        if r_id in rule_map:
            rule = rule_map[r_id]
            rule.folder_id = data.folder_id # Р•СЃР»Рё РїРµСЂРµРЅРµСЃР»Рё РІ РґСЂСѓРіСѓСЋ РїР°РїРєСѓ
            rule.folder_sort_order = index  # РќРѕРІС‹Р№ РїРѕСЂСЏРґРєРѕРІС‹Р№ РЅРѕРјРµСЂ
    
    await db.commit()
    return JSONResponse({"status": "ok"})

# --- !!! Р’РћРў Р­РўРћРў Р­РќР”РџРћРРќРў Р‘Р«Р› РџР РћРџРЈР©Р•Рќ !!! ---
@router.get("/api/v1/rules/folders/tree")
async def get_folders_tree(device_group_id: str = Query(None), db: AsyncSession = Depends(get_db)):
    # Р’С‹Р±РёСЂР°РµРј С‚РѕР»СЊРєРѕ РїР°РїРєРё РЅСѓР¶РЅРѕРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІР°
    stmt = select(Folder).where(Folder.device_group_id == device_group_id).order_by(Folder.section, Folder.sort_order)
    folders = (await db.execute(stmt)).scalars().all()
    
    result = []
    for f in folders:
        result.append({
            "id": f.id,
            "name": f.name,
            "section": f.section,
            "device_group_id": f.device_group_id
        })
    return JSONResponse(result)

class RuleCreateRequest(BaseModel):
    folder_id: str
    name: str
    action: str
    source_ids: List[str] = []
    dest_ids: List[str] = []
    service_ids: List[str] = []
    source_zone_ids: List[str] = []
    dst_zone_ids: List[str] = []
    app_ids: List[str] = []
    url_cat_ids: List[str] = []
    user_ids: List[str] = []
    ips_profile_id: str = ""
    av_profile_id: str = ""
    icap_profile_id: str = ""

class RuleUpdateRequest(BaseModel):
    rule_id: str
    name: str
    action: str
    enabled: bool = True
    log_mode: str = "SECURITY_RULE_LOG_MODE_AT_RULE_HIT"
    description: str = ""
    source_zone_ids: List[str] = []
    dst_zone_ids: List[str] = []
    source_ids: List[str] = []
    dest_ids: List[str] = []
    service_ids: List[str] = []
    app_ids: List[str] = []
    url_cat_ids: List[str] = []
    user_ids: List[str] = []
    ips_profile_id: str = ""
    av_profile_id: str = ""
    icap_profile_id: str = ""

class ToggleRequest(BaseModel):
    rule_id: str
    enabled: bool

class TransferRequest(BaseModel):
    rule_ids: List[str]
    target_gid: str
    target_folder_id: Optional[str] = None
    mode: str = "copy"

class DeleteRequest(BaseModel):
    rule_ids: List[str]

class AcknowledgeRequest(BaseModel):
    rule_ids: List[str]

@router.post("/api/v1/rules/create")
async def create_rule(request: Request, data: RuleCreateRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user: return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        from app.services.rule_creator import rule_creator
        payload = data.dict()
        await rule_creator.create_rule(db, client, payload)
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Rule creation failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()

@router.get("/api/v1/objects/list")
async def api_get_objects_list(device_group_id: str, category: str = "network", db: AsyncSession = Depends(get_db)):
    stmt = select(CachedObject.ext_id, CachedObject.name, CachedObject.device_group_id).where(
        CachedObject.device_group_id.in_([device_group_id, "global"]),
        func.lower(CachedObject.category).ilike(category.lower() + "%")
    ).order_by(CachedObject.name)
    rows = (await db.execute(stmt)).all()
    return JSONResponse([{"id": r.ext_id, "name": f"[Global] {r.name}" if r.device_group_id == 'global' else r.name} for r in rows])

@router.post("/api/v1/rules/acknowledge")
async def acknowledge_rules(request: Request, data: AcknowledgeRequest, db: AsyncSession = Depends(get_db)):
    """Clear the is_modified flag for the given rule IDs."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    rule_ids = data.rule_ids
    for rid in rule_ids:
        rule = await db.get(CachedRule, rid)
        if rule:
            rule.is_modified = False
            rule.modified_at = None
    await db.commit()
    return JSONResponse({"status": "ok", "cleared": len(rule_ids)})


@router.post("/api/v1/rules/update")
async def update_rule_endpoint(request: Request, data: RuleUpdateRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    rule = await db.get(CachedRule, data.rule_id)
    if not rule:
        return JSONResponse({"status": "error", "message": "Rule not found"}, status_code=404)

    folder = await db.get(Folder, rule.folder_id)
    device_group_id = folder.device_group_id if folder else None

    def build_field(ids, kind_any="RULE_KIND_ANY", kind_list="RULE_KIND_LIST"):
        if not ids:
            return {"kind": kind_any, "objects": {"array": []}}
        return {"kind": kind_list, "objects": {"array": list(ids)}}

    def build_user_field(ids):
        if not ids:
            return {"kind": "RULE_USER_KIND_ANY", "objects": {"array": []}}
        return {"kind": "RULE_USER_KIND_LIST", "objects": {"array": list(ids)}}

    action_map = {
        "allow": "SECURITY_RULE_ACTION_ALLOW",
        "drop": "SECURITY_RULE_ACTION_DROP",
        "deny": "SECURITY_RULE_ACTION_DENY",
        "reset_server": "SECURITY_RULE_ACTION_RESET_SERVER",
        "reset_client": "SECURITY_RULE_ACTION_RESET_CLIENT",
        "reset_both": "SECURITY_RULE_ACTION_RESET_BOTH",
    }

    api_payload = {
        "id": rule.ext_id,
        "name": data.name,
        "description": data.description,
        "action": action_map.get(data.action.lower(), "SECURITY_RULE_ACTION_ALLOW"),
        "enabled": data.enabled,
        "logMode": data.log_mode,
        "sourceZone":      build_field(data.source_zone_ids),
        "destinationZone": build_field(data.dst_zone_ids),
        "sourceAddr":      build_field(data.source_ids),
        "destinationAddr": build_field(data.dest_ids),
        "service":         build_field(data.service_ids),
        "application":     build_field(data.app_ids),
        "urlCategory":     build_field(data.url_cat_ids),
        "sourceUser":      build_user_field(data.user_ids),
    }
    if data.ips_profile_id:
        api_payload["ipsProfileId"] = data.ips_profile_id
    if data.av_profile_id:
        api_payload["avProfileId"] = data.av_profile_id
    if data.icap_profile_id:
        api_payload["icapProfileId"] = data.icap_profile_id

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        await client.update_rule(rule.ext_id, api_payload)

        full_data = await client.fetch_single_rule(rule.ext_id, device_group_id)
        if full_data:
            rule.name = full_data.get("name", rule.name)
            rule.data = full_data
            rule.is_modified = False
            rule.modified_at = None

        await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Rule update failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/rules/toggle")
async def toggle_rule(request: Request, data: ToggleRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    rule = await db.get(CachedRule, data.rule_id)
    if not rule:
        return JSONResponse({"status": "error", "message": "Rule not found"}, status_code=404)

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        await client.update_rule(rule.ext_id, {"id": rule.ext_id, "enabled": data.enabled})
        if rule.data:
            rule.data = {**rule.data, "enabled": data.enabled}
        await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Toggle rule failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.get("/api/v1/profiles/list")
async def get_profiles_list(request: Request, profile_type: str, device_group_id: str = ""):
    user = get_current_user(request)
    if not user:
        return JSONResponse([], status_code=401)

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        dgid = device_group_id or None
        if profile_type == 'ips':
            items = await client.get_ips_profiles(dgid)
        elif profile_type == 'av':
            items = await client.get_av_profiles(dgid)
        elif profile_type == 'icap':
            items = await client.get_icap_profiles(dgid)
        else:
            items = []
        return JSONResponse([{"id": p.get("id"), "name": p.get("name", "")} for p in items if p.get("id")])
    except Exception as e:
        logger.error(f"Profile list failed: {e}")
        return JSONResponse([])
    finally:
        await client.close()


@router.post("/api/v1/rules/transfer")
async def transfer_rules(request: Request, data: TransferRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user: return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        from app.services.transfer_service import TransferService
        t_service = TransferService(db, client)
        
        for rid in data.rule_ids:
            try:
                new_rule = await t_service.transfer_rule(rid, data.target_gid, data.target_folder_id)
                if data.mode == "move":
                    stmt = select(CachedRule).where(CachedRule.id == rid)
                    old_r = (await db.execute(stmt)).scalar_one_or_none()
                    if old_r:
                        await client.delete_rule(old_r.ext_id)
                        await db.delete(old_r)
            except Exception as re_err:
                logger.error(f"Error transferring rule {rid}: {re_err}")
                
        await db.commit()
        return JSONResponse({"status": "ok", "conflicts": getattr(t_service, "newly_created_objects", [])})
    except Exception as e:
        logger.error(f"Transfer failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()

@router.post("/api/v1/rules/delete")
async def delete_rules(request: Request, data: DeleteRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    client = NGFWClient(user['host'], verify_ssl=False)
    await client.login(user['username'], user['password'])
    stmt = select(CachedRule).where(CachedRule.id.in_(data.rule_ids))
    rules = (await db.execute(stmt)).scalars().all()
    for rule in rules:
        await client.delete_rule(rule.ext_id)
        await db.delete(rule)
    await client.close()
    await db.commit()
    return JSONResponse({"status": "ok"})

# --- OTHER ROUTES ---

@router.post("/create_folder")
async def create_folder(request: Request, folder_name: str = Form(...), device_id: str = Form(...), section: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not get_current_user(request): return RedirectResponse("/login", status_code=303)
    
    stmt = select(func.max(Folder.sort_order)).where(Folder.device_group_id == device_id)
    max_sort = (await db.execute(stmt)).scalar() or 0
    new_folder = Folder(id=str(uuid.uuid4()), name=folder_name, device_group_id=device_id, section=section, sort_order=max_sort + 1)
    db.add(new_folder)
    await db.commit()
    return RedirectResponse(url=f"/?folder_id={new_folder.id}", status_code=303)

@router.get("/", response_class=HTMLResponse)
async def index(request: Request, folder_id: str = Query(None), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user: return RedirectResponse(url="/login")

    stmt = select(Folder).options(selectinload(Folder.rules)).order_by(Folder.device_group_id, Folder.sort_order)
    result = await db.execute(stmt)
    all_folders = result.scalars().all()

    meta_res = await db.execute(select(DeviceMeta))
    device_names = {o.device_id: o.name for o in meta_res.scalars().all()}

    tree = {}
    first_folder_id = None
    first_device_id = None

    for f in all_folders:
        if not first_folder_id: first_folder_id = str(f.id)
        if not first_device_id: first_device_id = f.device_group_id
        
        gid = f.device_group_id or "unknown"
        dev_name = device_names.get(gid, f"Device {gid[:8]}")
        if gid not in tree: tree[gid] = {"name": dev_name, "id": gid, "sections": {"pre": [], "post": [], "default": []}}
        f.device_name = dev_name; f.rules_count = len(f.rules)
        sec = f.section.lower() if f.section and f.section.lower() in ['pre', 'post', 'default'] else 'pre'
        tree[gid]["sections"][sec].append(f)

    target_folder = next((f for f in all_folders if str(f.id) == folder_id), None)
    if folder_id and not target_folder:
        folder_id = first_folder_id
        target_folder = next((f for f in all_folders if str(f.id) == folder_id), None)

    selected_fid = folder_id or first_folder_id
    current_device_id = target_folder.device_group_id if target_folder else first_device_id

    dashboard_data = []
    
    all_objs = await db.execute(select(CachedObject.ext_id, CachedObject.name, CachedObject.data))
    class MockObj:
        def __init__(self, ext_id, name, data): self.ext_id = ext_id; self.name = name; self.data = data
    
    GLOBAL_NAME_MAP.clear()
    object_map = {}
    for row in all_objs.fetchall():
        obj = MockObj(row.ext_id, row.name, row.data)
        object_map[row.ext_id] = obj
        GLOBAL_NAME_MAP[row.ext_id] = row.name

    if target_folder:
        rules_processed = [rule_to_dict(r, object_map) for r in sorted(target_folder.rules, key=lambda x: x.folder_sort_order)]
        dashboard_data.append({"folder": target_folder, "rules": rules_processed})

    filtered_tree = {k: v for k, v in tree.items() if k != "global"}

    return templates.TemplateResponse(request, "index.html", {
        "request": request, "tree": filtered_tree, "dashboard_data": dashboard_data, 
        "selected_folder_id": selected_fid, "current_device_id": current_device_id,
        "user": user
    })

@router.get("/objects", response_class=HTMLResponse)
async def list_objects(request: Request, device_id: str = Query(None), page: int = Query(1), type_filter: str = Query('net'), db: AsyncSession = Depends(get_db)):
    if not get_current_user(request): return RedirectResponse(url="/login")
    
    PAGE_SIZE = 150
    meta_res = await db.execute(select(DeviceMeta).order_by(DeviceMeta.name))
    all_devices = meta_res.scalars().all()
    devices = [d for d in all_devices if d.device_id != "global"]

    if not device_id or device_id == 'global':
        selected_device_id = devices[0].device_id if devices else None
    else:
        selected_device_id = device_id

    name_res = await db.execute(select(CachedObject.ext_id, CachedObject.name))
    GLOBAL_NAME_MAP.clear()
    for row in name_res:
        GLOBAL_NAME_MAP[row.ext_id] = row.name

    query = select(CachedObject).where(CachedObject.device_group_id == selected_device_id)
    cat_map = {
        'net':     ['net', 'Network', 'Network Group', 'Host/Network'],
        'service': ['service', 'Service', 'Service Group'],
        'app':     ['app', 'Application'],
        'urlcat':  ['urlcat', 'URL Category'],
        'user':    ['user', 'User', 'User Group'],
        'zone':    ['zone', 'Zone', 'Security Zone'],
    }
    target_cats = cat_map.get(type_filter, [])
    if target_cats: query = query.where(CachedObject.category.in_(target_cats))
    
    count_stmt = select(func.count()).select_from(query.subquery('t'))
    total_items = (await db.execute(count_stmt)).scalar_one()
    total_pages = max(1, math.ceil(total_items / PAGE_SIZE))

    query = query.order_by(CachedObject.name).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
    objects = (await db.execute(query)).scalars().all()

    return templates.TemplateResponse(request, "objects.html", {
        "request": request, "devices": devices, "selected_device_id": selected_device_id,
        "objects": objects, "type_filter": type_filter, "page": page,
        "total_pages": total_pages, "total_items": total_items
    })


# ===========================================================================
#  OBJECTS CRUD
# ===========================================================================

class ObjectCreateRequest(BaseModel):
    device_group_id: str
    obj_type: str        # net_ip | net_range | net_fqdn | net_group | service | service_group | zone
    name: str
    ip_value: str = ""   # "192.168.1.0/24"
    range_start: str = ""
    range_end: str = ""
    fqdn: str = ""
    protocol: int = 6    # TCP=6, UDP=17, ICMP=1
    dst_port_start: int = 0
    dst_port_end: int = 0
    member_ids: List[str] = []


class ObjectDeleteRequest(BaseModel):
    ext_ids: List[str]


@router.post("/api/v1/objects/create")
async def create_object_endpoint(request: Request, data: ObjectCreateRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        dg_id = data.device_group_id
        name  = data.name.strip()

        if data.obj_type == 'net_ip':
            res = await client.create_network_object({"name": name, "deviceGroupId": dg_id,
                "networkIpAddress": {"value": data.ip_value}})
            type_lbl, cat = "Host/Network", "net"

        elif data.obj_type == 'net_range':
            res = await client.create_network_object({"name": name, "deviceGroupId": dg_id,
                "networkIpRange": {"start": data.range_start, "end": data.range_end}})
            type_lbl, cat = "Host/Network", "net"

        elif data.obj_type == 'net_fqdn':
            res = await client.create_network_object({"name": name, "deviceGroupId": dg_id,
                "networkFqdn": {"fqdn": data.fqdn}})
            type_lbl, cat = "Host/Network", "net"

        elif data.obj_type == 'net_group':
            res = await client.create_network_object_group({"name": name, "deviceGroupId": dg_id,
                "items": data.member_ids})
            type_lbl, cat = "Network Group", "net"

        elif data.obj_type == 'service':
            if data.dst_port_end and data.dst_port_end != data.dst_port_start:
                ports = [{"portRange": {"from": data.dst_port_start, "to": data.dst_port_end}}]
            elif data.dst_port_start:
                ports = [{"singlePort": {"port": data.dst_port_start}}]
            else:
                ports = []
            svc_payload: Dict[str, Any] = {"name": name, "deviceGroupId": dg_id, "protocol": data.protocol}
            if ports:
                svc_payload["dstPorts"] = ports
            res = await client.create_service(svc_payload)
            type_lbl, cat = "Service", "service"

        elif data.obj_type == 'service_group':
            res = await client.create_service_group({"name": name, "deviceGroupId": dg_id,
                "serviceIds": data.member_ids})
            type_lbl, cat = "Service Group", "service"

        elif data.obj_type == 'zone':
            res = await client.create_zone({"name": name, "deviceGroupId": dg_id})
            type_lbl, cat = "Security Zone", "zone"

        else:
            return JSONResponse({"status": "error", "message": f"Unknown obj_type: {data.obj_type}"}, status_code=400)

        # Extract ID from response (API sometimes nests it)
        ext_id = res.get("id")
        if not ext_id:
            for v in res.values():
                if isinstance(v, dict) and "id" in v:
                    ext_id = v["id"]
                    break
        if not ext_id:
            raise RuntimeError(f"API did not return object ID: {res}")

        db.add(CachedObject(ext_id=ext_id, name=name, type=type_lbl, category=cat,
                            device_group_id=dg_id, data=res))
        await db.commit()
        return JSONResponse({"status": "ok", "id": ext_id, "name": name})
    except Exception as e:
        logger.error(f"Object creation failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/objects/delete")
async def delete_objects_endpoint(request: Request, data: ObjectDeleteRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    stmt = select(CachedObject).where(CachedObject.ext_id.in_(data.ext_ids))
    objects = (await db.execute(stmt)).scalars().all()

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        failed = []
        for obj in objects:
            ok = await client.delete_object(obj.type, obj.ext_id)
            if ok:
                await db.delete(obj)
            else:
                failed.append(obj.name)
        await db.commit()
        if failed:
            return JSONResponse({"status": "partial", "failed": failed, "deleted": len(objects) - len(failed)})
        return JSONResponse({"status": "ok", "deleted": len(objects)})
    except Exception as e:
        logger.error(f"Object deletion failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# ===========================================================================
#  NAT RULES
# ===========================================================================

SNAT_LABELS = {
    "NAT_SOURCE_TRANSLATION_TYPE_NONE":           "None",
    "NAT_SOURCE_TRANSLATION_TYPE_DYNAMIC_IP_PORT": "PAT",
    "NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP":       "Static IP",
    "NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP_PORT":  "Static IP+Port",
}
DNAT_LABELS = {
    "NAT_DESTINATION_TRANSLATION_TYPE_NONE":         "None",
    "NAT_DESTINATION_TRANSLATION_TYPE_ADDRESS_POOL": "DNAT",
}


def nat_to_dict(rule: CachedNatRule, object_map: Dict[str, Any]) -> Dict[str, Any]:
    d = rule.data or {}

    def _extract(field_key: str):
        section = d.get(field_key)
        if not section:
            return []
        kind = section.get("kind", "")
        if "ANY" in kind:
            return []
        objects = section.get("objects", [])
        if isinstance(objects, dict):
            objects = objects.get("array", [])
        if not isinstance(objects, list):
            return []
        result = []
        for item in objects:
            if not isinstance(item, dict):
                continue
            if "id" in item:
                result.append((item["id"], item.get("name")))
            else:
                for v in item.values():
                    if isinstance(v, dict) and "id" in v:
                        result.append((v["id"], v.get("name")))
                        break
        return result

    def _render(field_key: str, css: str = "") -> str:
        items = _extract(field_key)
        if not items:
            return "Any"
        tags = []
        for uid, emb_name in items[:4]:
            cached = object_map.get(uid)
            name = (cached.name if cached else emb_name) or uid[:8]
            cls = f"obj-tag {css}".strip()
            tags.append(f"<span class='{cls}' title='{name}'>{name}</span>")
        extra = len(items) - 4
        result = "".join(tags)
        if extra > 0:
            result += f"<span class='obj-tag overflow'>+{extra}</span>"
        return result

    snat_raw = d.get("srcTranslationType", "")
    dnat_raw = d.get("dstTranslationType", "")

    return {
        "id":            rule.id,
        "ext_id":        rule.ext_id,
        "name":          rule.name,
        "folder_id":     rule.folder_id,
        "device_group_id": rule.device_group_id,
        "description":   d.get("description", ""),
        "enabled":       d.get("enabled", True),
        "snat_type":     SNAT_LABELS.get(snat_raw, snat_raw or "None"),
        "dnat_type":     DNAT_LABELS.get(dnat_raw, dnat_raw or "None"),
        "snat_raw":      snat_raw,
        "dnat_raw":      dnat_raw,
        "src_addr_type": d.get("srcTranslationAddrType", "NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_NONE"),
        "dst_translated_port": d.get("dstTranslatedPort", ""),
        "src_zone":  _render("sourceZone", "zone"),
        "src_net":   _render("sourceAddr"),
        "dst_zone":  _render("destinationZone", "zone"),
        "dst_net":   _render("destinationAddr"),
        "service":   _render("service", "service"),
        "is_modified": rule.is_modified or False,
        "modified_at": rule.modified_at or "",
        # raw IDs for edit modal
        "src_zone_ids":  [uid for uid, _ in _extract("sourceZone")],
        "dst_zone_ids":  [uid for uid, _ in _extract("destinationZone")],
        "src_net_ids":   [uid for uid, _ in _extract("sourceAddr")],
        "dst_net_ids":   [uid for uid, _ in _extract("destinationAddr")],
        "service_ids":   [uid for uid, _ in _extract("service")],
        "src_translated_ids": [uid for uid, _ in _extract("srcTranslatedAddress")] if isinstance(d.get("srcTranslatedAddress"), dict) else [],
        "dst_translated_ids": [uid for uid, _ in _extract("dstTranslatedAddress")] if isinstance(d.get("dstTranslatedAddress"), dict) else [],
    }


class NatCreateRequest(BaseModel):
    folder_id: str
    name: str
    description: str = ""
    enabled: bool = True
    src_zone_ids: List[str] = []
    dst_zone_ids: List[str] = []
    src_net_ids: List[str] = []
    dst_net_ids: List[str] = []
    service_ids: List[str] = []
    snat_type: str = "NAT_SOURCE_TRANSLATION_TYPE_NONE"
    src_addr_type: str = "NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_NONE"
    src_translated_ids: List[str] = []
    dnat_type: str = "NAT_DESTINATION_TRANSLATION_TYPE_NONE"
    dst_translated_ids: List[str] = []
    dst_translated_port: int = 0


class NatDeleteRequest(BaseModel):
    rule_ids: List[str]


class NatReorderRequest(BaseModel):
    folder_id: str
    rule_ids: List[str]


class NatToggleRequest(BaseModel):
    rule_id: str
    enabled: bool


@router.get("/nat", response_class=HTMLResponse)
async def nat_page(request: Request, folder_id: str = Query(None), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    stmt = select(NatFolder).options(selectinload(NatFolder.rules)).order_by(NatFolder.device_group_id, NatFolder.sort_order)
    all_folders = (await db.execute(stmt)).scalars().all()

    meta_res = await db.execute(select(DeviceMeta))
    device_names = {o.device_id: o.name for o in meta_res.scalars().all()}

    tree: Dict[str, Any] = {}
    first_folder_id = None
    first_device_id = None

    for f in all_folders:
        if not first_folder_id:
            first_folder_id = str(f.id)
        if not first_device_id:
            first_device_id = f.device_group_id
        gid = f.device_group_id or "unknown"
        dev_name = device_names.get(gid, f"Device {gid[:8]}")
        if gid not in tree:
            tree[gid] = {"name": dev_name, "id": gid, "sections": {"pre": [], "post": [], "default": []}}
        f.device_name = dev_name
        f.rules_count = len(f.rules)
        sec = f.section.lower() if f.section and f.section.lower() in ['pre', 'post', 'default'] else 'pre'
        tree[gid]["sections"][sec].append(f)

    target_folder = next((f for f in all_folders if str(f.id) == folder_id), None)
    if folder_id and not target_folder:
        folder_id = first_folder_id
        target_folder = next((f for f in all_folders if str(f.id) == folder_id), None)

    selected_fid = folder_id or first_folder_id
    current_device_id = target_folder.device_group_id if target_folder else first_device_id

    all_objs = await db.execute(select(CachedObject.ext_id, CachedObject.name, CachedObject.data))

    class MockObj:
        def __init__(self, ext_id, name, data):
            self.ext_id = ext_id; self.name = name; self.data = data

    object_map: Dict[str, Any] = {}
    for row in all_objs.fetchall():
        object_map[row.ext_id] = MockObj(row.ext_id, row.name, row.data)

    dashboard_data = []
    if target_folder:
        rules_sorted = sorted(target_folder.rules, key=lambda x: x.folder_sort_order)
        dashboard_data.append({
            "folder": target_folder,
            "rules": [nat_to_dict(r, object_map) for r in rules_sorted],
        })

    filtered_tree = {k: v for k, v in tree.items() if k != "global"}

    return templates.TemplateResponse(request, "nat.html", {
        "request": request, "tree": filtered_tree, "dashboard_data": dashboard_data,
        "selected_folder_id": selected_fid, "current_device_id": current_device_id,
        "user": user,
    })


@router.post("/nat/create_folder")
async def create_nat_folder(
    request: Request,
    folder_name: str = Form(...),
    device_id: str = Form(...),
    section: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if not get_current_user(request):
        return RedirectResponse("/login", status_code=303)
    stmt = select(func.max(NatFolder.sort_order)).where(NatFolder.device_group_id == device_id)
    max_sort = (await db.execute(stmt)).scalar() or 0
    new_folder = NatFolder(
        id=str(uuid.uuid4()),
        name=folder_name,
        device_group_id=device_id,
        section=section,
        sort_order=max_sort + 1,
    )
    db.add(new_folder)
    await db.commit()
    return RedirectResponse(url=f"/nat?folder_id={new_folder.id}", status_code=303)


@router.post("/nat/deploy")
async def deploy_nat(request: Request, device_id: str = Form(...), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        from app.services.nat_service import NatDeployService
        await NatDeployService().deploy_nat_policy(db, client, device_id)
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"NAT deploy failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.get("/api/v1/nat/folders/tree")
async def nat_folders_tree(device_group_id: str = Query(None), db: AsyncSession = Depends(get_db)):
    stmt = select(NatFolder).where(NatFolder.device_group_id == device_group_id).order_by(NatFolder.section, NatFolder.sort_order)
    folders = (await db.execute(stmt)).scalars().all()
    return JSONResponse([{"id": f.id, "name": f.name, "section": f.section} for f in folders])


@router.post("/api/v1/nat/rules/create")
async def create_nat_rule_endpoint(request: Request, data: NatCreateRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    folder = await db.get(NatFolder, data.folder_id)
    if not folder:
        return JSONResponse({"status": "error", "message": "Folder not found"}, status_code=404)

    def build_field(ids):
        if not ids:
            return {"kind": "RULE_KIND_ANY", "objects": {"array": []}}
        return {"kind": "RULE_KIND_LIST", "objects": {"array": list(ids)}}

    section = (folder.section or "pre").lower()

    api_payload: Dict[str, Any] = {
        "name": data.name,
        "description": data.description,
        "deviceGroupId": folder.device_group_id,
        "precedence": section,
        "position": 1,
        "enabled": data.enabled,
        "srcTranslationType": data.snat_type,
        "srcTranslationAddrType": data.src_addr_type,
        "dstTranslationType": data.dnat_type,
        "sourceZone":      build_field(data.src_zone_ids),
        "sourceAddr":      build_field(data.src_net_ids),
        "destinationZone": build_field(data.dst_zone_ids),
        "destinationAddr": build_field(data.dst_net_ids),
        "service":         build_field(data.service_ids),
    }
    if data.src_translated_ids:
        api_payload["srcTranslatedAddress"] = data.src_translated_ids
    if data.dst_translated_ids:
        api_payload["dstTranslatedAddress"] = data.dst_translated_ids
    if data.dst_translated_port:
        api_payload["dstTranslatedPort"] = data.dst_translated_port

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        res = await client.create_nat_rule(api_payload)
        ext_id = res.get("id")
        if not ext_id:
            raise RuntimeError(f"API did not return NAT rule ID: {res}")

        stmt = select(func.max(CachedNatRule.folder_sort_order)).where(CachedNatRule.folder_id == data.folder_id)
        max_pos = (await db.execute(stmt)).scalar() or 0

        db.add(CachedNatRule(
            id=str(uuid.uuid4()),
            ext_id=ext_id,
            name=data.name,
            folder_id=data.folder_id,
            folder_sort_order=max_pos + 1,
            device_group_id=folder.device_group_id,
            data={**api_payload, "id": ext_id},
        ))
        await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"NAT rule creation failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/nat/rules/delete")
async def delete_nat_rules(request: Request, data: NatDeleteRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        stmt = select(CachedNatRule).where(CachedNatRule.id.in_(data.rule_ids))
        rules = (await db.execute(stmt)).scalars().all()
        for rule in rules:
            await client.delete_nat_rule(rule.ext_id)
            await db.delete(rule)
        await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"NAT delete failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/nat/rules/reorder")
async def reorder_nat_rules(data: NatReorderRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(CachedNatRule).where(CachedNatRule.id.in_(data.rule_ids))
    rules = (await db.execute(stmt)).scalars().all()
    rule_map = {r.id: r for r in rules}
    for index, r_id in enumerate(data.rule_ids):
        if r_id in rule_map:
            rule_map[r_id].folder_id = data.folder_id
            rule_map[r_id].folder_sort_order = index
    await db.commit()
    return JSONResponse({"status": "ok"})


@router.post("/api/v1/nat/rules/toggle")
async def toggle_nat_rule(request: Request, data: NatToggleRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    rule = await db.get(CachedNatRule, data.rule_id)
    if not rule:
        return JSONResponse({"status": "error", "message": "NAT rule not found"}, status_code=404)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        await client.update_rule(rule.ext_id, {"id": rule.ext_id, "enabled": data.enabled})
        if rule.data:
            rule.data = {**rule.data, "enabled": data.enabled}
        await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"NAT toggle failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()







# ===========================================================================
#  LOGS & MONITORING
# ===========================================================================

@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, device_id: str = Query(None), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
    meta_res = await db.execute(select(DeviceMeta).order_by(DeviceMeta.name))
    all_devices = [d for d in meta_res.scalars().all() if d.device_id != "global"]
    selected = device_id or (all_devices[0].device_id if all_devices else "")
    return templates.TemplateResponse(request, "logs.html", {
        "request": request, "user": user,
        "devices": all_devices, "selected_device_id": selected,
        "log_ttl_hours": 1,
    })


# ---- Helpers ----

def _extract_log_fields(row: Dict[str, Any], log_type: str) -> Dict[str, Any]:
    """Pull indexed fields out of a raw NGFW log entry."""
    def _g(*keys):
        for k in keys:
            v = row.get(k)
            if v is not None and v != "":
                return v
        return None

    src_ip   = _g("srcAddr", "sourceAddress", "srcAddress", "srcIp")
    dst_ip   = _g("dstAddr", "dstAddress", "dstIp")
    dst_port = _g("dstPort")
    action   = _g("action", "ruleAction", "verdict")
    ts_raw   = _g("entryGeneration", "entryReceived", "sessionStart", "generateTime", "timestamp")

    event_time = None
    if ts_raw:
        try:
            if isinstance(ts_raw, (int, float)):
                event_time = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            else:
                s = str(ts_raw).replace("Z", "+00:00")
                event_time = datetime.fromisoformat(s)
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    try:
        dst_port_int = int(dst_port) if dst_port is not None else None
    except (ValueError, TypeError):
        dst_port_int = None

    return {
        "src_ip":     str(src_ip)[:64]    if src_ip    else None,
        "dst_ip":     str(dst_ip)[:64]    if dst_ip    else None,
        "dst_port":   dst_port_int,
        "action":     str(action)[:64]    if action    else None,
        "event_time": event_time,
    }


def _build_log_query(stmt, log_type: str, src_ip=None, dst_ip=None, dst_port=None,
                     action=None, time_from=None, time_to=None, search=None):
    """Apply SQL filters to a CachedLog SELECT statement."""
    if src_ip:
        stmt = stmt.where(CachedLog.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:
        stmt = stmt.where(CachedLog.dst_ip.ilike(f"%{dst_ip}%"))
    if dst_port:
        try:
            stmt = stmt.where(CachedLog.dst_port == int(dst_port))
        except ValueError:
            pass
    if action:
        stmt = stmt.where(CachedLog.action.ilike(f"%{action}%"))
    if time_from:
        try:
            tf = datetime.fromisoformat(time_from.replace("Z", "+00:00"))
            if tf.tzinfo is None:
                tf = tf.replace(tzinfo=timezone.utc)
            stmt = stmt.where(CachedLog.event_time >= tf)
        except Exception:
            pass
    if time_to:
        try:
            tt = datetime.fromisoformat(time_to.replace("Z", "+00:00"))
            if tt.tzinfo is None:
                tt = tt.replace(tzinfo=timezone.utc)
            stmt = stmt.where(CachedLog.event_time <= tt)
        except Exception:
            pass
    return stmt


# ---- Pydantic models for log endpoints ----

class LogFetchRequest(BaseModel):
    device_group_id: str
    log_type:        str            # traffic / ips / av / audit
    period_hours:    int = 1        # fallback if time_from/time_to not set
    confirmed_24h:   bool = False   # must be True for spans > 6h
    time_from:       Optional[str] = None  # ISO UTC — overrides period_hours
    time_to:         Optional[str] = None  # ISO UTC
    src_ip:          Optional[str] = None
    dst_ip:          Optional[str] = None
    dst_port:        Optional[int] = None
    action:          Optional[str] = None

class LogBrowseRequest(BaseModel):
    device_group_id: str
    log_type:        str
    limit:           int = 100
    offset:          int = 0
    src_ip:          Optional[str] = None
    dst_ip:          Optional[str] = None
    dst_port:        Optional[int] = None
    action:          Optional[str] = None
    time_from:       Optional[str] = None
    time_to:         Optional[str] = None

class LogClearRequest(BaseModel):
    device_group_id: str
    log_type:        Optional[str] = None  # None = clear all types


# ---- Fetch from NGFW → store in cache ----

@router.post("/api/v1/logs/fetch")
async def fetch_logs(request: Request, data: LogFetchRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)

    if data.time_from and data.time_to:
        # Custom time range supplied directly from UI date pickers
        try:
            tf = datetime.fromisoformat(data.time_from.replace("Z", "+00:00"))
            tt = datetime.fromisoformat(data.time_to.replace("Z", "+00:00"))
            if tf.tzinfo is None: tf = tf.replace(tzinfo=timezone.utc)
            if tt.tzinfo is None: tt = tt.replace(tzinfo=timezone.utc)
            if tf >= tt:
                return JSONResponse({"status": "error", "message": "time_from must be before time_to"}, status_code=400)
        except Exception:
            return JSONResponse({"status": "error", "message": "Invalid time_from/time_to format"}, status_code=400)
        time_from = tf.strftime("%Y-%m-%dT%H:%M:%SZ")
        time_to   = tt.strftime("%Y-%m-%dT%H:%M:%SZ")
        hours_span = max(1, (tt - tf).total_seconds() / 3600)
        if hours_span > 6 and not data.confirmed_24h:
            return JSONResponse({
                "status": "warn_24h",
                "message": f"Выгрузка {round(hours_span, 1)}ч логов может занять время. Подтвердите.",
            })
        max_records = min(20_000, max(2_000, int(hours_span * 1_000)))
    else:
        # Fallback: period_hours relative to now
        period = data.period_hours if data.period_hours > 0 else 1
        if period > 6 and not data.confirmed_24h:
            return JSONResponse({
                "status": "warn_24h",
                "message": f"Выгрузка {period}ч логов может занять время. Подтвердите.",
            })
        time_to   = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        # +12h lookback buffer: NGFW collector may have indexing lag
        time_from = (now_utc - timedelta(hours=period + 12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        max_records = min(20_000, max(2_000, period * 1_000))

    extra_filters: Dict[str, Any] = {}
    if data.src_ip:   extra_filters["srcAddr"]  = data.src_ip
    if data.dst_ip:   extra_filters["dstAddr"]  = data.dst_ip
    if data.dst_port: extra_filters["dstPort"]  = data.dst_port
    if data.action:   extra_filters["action"]   = data.action

    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        raw_logs = await client.fetch_all_logs(
            log_type        = data.log_type,
            device_group_id = data.device_group_id,
            time_from       = time_from,
            time_to         = time_to,
            extra_filters   = extra_filters,
            max_records     = max_records,
        )
    except Exception as e:
        logger.error(f"fetch_all_logs failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()

    # Clear existing cache for this device+type before inserting fresh data
    await db.execute(
        sa_delete(CachedLog).where(
            CachedLog.device_group_id == data.device_group_id,
            CachedLog.log_type == data.log_type,
        )
    )

    fetched_at = datetime.now(timezone.utc)
    batch = []
    for row in raw_logs:
        fields = _extract_log_fields(row, data.log_type)
        batch.append(CachedLog(
            device_group_id = data.device_group_id,
            log_type        = data.log_type,
            event_time      = fields["event_time"],
            src_ip          = fields["src_ip"],
            dst_ip          = fields["dst_ip"],
            dst_port        = fields["dst_port"],
            action          = fields["action"],
            data            = row,
            fetched_at      = fetched_at,
        ))

    if batch:
        db.add_all(batch)
    await db.commit()

    logger.info(f"Fetched and cached {len(batch)} {data.log_type} logs for {data.device_group_id}")
    return JSONResponse({
        "status":     "ok",
        "fetched":    len(raw_logs),
        "stored":     len(batch),
        "period_hours": data.period_hours,
        "fetched_at": fetched_at.isoformat(),
    })


# ---- Query from cache ----

@router.post("/api/v1/logs/query")
async def query_logs(request: Request, data: LogBrowseRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    base = (
        select(CachedLog)
        .where(CachedLog.device_group_id == data.device_group_id)
        .where(CachedLog.log_type == data.log_type)
    )
    base = _build_log_query(base, data.log_type, data.src_ip, data.dst_ip,
                            data.dst_port, data.action, data.time_from, data.time_to)

    # total count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # paginated items
    rows_stmt = (
        base
        .order_by(CachedLog.event_time.desc().nullslast(), CachedLog.id.desc())
        .limit(data.limit)
        .offset(data.offset)
    )
    rows = (await db.execute(rows_stmt)).scalars().all()
    if rows:
        logger.info(f"[query] First row data sample: {str(rows[0].data)[:500]}")
        logger.info(f"[query] First row data type: {type(rows[0].data)}")

    # Cache meta
    meta_stmt = (
        select(func.count(), func.max(CachedLog.fetched_at),
               func.min(CachedLog.event_time), func.max(CachedLog.event_time))
        .where(CachedLog.device_group_id == data.device_group_id)
        .where(CachedLog.log_type == data.log_type)
    )
    meta = (await db.execute(meta_stmt)).one()
    cache_count, last_fetched, oldest_ev, newest_ev = meta[0], meta[1], meta[2], meta[3]

    purge_in_sec = None
    if last_fetched:
        purge_at = last_fetched.replace(tzinfo=timezone.utc) + timedelta(hours=1)
        purge_in_sec = max(0, int((purge_at - datetime.now(timezone.utc)).total_seconds()))

    return JSONResponse({
        "status":        "ok",
        "items":         [r.data for r in rows],
        "total":         total,
        "cache_count":   cache_count,
        "fetched_at":    last_fetched.isoformat() if last_fetched else None,
        "purge_in_sec":  purge_in_sec,
        "oldest_event":  oldest_ev.isoformat() if oldest_ev else None,
        "newest_event":  newest_ev.isoformat() if newest_ev else None,
    })


# ---- Status ----

@router.get("/api/v1/logs/status")
async def logs_status(request: Request, device_group_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)

    result = {}
    for lt in ("traffic", "ips", "av", "audit"):
        stmt = (
            select(func.count(), func.max(CachedLog.fetched_at), func.min(CachedLog.event_time), func.max(CachedLog.event_time))
            .where(CachedLog.device_group_id == device_group_id)
            .where(CachedLog.log_type == lt)
        )
        row = (await db.execute(stmt)).one()
        count, last_fetch, oldest_ev, newest_ev = row
        purge_in = None
        if last_fetch:
            purge_at = last_fetch.replace(tzinfo=timezone.utc) + timedelta(hours=1)
            purge_in = max(0, int((purge_at - datetime.now(timezone.utc)).total_seconds()))
        result[lt] = {
            "count":       count,
            "fetched_at":  last_fetch.isoformat() if last_fetch else None,
            "oldest_event": oldest_ev.isoformat() if oldest_ev else None,
            "newest_event": newest_ev.isoformat() if newest_ev else None,
            "purge_in_sec": purge_in,
        }
    return JSONResponse({"status": "ok", "types": result})


# ---- Manual clear ----

@router.post("/api/v1/logs/clear")
async def clear_logs(request: Request, data: LogClearRequest, db: AsyncSession = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)

    stmt = sa_delete(CachedLog).where(CachedLog.device_group_id == data.device_group_id)
    if data.log_type:
        stmt = stmt.where(CachedLog.log_type == data.log_type)
    result = await db.execute(stmt)
    await db.commit()
    return JSONResponse({"status": "ok", "deleted": result.rowcount})


# ---- Export CSV (server-side streaming) ----

@router.get("/api/v1/logs/export")
async def export_logs_csv(
    request: Request,
    device_group_id: str = Query(...),
    log_type:        str = Query(...),
    src_ip:          Optional[str] = Query(None),
    dst_ip:          Optional[str] = Query(None),
    dst_port:        Optional[int] = Query(None),
    action:          Optional[str] = Query(None),
    time_from:       Optional[str] = Query(None),
    time_to:         Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)

    stmt = (
        select(CachedLog)
        .where(CachedLog.device_group_id == device_group_id)
        .where(CachedLog.log_type == log_type)
        .order_by(CachedLog.event_time.desc().nullslast(), CachedLog.id.desc())
    )
    stmt = _build_log_query(stmt, log_type, src_ip, dst_ip, dst_port, action, time_from, time_to)
    rows = (await db.execute(stmt)).scalars().all()

    # Column definitions per log type
    COL_KEYS = {
        "traffic": [("Time","entryGeneration","entryReceived","sessionStart"),
                    ("Context","contextName","deviceName"),
                    ("Src IP","srcAddr"),("Src Port","srcPort"),
                    ("Dst IP","dstAddr"),("Dst Port","dstPort"),
                    ("Protocol","ipProtocol"),("App","app"),
                    ("Action","action"),("Rule","securityRuleName"),
                    ("Bytes Sent","bytesSent"),("Bytes Recv","bytesReceived")],
        "ips":     [("Time","entryGeneration","entryReceived"),
                    ("Context","contextName","deviceName"),
                    ("Src IP","srcAddr"),("Src Port","srcPort"),
                    ("Dst IP","dstAddr"),("Dst Port","dstPort"),
                    ("Threat","threatName"),("Severity","threatSeverity"),
                    ("Action","action"),("Protocol","ipProtocol")],
        "av":      [("Time","entryGeneration","entryReceived"),
                    ("Context","contextName","deviceName"),
                    ("Src IP","srcAddr"),("Dst IP","dstAddr"),
                    ("Threat","threatName"),("File","fileName"),("Action","action")],
        "audit":   [("Time","generateTime"),
                    ("Admin","adminDisplayName","adminLogin"),
                    ("Action","action"),("Source IP","sourceAddress"),
                    ("Args","queryArgs"),("Result","result")],
    }
    cols = COL_KEYS.get(log_type, [("Time","entryGeneration"),("Src","srcAddr"),("Dst","dstAddr"),("Action","action")])

    def _g(d, *keys):
        for k in keys:
            v = d.get(k)
            if v is not None:
                return str(v)
        return ""

    def _generate():
        buf = io.StringIO()
        buf.write("﻿")  # BOM for Excel
        writer = csv.writer(buf)
        writer.writerow([c[0] for c in cols])
        yield buf.getvalue()

        for r in rows:
            buf = io.StringIO()
            writer = csv.writer(buf)
            d = r.data or {}
            writer.writerow([_g(d, *c[1:]) for c in cols])
            yield buf.getvalue()

    filename = f"logs_{log_type}_{device_group_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return StreamingResponse(
        _generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/v1/logs/rule_stats")
async def get_rule_stats_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse([], status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        stats = await client.get_rule_stats(device_group_id)
        return JSONResponse(stats)
    except Exception as e:
        logger.error(f"Rule stats failed: {e}")
        return JSONResponse([])
    finally:
        await client.close()


# =====================================================================
# BLOCK 5 — Policy Rules (Decryption / Authentication / PBR)
# =====================================================================

class PolicyListRequest(BaseModel):
    device_group_id: str
    tab: str  # "decryption" | "auth" | "pbr"

class PolicyCreateRequest(BaseModel):
    device_group_id: str
    tab: str
    payload: Dict[str, Any]

class PolicyDeleteRequest(BaseModel):
    device_group_id: str
    tab: str
    ids: List[str]

class PolicyToggleRequest(BaseModel):
    device_group_id: str
    tab: str
    rule_id: str
    enabled: bool


@router.get("/policy", response_class=HTMLResponse)
async def policy_page(
    request: Request,
    device_id: str = Query(None),
    tab: str = Query("decryption"),
    db: AsyncSession = Depends(get_db),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    meta_res = await db.execute(select(DeviceMeta).order_by(DeviceMeta.name))
    all_devices = meta_res.scalars().all()
    devices = [d for d in all_devices if d.device_id != "global"]

    selected_device_id = device_id or (devices[0].device_id if devices else None)

    obj_res = await db.execute(select(CachedObject))
    all_objs = obj_res.scalars().all()

    def _filter_objs(types):
        return [
            {"id": o.ext_id, "name": o.name}
            for o in all_objs
            if o.device_group_id in (selected_device_id, "global") and o.type in types
        ]

    net_objects  = _filter_objs({"Host/Network", "Network", "Network Group"})
    svc_objects  = _filter_objs({"Service", "Service Group"})
    zone_objects = _filter_objs({"Security Zone", "Zone"})

    return templates.TemplateResponse(request, "policy.html", {
        "request": request,
        "devices": devices,
        "selected_device_id": selected_device_id,
        "active_tab": tab,
        "user": user,
        "net_objects": net_objects,
        "svc_objects": svc_objects,
        "zone_objects": zone_objects,
    })


@router.post("/api/v1/policy/list")
async def list_policy_rules(request: Request, data: PolicyListRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        if data.tab == "decryption":
            rules = await client.list_decryption_rules(data.device_group_id)
        elif data.tab == "auth":
            rules = await client.list_auth_rules(data.device_group_id)
        elif data.tab == "pbr":
            rules = await client.list_pbr_rules(data.device_group_id)
        else:
            return JSONResponse({"status": "error", "message": f"Unknown tab: {data.tab}"}, status_code=400)
        return JSONResponse({"status": "ok", "rules": rules})
    except Exception as e:
        logger.error(f"Policy list ({data.tab}) failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/policy/create")
async def create_policy_rule(request: Request, data: PolicyCreateRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        if data.tab == "decryption":
            result = await client.create_decryption_rule(data.payload)
        elif data.tab == "auth":
            result = await client.create_auth_rule(data.payload)
        elif data.tab == "pbr":
            result = await client.create_pbr_rule(data.payload)
        else:
            return JSONResponse({"status": "error", "message": f"Unknown tab: {data.tab}"}, status_code=400)
        return JSONResponse({"status": "ok", "rule": result})
    except Exception as e:
        logger.error(f"Policy create ({data.tab}) failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/policy/delete")
async def delete_policy_rules(request: Request, data: PolicyDeleteRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        failed = []
        for rule_id in data.ids:
            if data.tab == "decryption":
                ok = await client.delete_decryption_rule(rule_id)
            elif data.tab == "auth":
                ok = await client.delete_auth_rule(rule_id)
            elif data.tab == "pbr":
                ok = await client.delete_pbr_rule(rule_id)
            else:
                ok = False
            if not ok:
                failed.append(rule_id)
        if failed:
            return JSONResponse({"status": "partial", "failed": failed})
        return JSONResponse({"status": "ok", "deleted": len(data.ids)})
    except Exception as e:
        logger.error(f"Policy delete ({data.tab}) failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/policy/toggle")
async def toggle_policy_rule(request: Request, data: PolicyToggleRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        if data.tab == "decryption":
            ok = await client.toggle_decryption_rule(data.rule_id, data.enabled)
        elif data.tab == "auth":
            ok = await client.toggle_auth_rule(data.rule_id, data.enabled)
        elif data.tab == "pbr":
            ok = await client.toggle_pbr_rule(data.rule_id, data.enabled)
        else:
            ok = False
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        logger.error(f"Policy toggle ({data.tab}) failed: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# =====================================================================
# BLOCK 6 — System Management (Admins / Backup / Routing / Interfaces / Settings)
# =====================================================================

class AdminCreateRequest(BaseModel):
    device_group_id: str
    login: str
    name: str
    password: str
    role: str = "ReadOnly"

class AdminActionRequest(BaseModel):
    device_group_id: str
    admin_id: str
    action: str  # "delete" | "block" | "unblock"

class AdminPasswordRequest(BaseModel):
    device_group_id: str
    admin_id: str
    new_password: str

class BackupCreateRequest(BaseModel):
    device_group_id: str
    description: str = ""

class BackupDeleteRequest(BaseModel):
    device_group_id: str
    backup_id: str

class SnapshotCommitRequest(BaseModel):
    device_group_id: str
    description: str = ""

class RouteCreateRequest(BaseModel):
    device_group_id: str
    destination: str
    prefix_len: int
    gateway: str
    interface: str = ""
    metric: int = 1
    description: str = ""

class RouteDeleteRequest(BaseModel):
    device_group_id: str
    route_id: str

class TimeoutsSetRequest(BaseModel):
    device_group_id: str
    tcp: Optional[int] = None
    udp: Optional[int] = None
    icmp: Optional[int] = None
    tcp_half_open: Optional[int] = None
    tcp_time_wait: Optional[int] = None
    udp_stream: Optional[int] = None


def _sys_client_from_request(request: Request):
    user = get_current_user(request)
    if not user:
        return None, None
    return user, NGFWClient(user['host'], verify_ssl=False)


@router.get("/system", response_class=HTMLResponse)
async def system_page(
    request: Request,
    device_id: str = Query(None),
    tab: str = Query("admins"),
    db: AsyncSession = Depends(get_db),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    meta_res = await db.execute(select(DeviceMeta).order_by(DeviceMeta.name))
    all_devices = meta_res.scalars().all()
    devices = [d for d in all_devices if d.device_id != "global"]
    selected_device_id = device_id or (devices[0].device_id if devices else None)

    return templates.TemplateResponse(request, "system.html", {
        "request": request,
        "devices": devices,
        "selected_device_id": selected_device_id,
        "active_tab": tab,
        "user": user,
    })


# ---- Admins ----

@router.get("/api/v1/system/admins")
async def list_admins_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        admins = await client.list_admins(device_group_id)
        return JSONResponse({"status": "ok", "admins": admins})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/admins/create")
async def create_admin_endpoint(request: Request, data: AdminCreateRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        payload = {
            "login": data.login, "name": data.name,
            "password": data.password, "role": data.role,
            "deviceGroupId": data.device_group_id,
        }
        result = await client.create_admin(payload)
        return JSONResponse({"status": "ok", "admin": result})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/admins/action")
async def admin_action_endpoint(request: Request, data: AdminActionRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        if data.action == "delete":
            ok = await client.delete_admin(data.admin_id)
        elif data.action == "block":
            ok = await client.block_admin(data.admin_id)
        elif data.action == "unblock":
            ok = await client.unblock_admin(data.admin_id)
        else:
            return JSONResponse({"status": "error", "message": f"Unknown action: {data.action}"}, status_code=400)
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/admins/password")
async def admin_password_endpoint(request: Request, data: AdminPasswordRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        ok = await client.update_admin_credentials(data.admin_id, {"password": data.new_password})
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# ---- Backup & Snapshot ----

@router.get("/api/v1/system/backups")
async def list_backups_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        backups = await client.list_backups(device_group_id)
        snapshots = await client.list_snapshots(device_group_id)
        return JSONResponse({"status": "ok", "backups": backups, "snapshots": snapshots})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/backups/create")
async def create_backup_endpoint(request: Request, data: BackupCreateRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        result = await client.create_backup(data.device_group_id, data.description)
        return JSONResponse({"status": "ok", "backup": result})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/backups/delete")
async def delete_backup_endpoint(request: Request, data: BackupDeleteRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        ok = await client.delete_backup(data.backup_id)
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/snapshots/commit")
async def commit_snapshot_endpoint(request: Request, data: SnapshotCommitRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        result = await client.commit_snapshot(data.device_group_id, data.description)
        return JSONResponse({"status": "ok", "snapshot": result})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# ---- Routing ----

@router.get("/api/v1/system/routing")
async def get_routing_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        routes, bgp_info, bgp_peers, ospf_info, ospf_areas = await asyncio.gather(
            client.list_static_routes(device_group_id),
            client.get_bgp(device_group_id),
            client.list_bgp_peers(device_group_id),
            client.get_ospf(device_group_id),
            client.list_ospf_areas(device_group_id),
            return_exceptions=True,
        )
        return JSONResponse({
            "status": "ok",
            "routes":     routes     if isinstance(routes, list)     else [],
            "bgp_info":   bgp_info   if isinstance(bgp_info, dict)   else {},
            "bgp_peers":  bgp_peers  if isinstance(bgp_peers, list)  else [],
            "ospf_info":  ospf_info  if isinstance(ospf_info, dict)  else {},
            "ospf_areas": ospf_areas if isinstance(ospf_areas, list) else [],
        })
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/routing/create")
async def create_route_endpoint(request: Request, data: RouteCreateRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        payload = {
            "deviceGroupId": data.device_group_id,
            "destination": data.destination,
            "prefixLen": data.prefix_len,
            "gateway": data.gateway,
            "metric": data.metric,
        }
        if data.interface:
            payload["interface"] = data.interface
        if data.description:
            payload["description"] = data.description
        result = await client.create_static_route(payload)
        return JSONResponse({"status": "ok", "route": result})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/routing/delete")
async def delete_route_endpoint(request: Request, data: RouteDeleteRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        ok = await client.delete_static_route(data.route_id)
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# ---- Interfaces ----

@router.get("/api/v1/system/interfaces")
async def list_interfaces_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        virtual, logical = await asyncio.gather(
            client.list_virtual_interfaces(device_group_id),
            client.list_logical_interfaces(device_group_id),
            return_exceptions=True,
        )
        vlist = virtual if isinstance(virtual, list) else []
        llist = logical if isinstance(logical, list) else []
        for i in vlist: i['_itype'] = 'Virtual'
        for i in llist: i['_itype'] = 'Logical'
        return JSONResponse({"status": "ok", "interfaces": vlist + llist})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


# ---- Timeouts / Settings ----

@router.get("/api/v1/system/timeouts")
async def get_timeouts_endpoint(request: Request, device_group_id: str = Query(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        data = await client.get_device_timeouts(device_group_id)
        return JSONResponse({"status": "ok", "timeouts": data})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()


@router.post("/api/v1/system/timeouts/set")
async def set_timeouts_endpoint(request: Request, data: TimeoutsSetRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"status": "error"}, status_code=401)
    client = NGFWClient(user['host'], verify_ssl=False)
    try:
        await client.login(user['username'], user['password'])
        payload = {k: v for k, v in {
            "tcp": data.tcp, "udp": data.udp, "icmp": data.icmp,
            "tcpHalfOpen": data.tcp_half_open,
            "tcpTimeWait": data.tcp_time_wait,
            "udpStream":   data.udp_stream,
        }.items() if v is not None}
        ok = await client.set_device_timeouts(data.device_group_id, payload)
        return JSONResponse({"status": "ok" if ok else "error"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        await client.close()
