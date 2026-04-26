from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import Folder, CachedObject
from app.services.rule_service import RuleService
from app.services.sync_service import SyncService
from app.infrastructure.ngfw_client import NGFWClient

router = APIRouter()

# --- Schemas ---

class SyncRequest(BaseModel):
    host: str
    username: str
    password: str
    port: int = 443

class FolderCreate(BaseModel):
    name: str
    gid: Optional[str] = None
    device_group_id: Optional[str] = None
    section: str = "pre"
    parent_id: Optional[str] = None

class ReorderRequest(BaseModel):
    folder_id: Optional[str]
    rule_ids: List[str]

class RuleToggle(BaseModel):
    enabled: bool

# --- Endpoints ---

@router.post("/sync")
async def sync_rules_endpoint(
    payload: SyncRequest,
    db: AsyncSession = Depends(get_db)
):
    base_url = f"https://{payload.host}:{payload.port}"
    client = NGFWClient(base_url=base_url, verify_ssl=False)
    
    try:
        await client.login(payload.username, payload.password)
        service = SyncService()
        await service.sync_all(db, client)
        return {"status": "success", "message": f"Synced from {payload.host}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await client.close()

@router.post("/folders/create")
async def create_folder(payload: FolderCreate, db: AsyncSession = Depends(get_db)):
    service = RuleService(db)
    gid = payload.gid if payload.gid else payload.device_group_id
    return await service.create_folder(payload.name, gid, payload.section, payload.parent_id)

@router.get("/folders/tree")
async def get_folders_tree(
    device_group_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Р’РѕР·РІСЂР°С‰Р°РµС‚ СЃРїРёСЃРѕРє РїР°РїРѕРє.
    Р•СЃР»Рё РїРµСЂРµРґР°РЅ device_group_id, РІРѕР·РІСЂР°С‰Р°РµС‚ РїР°РїРєРё С‚РѕР»СЊРєРѕ СЌС‚РѕРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІР°.
    """
    # 1. РћСЃРЅРѕРІРЅРѕР№ Р·Р°РїСЂРѕСЃ РїР°РїРѕРє
    query = select(Folder).order_by(Folder.sort_order)
    
    if device_group_id:
        query = query.where(Folder.device_group_id == device_group_id)
        
    result = await db.execute(query)
    folders = result.scalars().all()
    
    # 2. РџРѕР»СѓС‡Р°РµРј РёРјРµРЅР° СѓСЃС‚СЂРѕР№СЃС‚РІ (РґР»СЏ РєСЂР°СЃРёРІРѕРіРѕ РѕС‚РѕР±СЂР°Р¶РµРЅРёСЏ РІ UI)
    meta_query = select(CachedObject).where(CachedObject.type == 'device_meta')
    meta_res = await db.execute(meta_query)
    # РЎР»РѕРІР°СЂСЊ {id: "Firewall-01"}
    dev_map = {o.device_group_id: o.name for o in meta_res.scalars().all()}

    # 3. Р¤РѕСЂРјРёСЂСѓРµРј РѕС‚РІРµС‚
    response = []
    for f in folders:
        dname = dev_map.get(f.device_group_id, "Unknown Device")
        response.append({
            "id": f.id,
            "name": f.name,
            "section": f.section,
            "device_group_id": f.device_group_id,
            "device_name": dname  # Р’Р°Р¶РЅРѕ РґР»СЏ С„СЂРѕРЅС‚РµРЅРґР°
        })
        
    return response

@router.post("/reorder")
async def reorder_rules(payload: ReorderRequest, db: AsyncSession = Depends(get_db)):
    service = RuleService(db)
    await service.reorder_rules_in_folder(payload.folder_id, payload.rule_ids)
    return {"status": "ok"}

@router.post("/{rule_id}/toggle")
async def toggle_rule(rule_id: str, payload: RuleToggle, db: AsyncSession = Depends(get_db)):
    return {"status": "ok", "enabled": payload.enabled}

# --- Р—Р°РіР»СѓС€РєРё ---
@router.post("/commit")
async def commit_endpoint(): 
    return {"status": "mock_commit_ok"}

@router.post("/delete")
async def delete_rules(ids: dict = Body(...)): 
    return {"status": "mock_delete_ok"}
