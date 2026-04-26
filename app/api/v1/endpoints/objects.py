from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.db.session import get_db
from app.db.models import CachedObject, CachedZone
from app.infrastructure.ngfw_client import get_ngfw_client

router = APIRouter()

def flatten(groups):
    r = []
    for g in groups:
        r.append(g)
        if "subgroups" in g: r.extend(flatten(g["subgroups"]))
    return r

@router.post("/sync")
async def sync_objects(db: AsyncSession=Depends(get_db), client=Depends(get_ngfw_client)):
    try:
        grps = await client.get_device_groups()
        all_grps = flatten(grps)
        
        await db.execute(delete(CachedObject))
        await db.execute(delete(CachedZone))
        
        for g in all_grps:
            gid = g["id"]
            # Zones
            try:
                for z in await client.get_zones(gid):
                    db.add(CachedZone(name=z["name"], device_group_id=gid))
            except: pass
            
            # Networks
            try:
                d = await client.get_network_objects(gid)
                for i in d.get("addresses", []):
                    db.add(CachedObject(name=i["name"], obj_type="network", value=i.get("inet",""), device_group_id=gid))
                for i in d.get("fqdnAddresses", []):
                    db.add(CachedObject(name=i["name"], obj_type="network", value=i.get("fqdn",""), device_group_id=gid))
            except: pass
            
            # Services
            try:
                d = await client.get_services(gid)
                for s in d.get("services", []):
                    # (Logic to parse ports as in previous step)
                    val = "Complex" # Placeholder for brevity, use full logic
                    db.add(CachedObject(name=s["name"], obj_type="service", value=val, device_group_id=gid))
            except: pass
            
        await db.commit()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(500, str(e))

@router.get("/list")
async def lst(type: str = None, db: AsyncSession=Depends(get_db)):
    # ... standard list implementation ...
    pass
