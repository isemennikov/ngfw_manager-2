from fastapi import APIRouter, HTTPException, Body
from app.infrastructure.ngfw_client import NGFWClient

router = APIRouter()

@router.post("/login")
async def login_api(data: dict = Body(...)):
    """
    API СЌРЅРґРїРѕРёРЅС‚ РґР»СЏ РІС…РѕРґР°.
    РџСЂРѕРІРµСЂСЏРµС‚ РєСЂРµРґС‹ РЅР° NGFW Рё РІРѕР·РІСЂР°С‰Р°РµС‚ С‚РѕРєРµРЅ.
    """
    host = data.get("host")
    username = data.get("username")
    password = data.get("password")
    
    if not host or not username or not password:
        raise HTTPException(status_code=400, detail="Missing host, username or password")
        
    try:
        # РРЅРёС†РёР°Р»РёР·РёСЂСѓРµРј РєР»РёРµРЅС‚ Рё РїСЂРѕР±СѓРµРј РІРѕР№С‚Рё
        client = NGFWClient(base_url=host)
        auth_response = await client.login(username, password)
        await client.close()
        
        # Р’РѕР·РІСЂР°С‰Р°РµРј С‚РѕРєРµРЅ С„СЂРѕРЅС‚Сѓ
        return auth_response
    except Exception as e:
        print(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")
