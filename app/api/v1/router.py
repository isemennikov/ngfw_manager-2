from fastapi import APIRouter
# РРјРїРѕСЂС‚РёСЂСѓРµРј СЌРЅРґРїРѕРёРЅС‚С‹ (СѓР±РµРґРёСЃСЊ, С‡С‚Рѕ С„Р°Р№Р»С‹ auth.py Рё rules.py СЃСѓС‰РµСЃС‚РІСѓСЋС‚ РІ app/api/v1/endpoints/)
from app.api.v1.endpoints import auth, rules

router = APIRouter()

# РџРѕРґРєР»СЋС‡Р°РµРј СЂРѕСѓС‚С‹ РёР· РјРѕРґСѓР»РµР№
# auth - Р·Р°РіР»СѓС€РєР°, РµСЃР»Рё РµРіРѕ РЅРµС‚, РјРѕР¶РЅРѕ Р·Р°РєРѕРјРјРµРЅС‚РёСЂРѕРІР°С‚СЊ
# router.include_router(auth.router, prefix="/auth", tags=["auth"])

# rules - РѕСЃРЅРѕРІРЅРѕР№ РјРѕРґСѓР»СЊ СЃ Р»РѕРіРёРєРѕР№ РїСЂР°РІРёР»
router.include_router(rules.router, prefix="/rules", tags=["rules"])
