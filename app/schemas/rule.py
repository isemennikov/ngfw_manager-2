from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Literal

class LoginPayload(BaseModel):
    host: str       # <-- Р”РѕР±Р°РІРёР»Рё Р°РґСЂРµСЃ С…РѕСЃС‚Р°
    login: str
    password: str

# ... РѕСЃС‚Р°Р»СЊРЅС‹Рµ РјРѕРґРµР»Рё (RuleBase, RuleResponse Рё С‚.Рґ.) РѕСЃС‚Р°РІР»СЏРµРј РєР°Рє Р±С‹Р»Рё ...
# (Р”СѓР±Р»РёСЂРѕРІР°С‚СЊ РёС… Р·РґРµСЃСЊ РЅРµ Р±СѓРґСѓ, С‡С‚РѕР±С‹ РЅРµ Р·Р°РЅРёРјР°С‚СЊ РјРµСЃС‚Рѕ, РёСЃРїРѕР»СЊР·СѓР№ СЃС‚Р°СЂС‹Р№ РєРѕРґ РЅРёР¶Рµ LoginPayload)
class RuleBase(BaseModel):
    # ... СЃС‚Р°СЂС‹Р№ РєРѕРґ ...
    pass
# ...
