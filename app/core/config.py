import os
import sys
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # --- РћСЃРЅРѕРІРЅС‹Рµ РЅР°СЃС‚СЂРѕР№РєРё ---
    PROJECT_NAME: str = "NGFW Manager"
    
    # РџР РРћР РРўР•Рў:
    # 1. РџРµСЂРµРјРµРЅРЅР°СЏ РѕРєСЂСѓР¶РµРЅРёСЏ (Docker Environment)
    # 2. .env С„Р°Р№Р»
    # 3. Р”РµС„РѕР»С‚РЅРѕРµ Р·РЅР°С‡РµРЅРёРµ
    DATABASE_URL: str = "sqlite+aiosqlite:///./sql_app.db"

    # --- Р‘РµР·РѕРїР°СЃРЅРѕСЃС‚СЊ ---
    SECRET_KEY: str = "changethis_in_production_please"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # --- РџРµСЂРµРјРµРЅРЅС‹Рµ РёР· С‚РІРѕРµРіРѕ .env (С‡С‚РѕР±С‹ Pydantic РЅРµ РїР°РґР°Р») ---
    APP_TITLE: str = "NGFW Manager"
    APP_VERSION: str = "1.0.0"
    NGFW_DEFAULT_HOST: Optional[str] = None
    HTTPS_ENABLED: bool = True
    
    # --- РРіРЅРѕСЂРёСЂРѕРІР°РЅРёРµ Р»РёС€РЅРёС… РїРµСЂРµРјРµРЅРЅС‹С… (Docker-specific) ---
    # РџРµСЂРµРјРµРЅРЅС‹Рµ С‚РёРїР° POSTGRES_USER, РєРѕС‚РѕСЂС‹Рµ РµСЃС‚СЊ РІ env, РЅРѕ РЅРµ РЅСѓР¶РЅС‹ Р·РґРµСЃСЊ
    POSTGRES_USER: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    PYTHONUNBUFFERED: Optional[str] = None

    # РќР°СЃС‚СЂРѕР№РєРё Pydantic V2
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"  # <--- Р­РўРћ РЎРђРњРћР• Р’РђР–РќРћР•: РќРµ РїР°РґР°С‚СЊ РѕС‚ РЅРµРёР·РІРµСЃС‚РЅС‹С… РїРµСЂРµРјРµРЅРЅС‹С…
    )

settings = Settings()

# --- Р”РёР°РіРЅРѕСЃС‚РёРєР° РїСЂРё СЃС‚Р°СЂС‚Рµ ---
print("-----------------------------------------------------")
print(f" >>> [CONFIG] Loading settings...")
print(f" >>> [CONFIG] DATABASE_URL detected: {settings.DATABASE_URL.split('@')[-1]}") # РЎРєСЂС‹РІР°РµРј РїР°СЂРѕР»СЊ
print("-----------------------------------------------------")
sys.stdout.flush()
