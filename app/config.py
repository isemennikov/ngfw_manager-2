import os

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres_password@db:5432/ngfw_db")
    
    # os.getenv Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РІРѕР·СЊРјРµС‚ Р·РЅР°С‡РµРЅРёСЏ, Р·Р°РіСЂСѓР¶РµРЅРЅС‹Рµ Р”РѕРєРµСЂРѕРј РёР· .env
    NGFW_URL = os.getenv("NGFW_URL")
    NGFW_USER = os.getenv("NGFW_USER")
    NGFW_PASSWORD = os.getenv("NGFW_PASSWORD")

SETTINGS = Settings()
