from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import SETTINGS

# РЎРѕР·РґР°РµРј РґРІРёР¶РѕРє
engine = create_async_engine(SETTINGS.DATABASE_URL, echo=False, future=True)

# РЎРѕР·РґР°РµРј С„Р°Р±СЂРёРєСѓ СЃРµСЃСЃРёР№
async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# --- Р’РђР–РќРћ: РћР±СЉСЏРІР»СЏРµРј Base ---
Base = declarative_base()

# Р¤СѓРЅРєС†РёСЏ РґР»СЏ Dependency Injection РІ FastAPI
async def get_db():
    async with async_session() as session:
        yield session
