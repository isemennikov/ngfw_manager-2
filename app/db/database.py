import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

# 1. РџРѕР»СѓС‡Р°РµРј URL
DATABASE_URL = os.getenv("DATABASE_URL")

# 2. Р¤РѕР»Р±РµРє РЅР° SQLite
if not DATABASE_URL:
    print(">>> [DB WARNING] DATABASE_URL not set! Defaulting to local SQLite.")
    DATABASE_URL = "sqlite+aiosqlite:///./sql_app.db"

print(f">>> [DB CONFIG] ACTIVE URL: {DATABASE_URL}")

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_async_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False 
)

# 3. Р’РђР–РќРћР• РР—РњР•РќР•РќРР•: expire_on_commit=False
# Р­С‚Рѕ РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ MissingGreenlet РїСЂРё РґРѕСЃС‚СѓРїРµ Рє РїРѕР»СЏРј РїРѕСЃР»Рµ commit()
SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine, 
    class_=AsyncSession,
    expire_on_commit=False  # <--- Р’РћРў Р­РўРћ РЎРџРђРЎР•Рў РЎРРўРЈРђР¦РР®
)

Base = declarative_base()
