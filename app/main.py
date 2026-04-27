from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.db.session import engine, Base, async_session
from app.web.router import router as web_router
from app.api.v1.router import router as api_router
from sqlalchemy import text, delete
import asyncio
import os
import logging
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")  # main app logger

import app.db.models
from app.db.models import CachedLog

LOG_TTL_HOURS = 1          # auto-purge TTL for cached logs
PURGE_INTERVAL_SEC = 600   # run purge every 10 minutes


async def _auto_purge_logs():
    """Background task: delete CachedLog records older than LOG_TTL_HOURS."""
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SEC)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=LOG_TTL_HOURS)
            async with async_session() as session:
                result = await session.execute(
                    delete(CachedLog).where(CachedLog.fetched_at < cutoff)
                )
                await session.commit()
                if result.rowcount:
                    logger.info(f"[log-purge] Deleted {result.rowcount} expired log entries")
        except Exception as e:
            logger.error(f"[log-purge] Error: {e}")


async def init_db():
    try:
        logger.info("Creating database tables...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise e

    migrations = [
        "ALTER TABLE cached_rules ADD COLUMN is_modified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE cached_rules ADD COLUMN modified_at VARCHAR",
    ]
    for stmt in migrations:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(stmt))
            logger.info(f"Migration applied: {stmt[:60]}")
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    task = asyncio.create_task(_auto_purge_logs())
    logger.info(f"[log-purge] Background task started (TTL={LOG_TTL_HOURS}h, interval={PURGE_INTERVAL_SEC}s)")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan)

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-random-string-12345")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=False)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(api_router, prefix="/api/v1")
app.include_router(web_router)
