from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import NatFolder, CachedNatRule
from app.infrastructure.ngfw_client import NGFWClient
import logging

logger = logging.getLogger(__name__)


class NatDeployService:
    async def deploy_nat_policy(self, db: AsyncSession, client: NGFWClient, device_group_id: str):
        logger.info(f"Starting NAT DEPLOY for device {device_group_id}...")

        for section in ['pre', 'default', 'post']:
            stmt = select(NatFolder).where(
                NatFolder.device_group_id == device_group_id,
                NatFolder.section == section,
            ).order_by(NatFolder.sort_order)

            folders = (await db.execute(stmt)).scalars().all()
            if not folders:
                continue

            custom_folders = [f for f in folders if "(Default)" not in f.name]
            system_folders = [f for f in folders if "(Default)" in f.name]
            position = 1

            for folder in custom_folders + system_folders:
                stmt_rules = select(CachedNatRule).where(
                    CachedNatRule.folder_id == folder.id
                ).order_by(CachedNatRule.folder_sort_order)

                rules = (await db.execute(stmt_rules)).scalars().all()
                for rule in rules:
                    success = await client.move_nat_rule(rule.ext_id, position)
                    if success:
                        position += 1
                    else:
                        logger.error(f"Failed to move NAT rule {rule.name}")

        logger.info("NAT Deploy complete.")
