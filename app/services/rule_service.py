import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.db.models import CachedRule, Folder

logger = logging.getLogger(__name__)

class RuleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_folder(self, name: str, device_group_id: str, section: str = "pre", parent_id: str = None) -> Folder:
        stmt = select(Folder).where(Folder.device_group_id == device_group_id)
        result = await self.db.execute(stmt)
        count = len(result.all())
        
        folder = Folder(
            name=name,
            device_group_id=device_group_id,
            section=section,
            parent_id=parent_id,
            sort_order=(count + 1) * 10
        )
        self.db.add(folder)
        await self.db.commit()
        await self.db.refresh(folder)
        return folder

    async def reorder_rules_in_folder(self, folder_id: str, rule_ids: list[str]):
        """
        РџРµСЂРµРјРµС‰Р°РµС‚ СЃРїРёСЃРѕРє РїСЂР°РІРёР» РІ СѓРєР°Р·Р°РЅРЅСѓСЋ РїР°РїРєСѓ Рё РѕР±РЅРѕРІР»СЏРµС‚ РёС… РїРѕСЂСЏРґРѕРє.
        """
        # Р•СЃР»Рё folder_id РїСѓСЃС‚РѕР№ (РЅР°РїСЂРёРјРµСЂ, РєРѕСЂРµРЅСЊ РёР»Рё РѕС€РёР±РєР°) - РёРіРЅРѕСЂРёСЂСѓРµРј РёР»Рё РєРёРґР°РµРј РѕС€РёР±РєСѓ
        if not folder_id:
            logger.warning("Attempt to reorder rules into None folder")
            return

        for index, r_id in enumerate(rule_ids):
            # Р’Р°Р¶РЅРѕ: РћР±РЅРѕРІР»СЏРµРј Р folder_id Р folder_sort_order
            stmt = update(CachedRule).where(CachedRule.id == r_id).values(
                folder_id=folder_id,
                folder_sort_order=index * 10
            )
            await self.db.execute(stmt)
        
        await self.db.commit()
