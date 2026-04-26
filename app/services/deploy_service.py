from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Folder, CachedRule
from app.infrastructure.ngfw_client import NGFWClient
import logging

logger = logging.getLogger(__name__)

class DeployService:
    async def deploy_device_policy(self, db: AsyncSession, client: NGFWClient, device_group_id: str):
        logger.info(f"Starting DEPLOY for device {device_group_id}...")
        
        # РЎС‚СЂРѕРіРёР№ РїРѕСЂСЏРґРѕРє СЃРµРєС†РёР№
        sections_order = ['pre', 'default', 'post']
        
        for section in sections_order:
            logger.info(f"Processing Section: {section.upper()}")
            
            # 1. РџРѕР»СѓС‡Р°РµРј РІСЃРµ РїР°РїРєРё СЃРµРєС†РёРё
            stmt_folders = select(Folder).where(
                Folder.device_group_id == device_group_id,
                Folder.section == section
            ).order_by(Folder.sort_order)
            
            folders = (await db.execute(stmt_folders)).scalars().all()
            
            if not folders:
                continue

            # --- Р“Р›РђР’РќРћР• РР—РњР•РќР•РќРР•: РџР•Р Р•РЎРћР РўРР РћР’РљРђ РџРђРџРћРљ ---
            # РџСЂР°РІРёР»Р° РёР· РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРёС… РїР°РїРѕРє РґРѕР»Р¶РЅС‹ РёРґС‚Рё РџР•Р Р’Р«РњР.
            # РџСЂР°РІРёР»Р° РёР· РґРµС„РѕР»С‚РЅС‹С… РїР°РїРѕРє (СЃРѕР·РґР°РЅРЅС‹С… Sync) РґРѕР»Р¶РЅС‹ РёРґС‚Рё РџРћРЎР›Р•Р”РќРРњР.
            
            custom_folders = []
            system_folders = []
            
            for f in folders:
                # Р•СЃР»Рё РІ РёРјРµРЅРё РµСЃС‚СЊ "(Default)" - СЃС‡РёС‚Р°РµРј РµС‘ СЃРёСЃС‚РµРјРЅРѕР№ РєРѕСЂР·РёРЅРѕР№ Рё РєРёРґР°РµРј РІ РєРѕРЅРµС†
                if "(Default)" in f.name or f.name.lower() == "default":
                    system_folders.append(f)
                else:
                    custom_folders.append(f)
            
            # РќРѕРІС‹Р№ РїРѕСЂСЏРґРѕРє РѕР±СЂР°Р±РѕС‚РєРё: РЎРЅР°С‡Р°Р»Р° Vlan100, РїРѕС‚РѕРј Policy PRE (Default)
            sorted_folders_to_process = custom_folders + system_folders

            # 2. РРЅРёС†РёР°Р»РёР·РёСЂСѓРµРј СЃРєРІРѕР·РЅРѕР№ СЃС‡РµС‚С‡РёРє
            current_section_position = 1
            
            # 3. РџСЂРѕС…РѕРґРёРј РїРѕ РїР°РїРєР°Рј РІ РїСЂР°РІРёР»СЊРЅРѕРј РїРѕСЂСЏРґРєРµ
            for folder in sorted_folders_to_process:
                logger.info(f"  > Processing Folder '{folder.name}' (ID: {folder.id})")
                
                stmt_rules = select(CachedRule).where(
                    CachedRule.folder_id == folder.id
                ).order_by(CachedRule.folder_sort_order)
                
                rules = (await db.execute(stmt_rules)).scalars().all()
                
                if not rules:
                    continue
                
                # 4. РћС‚РїСЂР°РІР»СЏРµРј РїСЂР°РІРёР»Р°
                for rule in rules:
                    success = await client.update_rule_position(
                        rule_id=rule.ext_id,
                        new_position=current_section_position,
                        device_group_id=device_group_id,
                        precedence=section
                    )
                    
                    if success:
                        current_section_position += 1
                    else:
                        logger.error(f"Failed to move rule {rule.name}")
        
        logger.info("Deploy complete.")
