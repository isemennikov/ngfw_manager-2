"""Unit tests for RuleService."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.rule_service import RuleService
from app.db.models import Folder, CachedRule
import uuid


@pytest.mark.asyncio
class TestRuleService:
    """Test RuleService methods."""
    
    async def test_create_folder_basic(self, async_db: AsyncSession):
        """Test basic folder creation."""
        service = RuleService(async_db)
        device_group_id = str(uuid.uuid4())
        
        folder = await service.create_folder(
            name="Test Folder",
            device_group_id=device_group_id,
            section="pre"
        )
        
        assert folder.name == "Test Folder"
        assert folder.device_group_id == device_group_id
        assert folder.section == "pre"
        assert folder.sort_order == 10  # First folder
    
    async def test_create_folder_with_parent(self, async_db: AsyncSession):
        """Test creating folder with parent."""
        service = RuleService(async_db)
        device_group_id = str(uuid.uuid4())
        parent_id = str(uuid.uuid4())
        
        folder = await service.create_folder(
            name="Child Folder",
            device_group_id=device_group_id,
            parent_id=parent_id
        )
        
        assert folder.parent_id == parent_id
    
    async def test_create_multiple_folders_sort_order(self, async_db: AsyncSession):
        """Test that sort_order increments correctly for multiple folders."""
        service = RuleService(async_db)
        device_group_id = str(uuid.uuid4())
        
        folder1 = await service.create_folder(
            name="Folder 1",
            device_group_id=device_group_id
        )
        
        folder2 = await service.create_folder(
            name="Folder 2",
            device_group_id=device_group_id
        )
        
        folder3 = await service.create_folder(
            name="Folder 3",
            device_group_id=device_group_id
        )
        
        assert folder1.sort_order == 10
        assert folder2.sort_order == 20
        assert folder3.sort_order == 30
    
    async def test_reorder_rules_in_folder(self, async_db: AsyncSession):
        """Test reordering rules in a folder."""
        service = RuleService(async_db)
        device_group_id = str(uuid.uuid4())
        folder_id = str(uuid.uuid4())
        
        # Create sample rules
        rule_ids = [str(uuid.uuid4()) for _ in range(3)]
        
        for i, rule_id in enumerate(rule_ids):
            rule = CachedRule(
                id=rule_id,
                name=f"Rule {i}",
                device_group_id=device_group_id,
                folder_id=None,
                folder_sort_order=0
            )
            async_db.add(rule)
        
        await async_db.commit()
        
        # Reorder rules
        await service.reorder_rules_in_folder(folder_id, rule_ids)
        
        # Verify reordering
        for i, rule_id in enumerate(rule_ids):
            result = await async_db.execute(
                __import__('sqlalchemy').select(CachedRule).where(CachedRule.id == rule_id)
            )
            rule = result.scalar_one()
            assert rule.folder_id == folder_id
            assert rule.folder_sort_order == i * 10
    
    async def test_reorder_rules_empty_folder_id(self, async_db: AsyncSession):
        """Test reordering with None/empty folder_id (should be handled gracefully)."""
        service = RuleService(async_db)
        rule_ids = [str(uuid.uuid4()) for _ in range(2)]
        
        # Should not raise exception
        await service.reorder_rules_in_folder(None, rule_ids)
    
    async def test_reorder_rules_empty_list(self, async_db: AsyncSession):
        """Test reordering with empty rule list."""
        service = RuleService(async_db)
        folder_id = str(uuid.uuid4())
        
        # Should handle empty list without issues
        await service.reorder_rules_in_folder(folder_id, [])
