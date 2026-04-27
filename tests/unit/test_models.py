"""Unit tests for database models."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import Folder, CachedRule, CachedObject
import uuid


@pytest.mark.asyncio
class TestFolderModel:
    """Test Folder model."""
    
    async def test_folder_creation(self, async_db: AsyncSession):
        """Test creating and saving a Folder."""
        folder = Folder(
            name="Test Folder",
            device_group_id=str(uuid.uuid4()),
            section="pre",
            sort_order=10
        )
        async_db.add(folder)
        await async_db.commit()
        
        assert folder.id is not None
        assert folder.name == "Test Folder"
    
    async def test_folder_with_parent(self, async_db: AsyncSession):
        """Test creating folder with parent relationship."""
        parent_id = str(uuid.uuid4())
        folder = Folder(
            name="Child Folder",
            device_group_id=str(uuid.uuid4()),
            parent_id=parent_id,
            sort_order=20
        )
        async_db.add(folder)
        await async_db.commit()
        
        assert folder.parent_id == parent_id


@pytest.mark.asyncio
class TestCachedRuleModel:
    """Test CachedRule model."""
    
    async def test_rule_creation(self, async_db: AsyncSession):
        """Test creating and saving a CachedRule."""
        device_group_id = str(uuid.uuid4())
        rule = CachedRule(
            id=str(uuid.uuid4()),
            name="Allow HTTPS",
            device_group_id=device_group_id,
            device_serial="ABC123",
            folder_id=None,
            folder_sort_order=0
        )
        async_db.add(rule)
        await async_db.commit()
        
        assert rule.name == "Allow HTTPS"
    
    async def test_rule_with_folder(self, async_db: AsyncSession):
        """Test creating rule associated with folder."""
        device_group_id = str(uuid.uuid4())
        folder_id = str(uuid.uuid4())
        
        rule = CachedRule(
            id=str(uuid.uuid4()),
            name="Rule in Folder",
            device_group_id=device_group_id,
            folder_id=folder_id,
            folder_sort_order=10
        )
        async_db.add(rule)
        await async_db.commit()
        
        assert rule.folder_id == folder_id
        assert rule.folder_sort_order == 10


@pytest.mark.asyncio
class TestCachedObjectModel:
    """Test CachedObject model."""
    
    async def test_object_creation(self, async_db: AsyncSession):
        """Test creating and saving a CachedObject (network, service, etc)."""
        device_group_id = str(uuid.uuid4())
        obj = CachedObject(
            id=str(uuid.uuid4()),
            name="Internal Network",
            object_type="networkGroup",
            device_group_id=device_group_id,
            device_serial="ABC123"
        )
        async_db.add(obj)
        await async_db.commit()
        
        assert obj.name == "Internal Network"
        assert obj.object_type == "networkGroup"
