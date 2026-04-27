"""Unit tests for database models."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import Folder, CachedRule, CachedObject
import uuid


class TestFolderModel:
    """Test Folder model."""
    
    def test_folder_creation(self, async_db):
        """Test creating and saving a Folder."""
        folder = Folder(
            name="Test Folder",
            device_group_id=str(uuid.uuid4()),
            section="pre",
            sort_order=10
        )
        async_db.add(folder)
        async_db.commit()
        
        assert folder.id is not None
        assert folder.name == "Test Folder"
    
    def test_folder_with_parent(self, async_db):
        """Test creating folder with parent relationship."""
        parent_id = str(uuid.uuid4())
        folder = Folder(
            name="Child Folder",
            device_group_id=str(uuid.uuid4()),
            parent_id=parent_id,
            sort_order=20
        )
        async_db.add(folder)
        async_db.commit()
        
        assert folder.parent_id == parent_id


class TestCachedRuleModel:
    """Test CachedRule model."""
    
    def test_rule_creation(self, async_db):
        """Test creating and saving a CachedRule."""
        rule = CachedRule(
            id=str(uuid.uuid4()),
            ext_id=str(uuid.uuid4()),
            name="Allow HTTPS",
            folder_id=None,
            folder_sort_order=0,
            data={}
        )
        async_db.add(rule)
        async_db.commit()
        
        assert rule.name == "Allow HTTPS"
    
    def test_rule_with_folder(self, async_db):
        """Test creating rule associated with folder."""
        folder_id = str(uuid.uuid4())
        
        rule = CachedRule(
            id=str(uuid.uuid4()),
            ext_id=str(uuid.uuid4()),
            name="Rule in Folder",
            folder_id=folder_id,
            folder_sort_order=10,
            data={}
        )
        async_db.add(rule)
        async_db.commit()
        
        assert rule.folder_id == folder_id
        assert rule.folder_sort_order == 10


class TestCachedObjectModel:
    """Test CachedObject model."""
    
    def test_object_creation(self, async_db):
        """Test creating and saving a CachedObject (network, service, etc)."""
        device_group_id = str(uuid.uuid4())
        obj = CachedObject(
            ext_id=str(uuid.uuid4()),
            name="Internal Network",
            type="networkGroup",
            category="network",
            device_group_id=device_group_id,
            data={}
        )
        async_db.add(obj)
        async_db.commit()
        
        assert obj.name == "Internal Network"
        assert obj.type == "networkGroup"
