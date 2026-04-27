"""Unit tests for SyncService."""

import pytest
from app.services.sync_service import _field_ids, _rule_changed


class TestFieldIds:
    """Test _field_ids helper function."""
    
    def test_field_ids_with_any(self, sample_any_field):
        """Test extraction of field IDs when kind is ANY."""
        result = _field_ids(sample_any_field)
        assert result == ("ANY",)
    
    def test_field_ids_with_list(self, sample_list_field):
        """Test extraction of field IDs from LIST kind."""
        result = _field_ids(sample_list_field)
        assert len(result) == 3
        assert "obj-1" in result
        assert "obj-2" in result
        assert "obj-3" in result
    
    def test_field_ids_with_empty_objects(self):
        """Test extraction when objects list is empty."""
        field = {'kind': 'RULE_KIND_LIST', 'objects': []}
        result = _field_ids(field)
        assert result == ("ANY",)
    
    def test_field_ids_with_nested_id(self):
        """Test extraction of nested IDs from complex objects."""
        field = {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {'networkIpRange': {'id': 'net-range-1'}},
                {'networkIpAddress': {'id': 'net-addr-1'}}
            ]
        }
        result = _field_ids(field)
        assert "net-range-1" in result
        assert "net-addr-1" in result
    
    def test_field_ids_with_none(self):
        """Test extraction with None field."""
        result = _field_ids(None)
        assert result == ("ANY",)
    
    def test_field_ids_sorted(self):
        """Test that returned IDs are sorted."""
        field = {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {'id': 'z-id'},
                {'id': 'a-id'},
                {'id': 'm-id'}
            ]
        }
        result = _field_ids(field)
        assert result == tuple(sorted(['z-id', 'a-id', 'm-id']))


class TestRuleChanged:
    """Test _rule_changed helper function."""
    
    def test_rule_not_changed_same_rules(self, sample_rule_data):
        """Test that identical rules are detected as unchanged."""
        result = _rule_changed(sample_rule_data, sample_rule_data)
        assert result is False
    
    def test_rule_changed_on_name(self, sample_rule_data, sample_rule_changed):
        """Test that name change is detected."""
        result = _rule_changed(sample_rule_data, sample_rule_changed)
        assert result is True
    
    def test_rule_changed_on_enabled_status(self, sample_rule_data, sample_rule_changed):
        """Test that enabled status change is detected."""
        modified = sample_rule_data.copy()
        modified['enabled'] = not modified['enabled']
        result = _rule_changed(sample_rule_data, modified)
        assert result is True
    
    def test_rule_changed_on_action(self, sample_rule_data):
        """Test that action change is detected."""
        modified = sample_rule_data.copy()
        modified['action'] = 'SECURITY_RULE_ACTION_DROP'
        result = _rule_changed(sample_rule_data, modified)
        assert result is True
    
    def test_rule_changed_on_description(self, sample_rule_data):
        """Test that description change is detected."""
        old_rule = sample_rule_data.copy()
        old_rule['description'] = 'old description'
        
        new_rule = sample_rule_data.copy()
        new_rule['description'] = 'new description'
        
        result = _rule_changed(old_rule, new_rule)
        assert result is True
    
    def test_rule_not_changed_on_timestamp(self, sample_rule_data):
        """Test that timestamp changes don't affect rule comparison."""
        modified = sample_rule_data.copy()
        modified['updatedAt'] = '2026-04-27T10:00:00Z'
        result = _rule_changed(sample_rule_data, modified)
        assert result is False
    
    def test_rule_changed_on_source_addr(self, sample_rule_data):
        """Test that sourceAddr change is detected."""
        modified = sample_rule_data.copy()
        modified['sourceAddr'] = {'kind': 'RULE_KIND_ANY', 'objects': []}
        result = _rule_changed(sample_rule_data, modified)
        assert result is True
    
    def test_rule_changed_on_service(self, sample_rule_data):
        """Test that service change is detected."""
        modified = sample_rule_data.copy()
        modified['service'] = {'kind': 'RULE_KIND_ANY', 'objects': []}
        result = _rule_changed(sample_rule_data, modified)
        assert result is True
