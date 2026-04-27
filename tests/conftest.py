"""Shared pytest fixtures for all tests."""

import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.db.session import get_db


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def async_db():
    """Create test database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker as sync_sessionmaker
    
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    
    SessionLocal = sync_sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    yield session
    
    session.close()
    engine.dispose()


@pytest.fixture
def sample_rule_data():
    """Return sample firewall rule for testing."""
    return {
        'id': '019be530-75a0-7a6a-ba06-f658af91888e',
        'name': 'test_rule',
        'action': 'SECURITY_RULE_ACTION_ALLOW',
        'enabled': True,
        'sourceAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpRange': {
                        'id': 'test-id-1',
                        'name': 'test_range',
                        'from': '10.0.0.1',
                        'to': '10.0.0.255'
                    }
                }
            ]
        },
        'destinationAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpAddress': {
                        'id': 'test-id-2',
                        'name': 'test_host',
                        'inet': '10.1.0.1/32'
                    }
                }
            ]
        },
        'service': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'service': {
                        'id': 'test-service-1',
                        'name': 'tcp_80',
                        'protocol': 'SERVICE_PROTOCOL_TCP',
                        'dstPorts': [{'singlePort': {'port': 80}}]
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_rule_changed():
    """Return modified version of sample rule for comparison testing."""
    return {
        'id': '019be530-75a0-7a6a-ba06-f658af91888e',
        'name': 'test_rule_modified',  # Changed name
        'action': 'SECURITY_RULE_ACTION_ALLOW',
        'enabled': False,  # Changed enabled status
        'sourceAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpRange': {
                        'id': 'test-id-1',
                        'name': 'test_range',
                        'from': '10.0.0.1',
                        'to': '10.0.0.255'
                    }
                }
            ]
        },
        'destinationAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpAddress': {
                        'id': 'test-id-2',
                        'name': 'test_host',
                        'inet': '10.1.0.1/32'
                    }
                }
            ]
        },
        'service': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'service': {
                        'id': 'test-service-1',
                        'name': 'tcp_80',
                        'protocol': 'SERVICE_PROTOCOL_TCP',
                        'dstPorts': [{'singlePort': {'port': 80}}]
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_any_field():
    """Return ANY field (no objects)."""
    return {'kind': 'RULE_KIND_ANY', 'objects': []}


@pytest.fixture
def sample_list_field():
    """Return LIST field with multiple objects."""
    return {
        'kind': 'RULE_KIND_LIST',
        'objects': [
            {'id': 'obj-1'},
            {'id': 'obj-2'},
            {'id': 'obj-3'}
        ]
    }
