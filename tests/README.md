# Tests

This directory contains unit and integration tests for NGFW Manager.

## Structure

```
tests/
├── conftest.py              # Shared pytest fixtures
├── fixtures/                # Test data and fixtures
│   ├── rules_data.py       # Real firewall rules from production
├── unit/                    # Unit tests
│   ├── test_sync_service.py    # Tests for SyncService (_field_ids, _rule_changed)
│   ├── test_rule_service.py    # Tests for RuleService (create_folder, reorder_rules)
│   └── test_models.py          # Tests for database models
└── integration/             # Integration tests
    └── test_api_endpoints.py   # Tests for API endpoints
```

## Running Tests

### Run all tests:
```bash
pytest
```

### Run unit tests only:
```bash
pytest tests/unit/
```

### Run integration tests only:
```bash
pytest tests/integration/
```

### Run with verbose output:
```bash
pytest -v
```

### Run a specific test file:
```bash
pytest tests/unit/test_sync_service.py
```

### Run a specific test:
```bash
pytest tests/unit/test_sync_service.py::TestFieldIds::test_field_ids_with_any
```

### Run with coverage:
```bash
pip install pytest-cov
pytest --cov=app --cov-report=html
```

## Test Data

Tests use real firewall rule data from production (8 actual rules) defined in `tests/fixtures/rules_data.py`.

Sample rule includes:
- Multiple source/destination IP ranges
- Network groups
- Custom services (TCP ports)
- Various rule actions (ALLOW, DROP)
- Logging modes

## Current Coverage

- **SyncService**: Tests for rule field parsing and comparison
  - `_field_ids()`: Extract and parse object IDs from rule fields
  - `_rule_changed()`: Detect meaningful changes between rule versions

- **RuleService**: Tests for folder and rule management
  - `create_folder()`: Create virtual folders with proper sort ordering
  - `reorder_rules_in_folder()`: Reorder rules within folders

- **Database Models**: Tests for ORM models
  - Folder creation and relationships
  - CachedRule creation and folder associations
  - CachedObject (networks, services, etc.)

- **API Endpoints**: Basic integration tests
  - Endpoint availability
  - Request/response validation

## Notes

- Tests use SQLite in-memory database (no external DB needed)
- Async tests use `pytest-asyncio`
- Mock NGFW client for testing sync operations
- All tests are isolated and can run in any order
