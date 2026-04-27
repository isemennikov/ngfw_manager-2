# Тестирование NGFW Manager

## Обзор

Проект использует pytest для unit и integration тестирования. Тесты покрывают критические компоненты: сервисы, модели БД, API эндпоинты.

## Подготовка окружения

### 1. Создать virtual environment:
```bash
/usr/local/bin/python3 -m venv venv
```

### 2. Активировать venv:
```bash
source venv/bin/activate
```

### 3. Установить зависимости:
```bash
pip install -r requirements.txt
```

## Структура тестов

```
tests/
├── conftest.py              # Общие фикстуры (async БД, mock-данные)
├── pytest.ini               # Конфигурация pytest
├── fixtures/                # Тестовые данные
│   ├── rules_data.py       # Реальные правила firewall (8 штук)
├── unit/                    # Unit-тесты (24 теста)
│   ├── test_sync_service.py    # SyncService: парсинг полей, сравнение правил
│   ├── test_rule_service.py    # RuleService: создание папок, reorder правил
│   └── test_models.py          # Модели БД: Folder, CachedRule, CachedObject
└── integration/             # Integration-тесты (4 теста)
    └── test_api_endpoints.py   # API: sync, folders, reorder
```

## Зависимости

Установите тестовые зависимости:
```bash
pip install -r requirements.txt
```

## Запуск тестов

### Все тесты:
```bash
pytest
```

### Только unit-тесты:
```bash
pytest tests/unit/
```

### Только integration-тесты:
```bash
pytest tests/integration/
```

### С подробным выводом:
```bash
pytest -v
```

### Конкретный файл:
```bash
pytest tests/unit/test_sync_service.py
```

### Конкретный тест:
```bash
pytest tests/unit/test_sync_service.py::TestFieldIds::test_field_ids_with_any
```

### С покрытием кода:
```bash
pip install pytest-cov
pytest --cov=app --cov-report=html
# Откройте htmlcov/index.html в браузере
```

### Запуск в Docker:
```bash
docker compose run --rm app pytest
```

## Проведение тестов

### Unit-тесты:
- Тестируют отдельные функции без внешних зависимостей
- Используют mock для БД и API
- Примеры: парсинг полей правил, сравнение объектов

### Integration-тесты:
- Тестируют взаимодействие компонентов (API + сервис + БД)
- Используют тестовую БД (SQLite in-memory)
- Примеры: создание папок через API, синхронизация

### Добавление новых тестов:
1. Создайте файл в `tests/unit/` или `tests/integration/`
2. Используйте фикстуры из `conftest.py`
3. Добавьте mock для внешних зависимостей (NGFW client)
4. Запустите `pytest` для проверки

## Тестовые данные

- **Реальные правила**: 8 правил firewall из production (JSON)
- **Mock-данные**: Фикстуры для ANY/LIST полей, изменённых правил
- **База данных**: SQLite in-memory (не требует внешней БД)

## Примеры тестов

### Unit-тест (SyncService):
```python
def test_field_ids_with_list(sample_list_field):
    result = _field_ids(sample_list_field)
    assert len(result) == 3
    assert "obj-1" in result
```

### Integration-тест (API):
```python
async def test_create_folder_endpoint(async_db, test_client):
    payload = {"name": "Test", "device_group_id": str(uuid.uuid4())}
    response = test_client.post("/folders", json=payload)
    assert response.status_code == 201
```

## CI/CD

Тесты автоматически запускаются в GitHub Actions при push в main.

## Добавление новых тестов

1. Создайте файл в `tests/unit/` или `tests/integration/`
2. Используйте фикстуры из `conftest.py`
3. Добавьте mock для внешних зависимостей (NGFW client)
4. Запустите `pytest` для проверки

## Проблемы

- Если тесты падают на async: Убедитесь что `pytest-asyncio` установлен
- Если проблемы с БД: Проверьте фикстуры в `conftest.py`
- Для отладки: `pytest -v --tb=long`