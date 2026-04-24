# HOWTO — backend (FastAPI + КриптоПро)

## Локальный запуск без Docker

> Требуется установленный КриптоПро CSP + собранный `pycades.so` для текущей версии Python. В Windows это нетривиально — рекомендуем Docker.

```bash
python -m venv .venv
source .venv/Scripts/activate      # Windows Git Bash
pip install -r requirements.txt
cp ../.env .env
uvicorn app:app --reload --host 0.0.0.0 --port 5000
```

## Запуск в Docker (рекомендовано)

Из корня репозитория:

```bash
docker-compose up -d --build api
docker-compose logs -f api
```

Сервис слушает `:5000` (HTTP) и `:5678` (debugpy, если `production` не задан).

## Отладка в VS Code

`.vscode/launch.json`:

```json
{
  "name": "Python: Remote Attach",
  "type": "debugpy",
  "request": "attach",
  "connect": { "host": "localhost", "port": 5678 },
  "pathMappings": [
    { "localRoot": "${workspaceFolder}/api-gosuslugi-backend",
      "remoteRoot": "/app" }
  ]
}
```

## Проверка жизнеспособности

```bash
curl http://localhost:5000/hc        # {"status":"Ok"}
curl http://localhost:5000/status    # версия PyCades
```

## Тесты

```bash
pytest -c pytest.ini
```

Для запуска в контейнере — `Dockerfile.test`.

## Частые задачи

### Добавить новую услугу

1. Положить эталонные `req.xml` и `piev_epgu.xml` в `xml/`.
2. Обновить XSD `piev_epgu.xsd` (если изменилась схема).
3. В корневом `.env` расширить `SERVICES`:
   ```json
   { "<код>": { "description": "...", "req_file": "req.xml", "piev_epgu_file": "piev_epgu.xml" } }
   ```
4. `docker-compose up -d --build api`.

### Подменить сертификат

1. Заменить содержимое `${key_folder}` (по умолчанию `./xxx.000`).
2. Перезапустить контейнер — startup-hook перечитает `CERTIFICATES`.
3. В UI выбрать нужный сертификат, либо `POST /set_current_certificate?cert_id=...`.

### Продиагностировать подпись

Логи с `logger.exception` показывают стек. Типовые ошибки:

| Сообщение | Причина |
|---|---|
| `Сертификаты не найдены.` | Пустое хранилище CSP / неверный volume |
| `Текущий сертификат не установлен.` | Не вызван `/set_current_certificate` |
| `Invalid XML: ...` | Несоответствие `piev_epgu.xml` XSD |

См. также [../docs/api.md](../docs/api.md), [../docs/security.md](../docs/security.md).
