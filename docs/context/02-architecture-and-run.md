# 02 - Архитектура и запуск

## Сервисы (docker-compose.yml)

### `api` (бэкенд)
- Образ `api-gosuslugi-backend:latest`, контекст `./api-gosuslugi-backend`.
- База `python:3.8` + установка КриптоПро CSP (`linux-amd64_deb.tgz`) + компиляция **PyCades** (`pycades.zip`, cmake/make). **Сборка тяжёлая и долгая.**
- Entrypoint: `sh /certs/entrypoint.sh` ->
  1. `chown` ключей и `/certs`;
  2. `csptest -keyset -enum_cont` -> находит контейнер ключа -> `certmgr -inst` ставит его в `uMy`;
  3. ставит корневые/промежуточные сертификаты из `/certs`;
  4. `python /app/app.py` -> uvicorn на `0.0.0.0:5000` (см. `app.py:719`).
- Порты: `5000:5000` (API), `5678:5678` (debugpy).

### `frontend`
- Образ `api-gosuslugi-client`, контекст `./api-gosuslugi-client`, контейнер `react-nginx`.
- Multi-stage: `node:18-alpine` (CRA `npm run build`) -> `nginx:stable-alpine`.
- `REACT_APP_BACKEND_URL` **вшивается на этапе сборки** из build-arg `BACKEND_URL`. nginx дополнительно проксирует `/api/` -> `BACKEND_API` (runtime, через `entrypoint.sh` + `default.conf.template`).
- Порт: `5080:80`.

## Порты (host -> container)

| Сервис | Host | Container | Назначение |
| --- | --- | --- | --- |
| api | 5000 | 5000 | FastAPI |
| api | 5678 | 5678 | debugpy |
| frontend | 5080 | 80 | nginx (UI + прокси `/api/`) |

## Volume'ы сервиса `api`

| Источник | Цель в контейнере |
| --- | --- |
| `./api-gosuslugi-backend/app.py` | `/app/app.py` |
| `./api-gosuslugi-backend/.env` | `/app/.env` |
| `${key_folder:-./api-gosuslugi-backend/xxx.000}` | `/var/opt/cprocsp/keys/root/xxx.000` |
| `./api-gosuslugi-backend/certs` | `/certs` |
| `./api-gosuslugi-backend/xml` | `/xml` |

>  Путь ключей по умолчанию (`xxx.000`) **не существует**. Реальные ключи - в `./keys.000`. См. [03](03-config-and-known-issues.md).

## Поток данных

```
Браузер (host)
  по адресу REACT_APP_BACKEND_URL (абсолютный, вшит при сборке)
  обращается к frontend:5080 (nginx)
  nginx проксирует /api/ на api:5000 (FastAPI)
  бэкенд ходит в ЕСИА и ЕПГУ (test) и подписывает через КриптоПро/PyCades
```

## Команды

```powershell
# Сборка обоих образов
docker compose build

# Запуск в фоне
docker compose up -d

# Логи
docker compose logs -f api
docker compose logs -f frontend

# Статус / остановка
docker compose ps
docker compose down
```

После правки `BACKEND_URL` (он вшивается в React при сборке) фронтенд нужно **пересобрать**:
`docker compose up -d --build frontend` (бэкенд возьмётся из кэша).

## Локальная разработка фронтенда (без Docker)

Dev-сервер CRA запускать на порту **3001**. Файлы клиента должны быть в **CRLF**, иначе сборка CRA падает.
