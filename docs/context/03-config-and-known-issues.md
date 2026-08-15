# 03 — Конфигурация и известные особенности

## Корневой `.env` для Compose

Compose использует `.env` для подстановки, но передаёт контейнерам только значения из `docker-compose.yml`.

| Переменная | Default | Назначение |
|---|---|---|
| `BACKEND_URL` | `/api` | Build-time base URL React |
| `BACKEND_API` | `http://api:5000` | Runtime upstream Nginx, без `/api` |
| `API_PORT` | `55000` | Loopback-only host-порт FastAPI |
| `FRONTEND_PORT` | `50080` | Loopback-only host-порт UI/Nginx |
| `apikey` | пусто | API key организации для получения access token |
| `esia_host` | `https://esia-portal1.test.gosuslugi.ru` | Test ЕСИА |
| `svcdev_host` | `https://svcdev-gostapi.test.gosuslugi.ru` | Формальный test API ЕПГУ |
| `ALLOWED_ORIGINS` | `http://localhost:50080` | Разрешённые browser origins |
| `SERVICES_OVERRIDE` | пусто | Строгий overlay versioned-профилей для Compose |
| `TSAAddress` | test CryptoPro TSA | Используется только внешним signing runtime |

В production используются `https://esia.gosuslugi.ru` и `https://www.gosuslugi.ru`. Секреты signing runtime не должны храниться в `.env`, Git или публичном Docker-образе.

`XML_ROOT=/xml` задаётся самим Compose; каталог уже встроен в backend-образ.

## `SERVICES_OVERRIDE` и standalone `SERVICES`

Backend-код читает `SERVICES`. Compose намеренно не подхватывает одноимённую legacy-переменную из host `.env`, а выполняет явное отображение:

```yaml
- SERVICES=${SERVICES_OVERRIDE:-}
```

Следовательно:

- в корневом `.env` для Compose используйте `SERVICES_OVERRIDE`;
- при standalone `uvicorn` используйте `SERVICES`;
- пустое значение оставляет встроенный `service_profiles.json` без изменений;
- существующий профиль deep-merge-ится, новый обязан быть полным и пройти startup-валидацию;
- `available=true` допустимо только для проверенного `status=verified` профиля.

Пример безопасного несекретного overlay:

```dotenv
SERVICES_OVERRIDE={"60010153":{"title":"Локальное отображаемое название"}}
```

## Frontend URL и Nginx

Правильная compose-пара:

```dotenv
BACKEND_URL=/api
BACKEND_API=http://api:5000
```

Axios использует `/api` как browser base URL. Nginx принимает `/api/...` и благодаря `proxy_pass ${BACKEND_API}/` снимает префикс перед отправкой в FastAPI.

Не добавляйте `/api` к `BACKEND_API`: значение `http://api:5000/api` превратит `/api/version` в upstream `/api/version`, тогда как backend route — `/version`.

`BACKEND_URL` встраивается на этапе React build и требует пересборки frontend. `BACKEND_API` подставляется entrypoint-скриптом при старте контейнера.

## Размеры и таймауты upload

Nginx настроен на:

- `client_max_body_size 64m`;
- `proxy_request_buffering off` и `proxy_buffering off`;
- `proxy_read_timeout 300s` и `proxy_send_timeout 300s`.

Это лимит входного multipart-комплекта, а не размер upstream chunk. Backend дополнительно ограничивает каждый файл и их сумму 50 000 000 байт, собирает ZIP в памяти и затем отправляет части до 50 МБ. Поднимать лимит или таймауты можно только после нагрузочной проверки и согласованного увеличения ресурсов.

## Healthcheck без CSP

- `/version` — core readiness; используется Dockerfile и работает без CryptoPro.
- `/hc` — CSP readiness; публичный образ отвечает degraded/`503`.
- `/status` — версия pycades; без signing runtime отвечает `503`.

Не настраивайте compose readiness на `/hc`: frontend тогда никогда не дождётся публичного core-образа.

## Публичный образ не подписывает

В backend image нет CryptoPro CSP, `pycades`, закрытых ключей и ведомственных CA. Каталог, Swagger, XML/XSD и `/goskey/preview` доступны; получение подписанного токена и `/goskey/submit` требуют отдельного лицензированного runtime. Обычное монтирование файла ключа не добавит в образ криптопровайдер.

## Нет bind mounts

Текущий Compose не монтирует host-код, XML, конфиги, Nginx template или shell scripts. Все эти артефакты входят в образы. Поэтому:

- нет зависимости от CRLF/LF host checkout при запуске контейнеров;
- нельзя исправить runtime простым редактированием host-файла;
- после изменения кода/profile/XML/template нужно пересобрать соответствующий image.

```bash
docker compose up -d --build api
docker compose up -d --build frontend
```

## CORS и публичные порты

Compose публикует API и UI только на loopback:

- <http://localhost:55000/> — прямой FastAPI;
- <http://localhost:50080/> — UI;
- <http://localhost:50080/api/> — тот же API через Nginx.

Для production задайте `ALLOWED_ORIGINS` точным HTTPS origin. Debug-порт стандартным Compose не публикуется.

## Single-operator security boundary

`ACCESS_TKN_ESIA`, `CURRENT_CERT_ID` и certificate registry глобальны для backend process. Встроенной пользовательской authentication/authorization нет, поэтому один runtime предназначен для одного оператора/tenant.

- Не меняйте bind на `0.0.0.0` для прямого LAN/Internet доступа.
- Для shared/public deployment используйте внешний TLS/auth reverse proxy с authorization, rate limits и аудитом.
- Запускайте отдельный backend process/runtime и отдельный secrets scope на каждого оператора/tenant.
- Не считайте `ALLOWED_ORIGINS` защитой API: CORS ограничивает браузер, но не произвольный HTTP-клиент.

## Минимальная локальная конфигурация

Для core/catalogue достаточно defaults:

```bash
docker compose up -d --build
curl http://localhost:55000/version
curl http://localhost:50080/api/version
```

Для вызовов внешнего API добавьте собственный `apikey` и согласованные параметры среды, не помещая реальные значения в документацию или Git.

См. [архитектуру и запуск](./02-architecture-and-run.md), [API](../api.md) и [каталог услуг](../SERVICES.md).
