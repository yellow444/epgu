# HOWTO - backend FastAPI

Backend имеет два режима:

- **core/catalogue** - публичный Python runtime без CryptoPro; доступны `/version`, Swagger, profiles, XML/XSD и preview;
- **signing** - отдельно лицензированный runtime с совместимыми CryptoPro CSP и `pycades`.

Публичный Docker-образ не устанавливает CSP и запускается непривилегированным пользователем `app`.

## Standalone-запуск

Из каталога `api-gosuslugi-backend` с Python 3.12:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload --host 127.0.0.1 --port 5000
```

Проверка:

```powershell
curl.exe http://127.0.0.1:5000/version
```

CryptoPro не нужен для core-запуска. При standalone-режиме overlay каталога передаётся непосредственно переменной `SERVICES`; имя `SERVICES_OVERRIDE` используется только внешним Compose.

## Docker Compose

Из корня репозитория:

```bash
docker compose up -d --build api
docker compose logs -f api
```

API публикуется только на loopback: <http://localhost:55000/> (`127.0.0.1:55000`). Стандартный Compose не публикует debug-порт и не использует bind mounts.

Backend image содержит код, Python-библиотеку, `service_profiles.json` и `xml/`. После их изменения пересоберите image:

```bash
docker compose up -d --build api
```

## Health и диагностика

```bash
curl http://localhost:55000/version
curl http://localhost:55000/hc
curl http://localhost:55000/status
```

- `/version` - core readiness и Docker healthcheck; должен вернуть `200` без CSP.
- `/hc` - CSP readiness; в публичном образе ожидаем degraded/`503`.
- `/status` - версия pycades; без signing runtime ожидаем `503`.

Frontend ждёт healthy `/version`, а не `/hc`.

## Граница доступа

Backend хранит `ACCESS_TKN_ESIA`, `CURRENT_CERT_ID` и certificate registry глобально в процессе. Один process/runtime предназначен для одного оператора/tenant; встроенной пользовательской authentication/authorization нет.

Не заменяйте loopback bind стандартного Compose на `0.0.0.0` для прямого LAN/Internet доступа. Shared/public deployment требует:

- внешний reverse proxy с TLS, authentication, authorization, rate limits и аудитом;
- отдельный backend process/runtime и secrets scope на каждого оператора/tenant;
- точный `ALLOWED_ORIGINS` как дополнительную browser-policy, а не замену auth.

Frontend Nginx принимает тело до 64 МБ и использует 300-секундные read/send timeouts. Backend ограничивает каждый исходный файл и их сумму 50 000 000 байт, собирает ZIP в памяти и затем нарезает upstream chunks до 50 МБ. Проверяйте крупные комплекты нагрузочным тестом до изменения лимитов.

## Тесты

Из `api-gosuslugi-backend`:

```bash
python -m pip install -r requirements-test.txt
python -m pytest -c pytest.ini
```

Контейнерная проверка из корня репозитория:

```bash
docker build -f api-gosuslugi-backend/Dockerfile.test -t epgu-backend-test .
docker run --rm epgu-backend-test
```

## Конфигурация услуг

Встроенный `service_profiles.json` генерируется из локального снимка официального каталога. Добавление рабочей услуги - это не только новая строка в JSON:

1. Обновить и проверить официальный снимок:

   ```bash
   python scripts/sync_api_for_gu_docs.py
   python scripts/extract_api_for_gu_assets.py
   ```

2. Описать точный транспорт, archive name, документы, XSD, подписи и capability state в генераторе profiles.
3. Добавить безопасные XML/XSD или typed-генератор и golden/contract tests.
4. Перегенерировать registry:

   ```bash
   python scripts/build_service_profiles.py
   ```

5. Запустить backend и Python SDK tests. `available=true` ставится только для `status=verified` контракта.

Для локального изменения существующего профиля:

- Compose: корневая переменная `SERVICES_OVERRIDE`;
- standalone backend: переменная `SERVICES`.

Обе переменные задают строгий deep-overlay. Новый профиль должен быть полным и пройти startup-валидацию; нельзя отправлять XML другой услуги под новым кодом.

## Signing runtime

Операции `/accessTkn_esia` и `/goskey/submit` требуют `pycades`. Оператор signing runtime отвечает за:

- лицензированную установку CryptoPro CSP/pycades;
- закрытый ключ и секреты вне Git/image;
- доверенную цепочку CA выбранного контура;
- минимальные права процесса и аудит операций подписи.

Простое добавление ключевого файла к публичному контейнеру не устанавливает CSP. Конкретный способ предоставления ключа зависит от лицензированного runtime и инфраструктуры секретов.

## Типовые ошибки

| Симптом | Причина / действие |
|---|---|
| `/version` недоступен или container unhealthy | Ошибка core startup; смотрите `docker compose logs api` |
| `/hc` и `/status` возвращают `503` | Ожидаемо для публичного no-CSP образа |
| `/accessTkn_esia` или `/goskey/submit` возвращает `503` | Нужен отдельно настроенный signing runtime |
| `Некорректный реестр услуг` при старте | Невалидный `SERVICES`/`SERVICES_OVERRIDE` overlay |
| `Invalid XML: ...` | Документ не well-formed или не соответствует XSD своего профиля |
| Изменение host-файла не видно в контейнере | Bind mounts отсутствуют; пересоберите image |
| Крупный upload завершается `413` | Тело превысило Nginx `client_max_body_size 64m` или backend-лимит 50 000 000 байт |
| Container завершается на крупном upload | ZIP собирается в памяти; согласуйте body limit и backend memory |

См. [REST API](../docs/api.md), [развёртывание](../docs/deployment.md), [безопасность](../docs/security.md) и [каталог услуг](../docs/SERVICES.md).
