# HOWTO - backend FastAPI

Backend работает в двух режимах:

- **core/catalogue** - обычный Python 3.12 без CryptoPro; доступны `/version`,
  Swagger, profiles, XML/XSD и preview;
- **signing** - тот же процесс на хосте с лицензированными CryptoPro CSP и
  совместимым `pycades`.

## Запуск

Из каталога `api-gosuslugi-backend`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:ALLOWED_ORIGINS='http://localhost:3000,http://127.0.0.1:3000'
python -m uvicorn app:app --host 127.0.0.1 --port 55000
```

На Linux/macOS активируйте `.venv/bin/activate`. Проверка:

```powershell
curl.exe http://127.0.0.1:55000/version
```

`/version` должен вернуть `200` без CSP. `/hc` и `/status` проверяют именно
CryptoPro/`pycades`, поэтому в core-режиме ожидаемо возвращают `503`.

## Граница доступа

Backend хранит `ACCESS_TKN_ESIA`, `CURRENT_CERT_ID` и реестр сертификатов
глобально в процессе. Один процесс предназначен для одного оператора/tenant;
встроенной многопользовательской аутентификации в публичном ядре нет.

Оставляйте основной API на loopback. Сетевое развёртывание требует внешнего
TLS, authentication, authorization, rate-limit, аудита и отдельного процесса с
собственным scope секретов для каждого оператора. `ALLOWED_ORIGINS` - только
browser-policy, а не замена аутентификации.

## Тесты

```powershell
python -m pip install -r requirements-test.txt
python -m pytest -c pytest.ini
```

## Каталог услуг

Встроенный `service_profiles.json` генерируется из локального снимка
официального каталога. Добавление рабочей услуги требует точного транспорта,
имён документов, XSD, подписей, typed-генератора/golden-тестов и проверки в
авторизованном контуре.

Из корня репозитория:

```powershell
python scripts/sync_api_for_gu_docs.py
python scripts/extract_api_for_gu_assets.py
python scripts/build_service_profiles.py
```

Для локального deep-overlay существующего профиля задайте переменную
`SERVICES`. Новый профиль должен быть полным и пройти startup-валидацию.

## Signing runtime

Операции `/accessTkn_esia` и `/goskey/submit` требуют `pycades`. На хосте
администратор отдельно устанавливает:

- лицензированный CryptoPro CSP и совместимый `pycades`;
- доверенную цепочку CA выбранного контура;
- сертификат с доступным закрытым ключом;
- секреты вне Git и с минимальными правами процесса.

Простое копирование файла сертификата не устанавливает CSP и не переносит
закрытый ключ. Конкретный способ хранения ключевого контейнера зависит от
операционной системы и лицензированного runtime.

## Типовые ошибки

| Симптом | Причина / действие |
|---|---|
| `/version` недоступен | Ошибка старта; смотрите терминал процесса |
| `/hc` и `/status` возвращают `503` | Нет CSP/`pycades` |
| `/accessTkn_esia` возвращает `503` | Signing runtime не настроен |
| `Некорректный реестр услуг` | Невалидный `SERVICES` overlay |
| `Invalid XML` | Документ не соответствует XSD профиля |
| Крупный upload завершается `413` | Превышен лимит 50 000 000 байт |

См. [REST API](../docs/api.md), [развёртывание](../docs/deployment.md),
[безопасность](../docs/security.md) и [каталог услуг](../docs/SERVICES.md).
