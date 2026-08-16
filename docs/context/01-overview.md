# 01 - Обзор системы

## Назначение

Проект предоставляет Python-библиотеку, FastAPI backend и React frontend для интеграции с API ЕПГУ/ЕСИА. Система каталогизирует официальные профили услуг, формирует требуемые XML/ZIP-контракты, выбирает `push`/`chunked`/adaptive-транспорт и обрабатывает статусы и ответные документы.

По умолчанию используется тестовый контур. Production endpoints задаются конфигурацией; форматы XML/XSD и способ отправки всегда определяет versioned-профиль конкретной услуги.

Каталог содержит 21 профиль. Исполняемы только проверенные профили с `available=true`; reference-only услуги видны во frontend, но блокируются до внешнего вызова. Актуальный перечень: [SERVICES.md](../SERVICES.md).

## Состав

- **`python-epgu`** - публикуемая Python-библиотека с транспортными моделями, архивами, подписью через абстракцию signer и typed-контрактами Госключа.
- **Backend** - FastAPI на Python 3.12: каталог услуг, XML/XSD-проверка, proxy к ЕСИА/ЕПГУ и API для frontend.
- **Frontend** - React-приложение, собранное на Node 24 и отдаваемое Nginx; Nginx проксирует `/api/` во внутренний backend.

Публичный backend-образ запускается non-root и не содержит CryptoPro CSP или `pycades`. Core/catalogue, Swagger, профили и preview работают без них. Операции реальной подписи требуют отдельного лицензированного signing runtime.

## Среды по умолчанию

| Назначение | Test | Production |
|---|---|---|
| ЕСИА | `https://esia-portal1.test.gosuslugi.ru` | `https://esia.gosuslugi.ru` |
| API ЕПГУ | `https://svcdev-gostapi.test.gosuslugi.ru` | `https://www.gosuslugi.ru` |
| Техпортал ЕСИА | `https://esia-portal1.test.gosuslugi.ru/console/tech` | `https://esia.gosuslugi.ru/console/tech/` |

## Локальный запуск

```bash
docker compose up -d --build
```

- UI: <http://localhost:50080/>
- API напрямую: <http://localhost:55000/version>
- API через UI proxy: <http://localhost:50080/api/version>

Frontend ждёт healthy-состояния backend. Compose проверяет backend через `/version`; `/hc` предназначен для CSP readiness и в публичном образе возвращает degraded/`503`.

Порты `50080` и `55000` привязаны к `127.0.0.1`, поэтому стандартный Compose - локальный single-operator стенд. Nginx ограничивает multipart body значением 512 МБ и использует API proxy timeouts 300 секунд.

## Что требуется для интеграционного контура

1. Зарегистрированная ИС и API key организации для соответствующей среды.
2. Согласованное подключение к ЕСИА и ЕПГУ.
3. Точная среда и разрешённый frontend origin в конфигурации.
4. Отдельный лицензированный CryptoPro/`pycades` runtime и доверенная цепочка CA, если сценарий выполняет подпись.
5. Хранение API key и signing secrets вне репозитория и публичных образов.

Для shared/LAN/public сценария нужен внешний auth reverse proxy с TLS, authentication, authorization, rate limits и аудитом. Из-за process-global access token и выбранного сертификата каждому оператору/tenant требуется отдельный backend process/runtime; прямое открытие compose-портов недопустимо.

Пошаговые материалы: [step/STEP.md](../../step/STEP.md).

## Ограничения

- СУБД нет: активный токен и выбранный сертификат живут в памяти процесса, пользовательские файлы frontend - в IndexedDB.
- Backend хранит один глобальный access token на процесс и не является мультитенантным.
- CORS не является authentication; стандартный frontend/backend нельзя безопасно разделять между несколькими пользователями.
- Публичный Docker runtime не выполняет криптографические операции без отдельно установленного CSP.
- Reference-only профиль нельзя отправить, пока его XML/XSD-контракт не прошёл проверку.
- ZIP формируется backend в памяти; ingress limit 512 МБ должен быть согласован с memory limit и реальной нагрузкой.
