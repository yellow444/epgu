# REST API бэкенда

Прямой адрес backend в Docker Compose: `http://localhost:55000/`. Frontend проксирует тот же API через `http://localhost:50080/api/`; Nginx снимает префикс `/api/`, поэтому `/api/version` превращается в upstream-запрос `/version`. Оба host-порта привязаны к `127.0.0.1` и доступны только с локальной машины.

FastAPI публикует Swagger напрямую на <http://localhost:55000/docs> и через frontend proxy на <http://localhost:50080/api/docs>.

Compose healthcheck использует `GET /version`, который работает в публичном core-образе без CryptoPro. `GET /hc` и `GET /status` проверяют именно CSP/pycades и без отдельного signing runtime закономерно возвращают `503`.

> Источник истины по внешним вызовам - [каталог API для госорганов](https://partners.gosuslugi.ru/catalog/api_for_gu), локальный снимок которого зафиксирован в [docs/api_for_gu](./api_for_gu/README.md). Общий транспорт реализован по спецификации API ЕПГУ v1.14; XML, подпись и способ отправки выбираются из versioned-профиля конкретной услуги.

## Сводная таблица

| Метод | Путь | Назначение | Источник в спец. v1.14 |
|---|---|---|---|
| GET | `/hc` | CSP readiness: `200` с PyCades, degraded/`503` без него | - (внутренний) |
| GET | `/status` | Версия PyCades / модуля | - (внутренний) |
| GET | `/version` | Core readiness и диагностика: pycades, среда, hosts, число услуг, версия спецификации | - (внутренний) |
| GET | `/environments` | Справочник известных сред (test/prod): host'ы ЕСИА/ЕПГУ, технологический портал, согласия | - (внутренний) |
| POST | `/get_certificates` | Список сертификатов из хранилища CSP | - (внутренний) |
| POST | `/set_current_certificate?cert_id=...` | Выбор активного сертификата | - (внутренний) |
| POST | `/get_current_certificate` | Текущий сертификат и его субъект | - (внутренний) |
| POST | `/accessTkn_esia` | Получение JWT от ЕСИА | ЕСИА `/esia-rs/.../tkn` |
| POST | `/order` | Создать/запросить заявление по услуге | `POST /api/gusmev/order` |
| POST | `/order/{orderId}` | Детали заявления + список ответных файлов | `POST /api/gusmev/order/{id}` |
| POST | `/order/{orderId}/cancel` | Отменить заявление | `POST /api/gusmev/order/{id}/cancel` |
| GET  | `/getUpdatedAfter` | Заявления, обновлённые после даты | `GET /api/gusmev/order/getUpdatedAfter` |
| GET  | `/getOrdersStatus` | Статусы по списку orderIds | `GET /api/gusmev/order/getOrdersStatus` |
| POST | `/dictionary/{code}` | Справочник НСИ | `POST /api/nsi/v1/dictionary/{code}` |
| POST | `/download_file/{objectId}/{objectType}` | Скачать файл-ответ | `GET /api/gusmev/files/download/{id}/{type}` |
| GET  | `/services` | Справочник услуг + профиль отправки (режим, шаблоны файлов) | - (внутренний) |
| GET  | `/services/{code}` | Описание одной услуги (404 если не зарегистрирована): `submissionMode`, `submissionDocuments`, `archiveNameTemplate` | - (внутренний) |
| GET  | `/xsd?service=...&simple_type_name=...` | Перечисления из собственной XSD выбранной исполняемой услуги | - (внутренний) |
| GET  | `/xml?service=...` | Локальные XML-шаблоны и метаданные профиля; генерируемый XML Госключа см. `/goskey/preview` | - (внутренний) |
| POST | `/zipsize` | Размер будущего zip-архива из файлов | - (внутренний) |
| POST | `/push` | Отправка заявления в ЕПГУ (одним куском) | `POST /api/gusmev/push` |
| POST | `/push/chunked` | Chunked-отправка + XSD-валидация по профилю документа | `POST /api/gusmev/push/chunked` |
| GET | `/goskey/capabilities` | Верифицированные и reference-only контракты Госключа | - (внутренний) |
| POST | `/goskey/preview` | Сгенерировать `req.xml` Госключа без подписи и отправки | - (внутренний) |
| POST | `/goskey/submit` | Сгенерировать, подписать и отправить архив Госключа выбранным транспортом | `push` или `order` + `push/chunked` |

## Модели запросов

### `APIKeyRequest`

```json
{ "api_key": "GUID" }
```

### `OrderRequest`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| region | string | обязательное | ОКАТО пользователя, передаваемый во время выполнения |
| serviceCode | string | обязательное | Код зарегистрированной услуги ЕПГУ |
| targetCode | string | обязательное | Код цели из профиля выбранной услуги |

### `GoskeyRequest`

`POST /goskey/preview` принимает JSON этой модели. `POST /goskey/submit` принимает multipart: поле `request` с тем же JSON и одно или несколько полей `documents` с файлами. Срок `signExpiration` должен быть будущим временем в пределах 24 часов; точный набор идентификаторов получателя зависит от услуги и capability.

## Ключевые сценарии

### Получение токена ЕСИА

```http
POST /accessTkn_esia
Content-Type: application/json

{ "api_key": "<GUID>" }
```

Backend подписывает `api_key` сертификатом (CAdES-BES, detached) через `pycades`, декодирует в url-safe base64 и вызывает:

```
GET {esia_host}/esia-rs/api/public/v1/orgs/ext-app/{api_key}/tkn?signature=...
```

Ответ - JSON с полем `accessTkn` (JWT). Сохраняется в глобальной переменной `ACCESS_TKN_ESIA`.

### Отправка заявления (chunked)

```http
POST /push/chunked
Content-Type: multipart/form-data

meta=<json>
orderId=<id>
files_upload=@piev_epgu.xml
files_upload=@...
```

Backend:
1. Проверяет `meta`, исполняемость услуги и соответствие `targetCode` профилю.
2. Один раз собирает ZIP из `files_upload`, проверяет обязательные имена, well-formed XML, XSD и detached-подписи по профилю.
3. Сам делит ZIP на части профиля (5-50 МБ) и последовательно вызывает `{svcdev_host}/api/gusmev/push/chunked`. В upstream-полях `chunk` используются индексы `0..N-1`; промежуточный ответ должен быть `206`, последний - `200`.

Клиент не нарезает архив. Старые поля формы допустимы только как `chunks=1`, `chunk=0` либо не передаются. `orderId` предварительно резервируется через `POST /order`. Для нескольких частей имена идут как `.z001`, `.z002`, ..., но значение поля `chunk` остаётся нулевым индексом.

Frontend Nginx ограничивает исходное multipart-тело значением `64m` и использует таймауты чтения/отправки 300 секунд. Backend отдельно ограничивает каждый исходный файл и их сумму 50 000 000 байт; upstream chunk также не превышает 50 МБ.

### Скачивание ответного файла

`fileDetails` из `POST /order/{orderId}` содержит поля `objectId`, `objectType`, `mnemonic`, `eserviceCode`. Они подставляются в `/download_file/{objectId}/{objectType}?mnemonic=...&eserviceCode=...`.

## Коды ошибок

| Код | Источник | Причина |
|---|---|---|
| 400 | backend | Неверный API-key, неверный XML, неверный JSON meta |
| 404 | backend | Для `order/{id}` - пустой `orderResponseFiles` / не парсится |
| 409 | backend | Профиль или вариант опубликован только для справки и не исполняется |
| 413 | backend | Adaptive-архив больше 50 МБ и требует `order` + chunked |
| 499 | backend | Клиент разорвал соединение при zip-сборке |
| 502 | backend | ЕПГУ вернул некорректный ответ или неожиданный `orderId`/HTTP-код части |
| 503 | backend | Для операции подписи недоступны `pycades`/CryptoPro CSP |
| 500 | backend | Ошибка криптопровайдера / неизвестная ошибка |
| любой | ЕПГУ | Проксируется `err.response.status_code` |

## Переменные окружения

Compose читает корневой `.env`, но передаёт контейнерам только переменные, перечисленные в `docker-compose.yml`.

| Имя | Compose default | Назначение |
|---|---|---|
| `apikey` | пусто | API-ключ организации (выпускается на технологическом портале ЕСИА) |
| `TSAAddress` | `http://testca2012.cryptopro.ru/tsp/tsp.srf` | Используется только отдельно подключённым signing runtime |
| `esia_host` | `https://esia-portal1.test.gosuslugi.ru` | ЕСИА (тест). Для прод: `https://esia.gosuslugi.ru` |
| `svcdev_host` | `https://svcdev-gostapi.test.gosuslugi.ru` | ЕПГУ (формальный test endpoint). Для prod: `https://www.gosuslugi.ru` |
| `XML_ROOT` | `/xml` | Встроенный в backend-образ корень XML/XSD; каждый профиль указывает собственную схему |
| `SERVICES_OVERRIDE` | пусто | Compose overlay; внутри контейнера передаётся приложению как `SERVICES` |
| `ALLOWED_ORIGINS` | `http://localhost:50080,http://127.0.0.1:50080` в compose | CORS allow-origins и обязательная Origin/Referer-проверка browser mutations; CLI/SDK без этих browser-заголовков поддерживаются |
| `UPSTREAM_CONNECT_TIMEOUT` | `15` | Таймаут соединения с ЕПГУ, секунды |
| `UPSTREAM_READ_TIMEOUT`, `UPSTREAM_WRITE_TIMEOUT` | `300` | Таймауты чтения/записи ЕПГУ для допустимых больших комплектов |
| `UPSTREAM_POOL_TIMEOUT` | `30` | Таймаут ожидания соединения из пула |
| `BACKEND_URL` | `/api` | Build-time base URL React; изменение требует пересборки frontend |
| `BACKEND_API` | `http://api:5000` | Runtime upstream Nginx; указывается без `/api` |
| `API_PORT` | `55000` | Loopback-only порт backend: `127.0.0.1:${API_PORT}:5000` |
| `FRONTEND_PORT` | `50080` | Loopback-only порт frontend: `127.0.0.1:${FRONTEND_PORT}:80` |

Полный шаблон - [.env.example](../.env.example).

При standalone-запуске backend без Compose строгий overlay передаётся непосредственно в `SERVICES`; `SERVICES_OVERRIDE` - защитное имя только внешнего compose-контракта. Публичный образ не монтирует `.env`, ключи или сертификаты и не содержит CryptoPro/pycades.

## Граница безопасности и tenancy

Backend хранит `ACCESS_TKN_ESIA`, `CURRENT_CERT_ID` и загруженные сертификаты в глобальном состоянии процесса. Стандартный Compose поэтому предназначен для одного локального оператора и не имеет встроенной пользовательской authentication/authorization.

Нельзя просто заменить loopback bind на `0.0.0.0` и считать систему общей. Для shared/LAN/public deployment необходим внешний reverse proxy с TLS, authentication, authorization, rate limiting и аудитом. Каждый оператор/tenant должен работать с отдельным backend process/runtime и собственным хранилищем секретов. Backend дополнительно отклоняет state-changing browser-запросы с чужим `Origin`/`Referer`; это защита локального оператора от CSRF, но не замена полноценной аутентификации API.

## Поддерживаемые услуги

Полный каталог из 21 профиля приведён в [SERVICES.md](./SERVICES.md). UI показывает также reference-only профили, но backend прекращает их обработку с `409` до внешнего вызова. На 2026-08-12 исполняемы три профиля Госключа:

| Код | Описание | Контракт |
|---|---|---|
| `10000000374` | Подписание физическим лицом в Госключе | УНЭП verified; УКЭП остаётся reference-only; adaptive |
| `60025907` | Подписание УКЭП юридическими лицами | typed XML + detached CAdES, adaptive |
| `60080470` | Подписание УКЭП с сертификатом Федерального казначейства | typed XML + detached CAdES, adaptive |

ФССП `60010153` имеет каталогизированные XSD и chunked-транспорт, но доступный XML является демонстрационным, а не безопасным рабочим вводом. Профиль остаётся `reference` до типизированной формы, fail-closed проверки placeholder/полей и приёмки в авторизованном контуре. `60079416` (расшифрование в Госключе) каталогизирован, но не исполняется из-за противоречий официальных источников. Для всех Госключ-сценариев каждый файл, включая `req.xml`, получает отдельный файл `.sig`; операции `/goskey/submit` требуют лицензированного CryptoPro/pycades runtime.
