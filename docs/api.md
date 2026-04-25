# REST API бэкенда

Базовый путь при запуске в Docker: `http://localhost:5000/` (через Nginx: `http://localhost:5080/api/`).

FastAPI автоматически публикует Swagger: <http://localhost:5000/docs>.

## Сводная таблица

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/hc` | Health-check (есть ли PyCades) |
| GET | `/status` | Версия PyCades / модуля |
| POST | `/get_certificates` | Список сертификатов из хранилища CSP |
| GET | `/get_certificates` | То же (fallback) |
| POST | `/set_current_certificate?cert_id=...` | Выбор активного сертификата |
| POST | `/get_current_certificate` | Текущий сертификат и его субъект |
| POST | `/accessTkn_esia` | Получение JWT от ЕСИА |
| POST | `/order` | Создать/запросить заявление по услуге |
| POST | `/order/{orderId}` | Детали заявления + список ответных файлов |
| POST | `/order/{orderId}/cancel` | Отменить заявление |
| GET  | `/getUpdatedAfter` | Заявления, обновлённые после даты |
| GET  | `/getOrdersStatus/` | Статусы по списку orderIds |
| POST | `/dictionary/{code}` | Справочник НСИ |
| POST | `/download_file/{objectId}/{objectType}` | Скачать файл-ответ |
| GET  | `/services` | Справочник услуг (из env `SERVICES`) |
| GET  | `/xsd?simple_type_name=...` | Перечисления (`xs:enumeration`) из XSD |
| GET  | `/xml?service=...` | Эталонные `req.xml` и `piev_epgu.xml` услуги |
| POST | `/zipsize` | Размер будущего zip-архива из файлов |
| POST | `/push` | Отправка заявления в ЕПГУ (одним куском) |
| POST | `/push/chunked` | Chunked-отправка + XSD-валидация `piev_epgu.xml` |

## Модели запросов

### `APIKeyRequest`

```json
{ "api_key": "GUID" }
```

### `OrderRequest`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| region | string | `45000000000` | ОКТМО региона |
| serviceCode | string | `60010153` | Код услуги ЕПГУ |
| targetCode | string | `-60010153` | Код цели |

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

Ответ — JSON с полем `accessTkn` (JWT). Сохраняется в глобальной переменной `ACCESS_TKN_ESIA`.

### Отправка заявления (chunked)

```http
POST /push/chunked
Content-Type: multipart/form-data

meta=<json>
orderId=<id>
chunks=<N>
chunk=<i>
files_upload=@piev_epgu.xml
files_upload=@...
```

Backend:
1. Парсит `meta` как JSON.
2. Собирает zip из всех `files_upload`; если среди них `piev_epgu.xml` — валидирует по XSD.
3. Вызывает `{svcdev_host}/api/gusmev/push/chunked` с заголовком `Authorization: Bearer <ACCESS_TKN_ESIA>`.

### Скачивание ответного файла

`fileDetails` из `POST /order/{orderId}` содержит поля `objectId`, `objectType`, `mnemonic`, `eserviceCode`. Они подставляются в `/download_file/{objectId}/{objectType}?mnemonic=...&eserviceCode=...`.

## Коды ошибок

| Код | Источник | Причина |
|---|---|---|
| 400 | backend | Неверный API-key, неверный XML, неверный JSON meta |
| 404 | backend | Для `order/{id}` — пустой `orderResponseFiles` / не парсится |
| 499 | backend | Клиент разорвал соединение при zip-сборке |
| 500 | backend | Ошибка криптопровайдера / неизвестная ошибка |
| любой | ЕПГУ | Проксируется `err.response.status_code` |

## Переменные окружения

| Имя | По умолчанию | Назначение |
|---|---|---|
| `apikey` | `my api key` | API-ключ организации |
| `KeyPin` | `1234567890` | PIN контейнера ключа |
| `TSAAddress` | `cryptopro.ru/tsp` | TSA для CAdES |
| `esia_host` | `esia-portal1.test.gosuslugi.ru` | ЕСИА |
| `svcdev_host` | `svcdev-beta.test.gosuslugi.ru` | СМЭВ/ЕПГУ |
| `XSD_FILE` | `/xml/piev_epgu.xsd` | Схема для валидации |
| `SERVICES` | см. `app.py` | JSON-справочник услуг |
| `production` | пусто | Если пусто — включается `debugpy` на `:5678` |
