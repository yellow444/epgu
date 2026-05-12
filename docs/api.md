# REST API бэкенда

Базовый путь при запуске в Docker: `http://localhost:5000/` (через Nginx: `http://localhost:5080/api/`).

FastAPI автоматически публикует Swagger: <http://localhost:5000/docs>.

> Источник истины по внешним вызовам — [Спецификация API ЕПГУ v1.13](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_13.docx) (с правками v1.12.1 по ГОСТ TLS и СМЭВ4). Внутренние эндпоинты бэкенда транслируют соответствующие методы спецификации, добавляя криптооперации через `pycades` и валидацию XML по локальному XSD.

## Сводная таблица

| Метод | Путь | Назначение | Источник в спец. v1.13 |
|---|---|---|---|
| GET | `/hc` | Health-check (есть ли PyCades) | — (внутренний) |
| GET | `/status` | Версия PyCades / модуля | — (внутренний) |
| GET | `/version` | Расширенная диагностика: pycades, среда, host'ы, число услуг, версия спецификации | — (внутренний) |
| GET | `/environments` | Справочник известных сред (test/prod): host'ы ЕСИА/ЕПГУ, технологический портал, согласия | — (внутренний) |
| POST | `/get_certificates` | Список сертификатов из хранилища CSP | — (внутренний) |
| GET | `/get_certificates` | То же (fallback) | — (внутренний) |
| POST | `/set_current_certificate?cert_id=...` | Выбор активного сертификата | — (внутренний) |
| POST | `/get_current_certificate` | Текущий сертификат и его субъект | — (внутренний) |
| POST | `/accessTkn_esia` | Получение JWT от ЕСИА | ЕСИА `/esia-rs/.../tkn` |
| POST | `/order` | Создать/запросить заявление по услуге | `POST /api/gusmev/order` |
| POST | `/order/{orderId}` | Детали заявления + список ответных файлов | `POST /api/gusmev/order/{id}` |
| POST | `/order/{orderId}/cancel` | Отменить заявление | `POST /api/gusmev/order/{id}/cancel` |
| GET  | `/getUpdatedAfter` | Заявления, обновлённые после даты | `GET /api/gusmev/order/getUpdatedAfter` |
| GET  | `/getOrdersStatus/` | Статусы по списку orderIds | `GET /api/gusmev/order/getOrdersStatus` |
| POST | `/dictionary/{code}` | Справочник НСИ | `POST /api/nsi/v1/dictionary/{code}` |
| POST | `/download_file/{objectId}/{objectType}` | Скачать файл-ответ | `GET /api/gusmev/files/download/{id}/{type}` |
| GET  | `/services` | Справочник услуг (из env `SERVICES`) | — (внутренний) |
| GET  | `/services/{code}` | Описание одной услуги (404 если не зарегистрирована) | — (внутренний) |
| GET  | `/xsd?simple_type_name=...` | Перечисления (`xs:enumeration`) из XSD | — (внутренний) |
| GET  | `/xml?service=...` | Эталонные `req.xml` и `piev_epgu.xml` услуги | — (внутренний) |
| POST | `/zipsize` | Размер будущего zip-архива из файлов | — (внутренний) |
| POST | `/push` | Отправка заявления в ЕПГУ (одним куском) | `POST /api/gusmev/push` |
| POST | `/push/chunked` | Chunked-отправка + XSD-валидация `piev_epgu.xml` | `POST /api/gusmev/push/chunked` |

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
| `apikey` | `my api key` | API-ключ организации (выпускается на технологическом портале ЕСИА) |
| `KeyPin` | `1234567890` | PIN контейнера ключа |
| `TSAAddress` | `http://www.cryptopro.ru/tsp/tsp.srf` | TSA для CAdES |
| `esia_host` | `https://esia-portal1.test.gosuslugi.ru` | ЕСИА (тест). Для прод: `https://esia.gosuslugi.ru` |
| `svcdev_host` | `https://svcdev-beta.test.gosuslugi.ru` | СМЭВ/ЕПГУ (тест). Для прод (ГОСТ TLS): `https://lk.gosuslugi.ru` |
| `XSD_FILE` | `/xml/piev_epgu.xsd` | Схема для валидации |
| `SERVICES` | см. `app.py` | JSON-справочник услуг |
| `production` | пусто | Если пусто — включается `debugpy` на `:5678` |

> **Подключение через СМЭВ4 (ПОДД)** — альтернатива прямому ГОСТ TLS. На тестовом контуре спецификация публикуется в `https://lkuv.gosuslugi.ru/paip-portal/`. На промышленном — на момент 2024-05 не опубликована. Подключение требует Агента ПОДД (см. [Документы СМЭВ 4 (ПОДД)](https://info.gosuslugi.ru/docs/section/%D0%A1%D0%9C%D0%AD%D0%92_4_(%D0%9F%D0%9E%D0%94%D0%94)/)). Бэкенд проксирует запросы по тому же контуру URL — переключение производится сменой `svcdev_host`.

## Поддерживаемые услуги

Полный каталог услуг и кодов — в [SERVICES.md](./SERVICES.md). По умолчанию в `app.py` зарегистрированы:

| Код | Описание | XML / XSD |
|---|---|---|
| `60010153` | Наличие ИП (ФССП) | `req.xml`, `piev_epgu.xml` (XSD: `piev_epgu.xsd`) |
| `10000000367` | Подача заявлений/ходатайств/объяснений | `req.xml`, `piev_epgu.xml` |
| `10000000109` | Доставка пенсии и социальных выплат ПФР/СФР | `req.xml`, `piev_epgu.xml` |
| `60010154` | Предоставление информации о ходе ИП (ФССП) | `req.xml`, `piev_epgu.xml` |
