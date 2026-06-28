# 04 - API и структура фронтенда

## Эндпоинты бэкенда (`api-gosuslugi-backend/app.py`)

| Метод | Путь | Назначение |
| --- | --- | --- |
| GET | `/status` | Версия модуля PyCades |
| GET | `/hc` | Health-check |
| POST | `/get_certificates` | Список доступных сертификатов |
| POST | `/set_current_certificate` | Выбрать текущий сертификат (`cert_id`) |
| POST | `/get_current_certificate` | Текущий сертификат |
| POST | `/accessTkn_esia` | Получить токен доступа ЕСИА (по `api_key`) |
| POST | `/order` | Создать заявление (`region`, `serviceCode`, `targetCode`) |
| POST | `/order/{orderId}` | Детали/статус заявления |
| POST | `/order/{orderId}/cancel` | Отмена заявления |
| GET | `/getUpdatedAfter` | Обновления (`pageNum`, `pageSize`, `updatedAfter`) |
| GET | `/getOrdersStatus/` | Статусы заявлений |
| POST | `/dictionary/{code}` | Справочник по коду |
| POST | `/download_file/{objectId}/{objectType}` | Скачать файл (`mnemonic`, `eserviceCode`) |
| GET | `/services` | Список услуг (из `SERVICES`) |
| GET | `/xsd` | XSD-схема |
| GET | `/xml` | Шаблон XML по услуге (`service`) |
| POST | `/zipsize` | Размер будущего ZIP-архива |
| POST | `/push` | Отправка файла |
| POST | `/push/chunked` | Отправка файла по частям (`meta`, `orderId`, `chunks`, `chunk`) |

Все вызываются фронтендом как `${BACKEND_URL}/<путь>` (см. [03](03-config-and-known-issues.md), грабля №3).

## Файлы данных бэкенда

- `api-gosuslugi-backend/xml/req.xml` - запрос услуги.
- `api-gosuslugi-backend/xml/piev_epgu.xml` + `piev_epgu.xsd` - данные ПИЭВ + XSD для валидации.
- `api-gosuslugi-backend/certs/` - корневые/промежуточные сертификаты, ставятся в entrypoint.

## Фронтенд (`api-gosuslugi-client/src`)

- `App.js` (~2000 строк) - основная логика: подача заявления, выбор услуги, редактор XML, статусы. `BACKEND_URL` определён на `App.js:18-19`.
- `components/`
  - `FileDropzone/` - drag-and-drop загрузка файлов.
  - `Instructions/` - вкладка с инструкциями (тест/прод setup; ссылки на каталог partners.gosuslugi.ru).
  - `JsonViewer/` - просмотр JSON-ответов.
- `index.js`, `App.css`, `index.css`, `setupTests.js`, `App.test.js` (мокает axios).
- nginx: `default.conf.template` (+ `entrypoint.sh` подставляет `BACKEND_API` через `envsubst`).

## Postman

Коллекция запросов к API - корень: `api gosuslugi.postman_collection.json`.

## Расхождения в официальной документации

Сводка несоответствий в спецификациях ЕПГУ/ЕСИА (push/chunked vs order, коды услуг, `DsContentType=21`,
диапазон `TrusteeDoctype`, статус SAML, нумерация разделов, GET vs POST для `getOrdersStatus`/`getUpdatedAfter`,
лишний `/` перед query) - см. [`issue.md`](../../issue.md).
