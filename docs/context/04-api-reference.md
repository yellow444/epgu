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
| POST | `/geps/search` | Заказать список уведомлений Госпочты за период |
| GET | `/geps/search/{task_uuid}` | Забрать заказанный список (`offset`, `limit`) |
| GET | `/geps/message/{thread}/{message}` | Карточка уведомления: текст, вложения, статусы |
| GET | `/geps/attachment/{message}/{attachment}/{file\|sig}` | Вложение или отсоединённая подпись |
| GET | `/geps/quota` | Остаток суточных попыток ГЭПС, без обращения к ЕПГУ |
| GET | `/geps/scheduler` | Состояние планировщика Госпочты |
| POST | `/geps/scheduler` | Включить или выключить автоматический забор (`enabled`) |
| POST | `/geps/scheduler/run` | Один такт прямо сейчас |
| GET | `/geps/jobs` | Заказанные списки и их состояние (с тома) |
| GET | `/geps/messages` | Сохранённые уведомления страницами |
| GET | `/geps/messages/{uuid}` | Сохранённая карточка с путями к вложениям |
| POST | `/geps/messages/{uuid}/attachments/{uuid}/save` | Скачать вложение на том |

## Вложения и файлы вручную

Почта нужна не всегда, а ответ поддержки не всегда сертификат: приходят
инструкции в PDF, документы Word, архивы. Разбор делает
[`attachments.py`](../../api-gosuslugi-backend/attachments.py).

| Метод | Путь | Назначение |
| --- | --- | --- |
| POST | `/certsources/upload` | Принести файлы руками (`target`: `certs` или `keys`) |
| GET | `/certsources/inspect` | Разобрать файл: текст, ссылки, вложенные файлы, подсказки |
| POST | `/certsources/extract` | Достать вложения архива или документа на диск |
| POST | `/certificates/delete` | Удалить сертификат (`cert_id`), сначала скопировав ключи |

Удаление устроено осторожно, потому что КриптоПро уносит сертификат вместе с
привязанным ключевым контейнером. Перед вызовом `certmgr -delete` каталог ключей
копируется в `keys-backup-<метка времени>` рядом с хранилищем, путь к копии
возвращается в ответе вместе со списком оставшихся контейнеров.

Что понимает разбор: PDF (текст через pypdf, ссылки, вложенные файлы), DOCX
(текст и объекты из `word/embeddings`), ZIP (список и извлечение),
сертификаты и файлы ключевого контейнера.

Отдельная подсказка про случай из практики: если PDF получен печатью из Word,
значки вложенных контейнеров в нём видны, а самих файлов нет. Разбор это
замечает и советует запросить исходный документ.

## Отдача Госпочты наружу (`outbound.py`, порт 58081)

Отдельный процесс. Читает только том с уже забранными уведомлениями, в ЕПГУ не
ходит. Закрыт, пока не задан `OUTBOUND_TOKEN` или `OUTBOUND_ALLOW_NETS`.

| Метод | Путь | Назначение |
| --- | --- | --- |
| GET | `/health` | Живость, отвечает всегда |
| GET | `/messages` | Уведомления в нашем JSON (`offset`, `limit`, `only_unread`, `since`) |
| GET | `/messages/{uuid}` | Одно уведомление: текст, разметка, статусы |
| GET | `/messages/{uuid}/attachments/{uuid}` | Файл вложения или подпись (`signature=true`) |
| GET | `/letters` | Те же данные в формате `Letters/Letter` (`request_id`) |

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
