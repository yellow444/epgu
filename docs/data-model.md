# Модель данных

> Актуализировано: **2026-08-12**.

Проект не использует СУБД - данные хранятся **в памяти процесса бэкенда** и **в браузере** (IndexedDB / storage).

## Backend - in-memory state

| Структура | Тип | Описание | Время жизни |
|---|---|---|---|
| `CERTIFICATES` | `dict[str, pycades.Certificate]` | thumbprint -> объект сертификата; пусто в core runtime без CSP | до рестарта |
| `CURRENT_CERT_ID` | `str \| None` | активный сертификат | до рестарта |
| `ACCESS_TKN_ESIA` | `str` | JWT от ЕСИА | до рестарта / нового вызова |
| `ACCESS_TKN_EXP` | `int` | unix-timestamp срока действия JWT (`exp`); `0` - неизвестен | пересчитывается при получении токена |
| `ALLOWED_ORIGINS` | `list[str]` | CORS allow_origins (из env `ALLOWED_ORIGINS`) | весь запуск |
| `services_dict` | `dict[str, ServiceProfile]` | 21 встроенный профиль + строгий deep-overlay из `SERVICES` | весь запуск |
| `_load_schema` | LRU cache | до 32 `lxml.XMLSchema`, ключ — файл XSD выбранного профиля | весь запуск |

## Таблицы «виртуальных» сущностей

### Сертификат

| Поле | Источник | Пример |
|---|---|---|
| id (thumbprint) | `cert.Thumbprint` | `A1B2...` |
| SubjectName (raw) | `cert.SubjectName` | `CN="...", OU="..."` |
| parsed | `parse_string_to_json(SubjectName)` | `{CN, OU, O, SN}` |

### Услуга (`services_dict[code]`)

| Поле | Тип | Описание |
|---|---|---|
| serviceCode, title, agency | str | Идентификатор и описание услуги |
| protocol | str | `gusmev-order`, `geps`, `equeue` или `reference` |
| status / available | str / bool | `verified` не означает исполняемость без `available=true`; reference-профили блокируются |
| region | str | Каталожное значение; runtime `region` (ОКАТО пользователя) обязателен отдельно |
| targetCode / serviceTargetCode | str | Проверяемый код цели |
| submission.mode | str | `push`, `chunked` или `adaptive` |
| submission.documents[] | array | Имена, роли, обязательность, media type, XSD и detached-подпись каждого документа |
| spec / officialAssets | object / array | URL, дата, SHA-256 документа и извлечённых официальных XML/XSD |
| capabilities[] | array | Варианты Госключа и их `verified`/`reference` состояние |

`GET /services` добавляет совместимые aliases (`req_file`, `piev_epgu_file`, `submissionMode`, `submissionDocuments`), но источником истины остаётся versioned-профиль.

### Заявление (ответ `/order/{orderId}`)

| Поле | Тип | Источник |
|---|---|---|
| orderId | str | параметр пути |
| currentStatusHistoryId | int | `orderDetails.order.currentStatusHistoryId` |
| orderResponseFiles[] | array | список файлов-ответов |
| fileDetails[] | array | все элементы `orderResponseFiles` с непустыми `link` и `fileName` |

### Файл-ответ (`fileDetails[]`)

| Поле | Описание |
|---|---|
| objectId | `currentStatusHistoryId` |
| objectType | последний сегмент `file.link` |
| mnemonic | `file.fileName` |
| eserviceCode | `serviceCode` из запроса |

## Frontend - IndexedDB

База `files-db`, object store `files` (keyPath = `name`):

| Поле | Описание |
|---|---|
| name | имя файла (ключ) |
| content | dataURL / Blob |

Используется для сохранения загруженных пользователем XML и приложений между перезагрузками. Удаление одного файла и «Очистить все» синхронно удаляют соответствующие записи; кнопка полной очистки также стирает local/session storage. Хранение остаётся включённым по умолчанию и рассчитано только на доверенную single-operator машину.

## Frontend - localStorage / sessionStorage

| Ключ | Хранилище | Назначение |
|---|---|---|
| `currentTab` | sessionStorage | Активная вкладка UI |
| `selectItem` | localStorage | Выбранные параметры услуги |
| (и др. настройки пользователя) | localStorage | См. `App.js` |

## Возможная миграция на СУБД

Рекомендуемая схема PostgreSQL - см. ER-диаграмму в [schemas.md](./schemas.md#таблицы-условная-бд).
