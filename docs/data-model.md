# Модель данных

Проект не использует СУБД — данные хранятся **в памяти процесса бэкенда** и **в браузере** (IndexedDB / storage).

## Backend — in-memory state

| Структура | Тип | Описание | Время жизни |
|---|---|---|---|
| `CERTIFICATES` | `dict[str, pycades.Certificate]` | thumbprint → объект сертификата | до рестарта |
| `CURRENT_CERT_ID` | `str \| None` | активный сертификат | до рестарта |
| `ACCESS_TKN_ESIA` | `str` | JWT от ЕСИА | до рестарта / нового вызова |
| `services_dict` | `dict` | справочник услуг | весь запуск |
| `schema` | `lxml.XMLSchema` | скомпилированный XSD | весь запуск |

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
| description | str | Название услуги |
| req_file | str | Имя XML запроса |
| piev_epgu_file | str | Имя XML заявления |
| region | str | ОКТМО (опц.) |
| targetCode | str | Код цели (опц.) |
| eServiceCode | str | Код сервиса (опц.) |
| serviceTargetCode | str | Код цели сервиса (опц.) |

### Заявление (ответ `/order/{orderId}`)

| Поле | Тип | Источник |
|---|---|---|
| orderId | str | параметр пути |
| currentStatusHistoryId | int | `orderDetails.order.currentStatusHistoryId` |
| orderResponseFiles[] | array | список файлов-ответов |
| fileDetails[] | array | отфильтровано по `fileName == "piev_epgu.zip"` |

### Файл-ответ (`fileDetails[]`)

| Поле | Описание |
|---|---|
| objectId | `currentStatusHistoryId` |
| objectType | последний сегмент `file.link` |
| mnemonic | `file.fileName` |
| eserviceCode | `serviceCode` из запроса |

## Frontend — IndexedDB

База `files-db`, object store `files` (keyPath = `name`):

| Поле | Описание |
|---|---|
| name | имя файла (ключ) |
| content | dataURL / Blob |

Используется для сохранения загруженных пользователем XML и приложений между перезагрузками.

## Frontend — localStorage / sessionStorage

| Ключ | Хранилище | Назначение |
|---|---|---|
| `currentTab` | sessionStorage | Активная вкладка UI |
| `selectItem` | localStorage | Выбранные параметры услуги |
| (и др. настройки пользователя) | localStorage | См. `App.js` |

## Возможная миграция на СУБД

Рекомендуемая схема PostgreSQL — см. ER-диаграмму в [schemas.md](./schemas.md#таблицы-условная-бд).
