# Схемы данных

> Актуализировано: **2026-08-12**. Источник истины по XML/XSD - спецификации отдельных услуг на [портале партнёров](https://partners.gosuslugi.ru/catalog/api_for_gu); локальный снимок и SHA-256 находятся в [api_for_gu](./api_for_gu/README.md), полный каталог - в [SERVICES.md](./SERVICES.md).

## XML / XSD

Файлы в `api-gosuslugi-backend/xml/` относятся к услугам ФССП и не служат универсальной схемой для всех услуг. По `piev_epgu.xsd` построитель `epgu.services.fssp` проверяет заявления `60010153` и `10000000352` перед отправкой. `req.xml` и `piev_epgu.xml` - примеры из спецификации с демонстрационными данными, при отправке они не используются:

| Файл | Назначение |
|---|---|
| `req.xml` | Пример транспортной обёртки из спецификации, не отправляется |
| `piev_epgu.xml` | Пример бизнес-запроса из спецификации, не отправляется |
| `piev_epgu.xsd` | XSD бизнес-запроса ФССП, по ней проверяется каждое заявление |

Backend выбирает `schemaFile` из `submission.documents[]`, безопасно разрешает путь внутри `XML_ROOT` и кеширует скомпилированную схему:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
schema = _load_schema(document_profile["schemaFile"])
schema.assertValid(etree.fromstring(xml_content, parser=parser))
```

Перечисления доступны через `GET /xsd?service=<code>&simple_type_name=<name>`. Endpoint принимает только исполняемый профиль с локальной XSD; отсутствие схемы возвращает `404`, reference-only профиль - `409`.

## Справочник услуг (env `SERVICES`)

`service_profiles.json` - сгенерированный versioned-реестр. `SERVICES` может быть только строгим deep-overlay; добавляемая услуга обязана содержать полный профиль. Ниже - иллюстративный фрагмент справочного профиля, а не готовый полный override:

```json
{
  "10000000396": {
    "serviceCode": "10000000396",
    "title": "Информация об исполнительных производствах для снятия ограничений на выезд",
    "status": "reference",
    "available": false,
    "unavailableReason": "Услуга только для физических лиц (ФЛ, ИГ): заявитель всегда должник, представителя нет.",
    "protocol": "gusmev-order",
    "targetCode": "-10000000396",
    "submission": {
      "mode": "chunked",
      "archiveNameTemplate": "{orderId}-archive.zip",
      "chunkSize": 5000000,
      "documents": [
        {"id": "transport", "outputName": "req.xml", "validation": "well-formed"},
        {"id": "request", "outputName": "piev_epgu.xml", "schemaFile": "piev_epgu.xsd", "validation": "xsd"}
      ]
    },
    "spec": {"source": "https://gu-st.ru/...docx", "sha256": "..."}
  }
}
```

Возвращается клиенту через `GET /services`. Справочный профиль виден в интерфейсе, но не отправляется. Исполняемые профили ФССП вместо `sourceFile` указывают у документов `"generator": "fssp"`: файлы собираются из формы, а общие `/xml`, `/push` и `/push/chunked` для них отвечают `409`.

## Pydantic-модели (backend)

### `APIKeyRequest`

| Поле | Тип | Описание |
|---|---|---|
| api_key | str | GUID API-ключа |

### `OrderRequest`

| Поле | Тип | Default | Описание |
|---|---|---|---|
| region | str | обязательное | Runtime ОКАТО пользователя |
| serviceCode | str | обязательное | Код зарегистрированной услуги |
| targetCode | str | обязательное | Должен совпасть с профилем услуги |

### `GoskeyRequest`

Typed DTO содержит `serviceCode`, runtime `region`, вариант/тип получателя и его идентификаторы, `signExpiration`, описание, реквизиты организации, optional backlink/orderId. Допустимые варианты публикует `GET /goskey/capabilities`; `reference` варианты не генерируются. `POST /goskey/submit` передаёт DTO строкой в multipart-поле `request`, а документы - повторяемым полем `documents`.

## Внутренние структуры

### Сертификат в памяти

| Ключ | Пример |
|---|---|
| thumbprint (id) | `A1B2C3...` |
| SubjectName | `CN="ООО Рога и Копыта", OU="IT", O="Рога"...` |

Парсится функцией `parse_string_to_json` в словарь `{CN, OU, O, SN, ...}`.

### Структура ответа `POST /order/{orderId}`

```json
{
  "message": "Детали запроса успешно получены.",
  "fileDetails": [
    {
      "objectId": "<currentStatusHistoryId>",
      "objectType": "<last segment of file.link>",
      "mnemonic": "piev_epgu.zip",
      "eserviceCode": "<serviceCode из запроса>"
    }
  ],
  "orderDetails": { "orderResponseFiles": [ ... ] }
}
```

## «Таблицы» (условная БД)

БД отсутствует; сущности живут в памяти процесса. Если делать таблицы (например, при переходе на PostgreSQL) - логичная схема:

```mermaid
erDiagram
    ORG ||--o{ API_KEY : owns
    API_KEY ||--o{ TOKEN : issues
    ORG ||--o{ ORDER : submits
    ORDER ||--o{ ORDER_FILE : has
    ORDER ||--|| SERVICE : of

    ORG {
        uuid id PK
        string name
        string ogrn
    }
    API_KEY {
        uuid id PK
        uuid org_id FK
        string guid
        timestamp created_at
    }
    TOKEN {
        uuid id PK
        uuid api_key_id FK
        text jwt
        timestamp issued_at
        timestamp expires_at
    }
    SERVICE {
        string code PK
        string title
        string status
        string submission_mode
        json profile
    }
    ORDER {
        string order_id PK
        uuid org_id FK
        string service_code FK
        string region
        string status
        timestamp updated_at
    }
    ORDER_FILE {
        uuid id PK
        string order_id FK
        string mnemonic
        string object_id
        string object_type
        string eservice_code
    }
```

См. также [data-model.md](./data-model.md).
