# Диаграммы последовательностей

## 1. Авторизация — получение токена ЕСИА

```mermaid
sequenceDiagram
    participant UI as React UI
    participant API as FastAPI
    participant CSP as КриптоПро (pycades)
    participant TSA as TSA
    participant ESIA as ЕСИА

    UI->>API: POST /accessTkn_esia {api_key}
    API->>CSP: Signer = CERTIFICATES[CURRENT_CERT_ID]
    API->>CSP: SignCades(api_key, CADES_BES, detached=1)
    CSP->>TSA: timestamp (опц.)
    TSA-->>CSP: tsp token
    CSP-->>API: detached signature (base64)
    API->>API: urlsafe_b64encode
    API->>ESIA: GET /esia-rs/.../tkn?signature=...
    ESIA-->>API: { accessTkn: JWT, ... }
    API->>API: ACCESS_TKN_ESIA = accessTkn
    API-->>UI: { accessTkn, expires_in }
    UI->>UI: jwtDecode → отобразить exp
```

## 2. Подача заявления (chunked)

```mermaid
sequenceDiagram
    participant UI
    participant API
    participant EPGU

    UI->>API: POST /push/chunked
(meta, orderId, chunks=1, chunk=1, files)
    API->>API: json.loads(meta)
    API->>API: zipfile.ZipFile — собрать piev_epgu.zip
    API->>API: validate piev_epgu.xml по XSD
    API->>EPGU: POST /api/gusmev/push/chunked
(Authorization: Bearer JWT)
    EPGU-->>API: { orderId, ... }
    API-->>UI: { orderId }
```

## 3. Опрос статуса и получение ответа

```mermaid
sequenceDiagram
    participant UI
    participant API
    participant EPGU

    loop опрос
        UI->>API: POST /order/{orderId}
        API->>EPGU: POST /api/gusmev/order/{orderId}
        EPGU-->>API: { order: "...json..." }
        API->>API: safe_parse_order → orderResponseFiles
        alt есть файлы
            API-->>UI: fileDetails + orderDetails
        else нет файлов
            API-->>UI: orderDetails (без fileDetails)
        end
    end
    UI->>API: POST /download_file/{objectId}/{objectType}
    API->>EPGU: GET /api/gusmev/files/download/...
    EPGU-->>API: zip (stream)
    API-->>UI: StreamingResponse (application/zip)
```

## 4. Отмена заявления

```mermaid
sequenceDiagram
    UI->>API: POST /order/{orderId}/cancel
    API->>EPGU: POST /api/gusmev/order/{orderId}/cancel
    EPGU-->>API: orderDetails
    API-->>UI: { message, orderDetails }
```

## 5. Старт приложения (backend)

```mermaid
sequenceDiagram
    participant Docker
    participant App as FastAPI
    participant CSP

    Docker->>App: uvicorn app:app
    App->>App: @on_event("startup") → load_certificates
    App->>CSP: Store.Open(CONTAINER_STORE, MY_STORE)
    CSP-->>App: Certificates (N)
    App->>App: CERTIFICATES = {thumbprint: cert}
    App->>App: CURRENT_CERT_ID = first
    Note over App: если production пуст — debugpy.listen(:5678)
    App-->>Docker: ready
```
