"""Публичный приёмник входящих запросов от ЕПГУ и ЕСИА.

Это отдельное приложение и отдельный процесс. На него смотрит внешний мир,
поэтому здесь нет ни сертификатов, ни маркера доступа, ни методов подачи
заявлений: только приём, запись в журнал и ответ отправителю.

Адреса, которые указываются при регистрации ИС в техпортале:

    URL системы                     https://<хост>/is
    URL для отправки push сообщений https://<хост>/push

Запуск:

    uvicorn inbound:app --host 0.0.0.0 --port 5001

Контракт входящего push в опубликованных спецификациях API ЕПГУ не описан:
там задокументированы только вызовы, которые ИС делает сама. Поэтому приёмник
намеренно нестрогий. Он принимает любой метод записи, любой content-type,
сохраняет тело как есть и отвечает 200. Разбор появится, когда станет известен
реальный формат: его будет видно в журнале.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

import inbound_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("inbound")

MNEMONIC = os.getenv("IS_MNEMONIC", "")
PUBLIC_URL = os.getenv("INBOUND_PUBLIC_URL", "")

app = FastAPI(
    title="Приёмник входящих запросов ЕПГУ",
    description=(
        "Публичная точка входа информационной системы: URL системы и URL для "
        "push сообщений. Принимает и журналирует входящие запросы."
    ),
    version="1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _identity() -> Dict[str, Any]:
    return {
        "status": "ok",
        "system": "ЕПГУ API client",
        "mnemonic": MNEMONIC,
        "public_url": PUBLIC_URL,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "endpoints": {
            "system": "/is",
            "push": "/push",
            "health": "/health",
        },
    }


async def _read_capped_body(request: Request) -> tuple[bytes, bool]:
    """Прочитать тело с ограничением, не падая на слишком больших запросах."""
    limit = inbound_store.max_body_bytes()
    chunks = bytearray()
    truncated = False
    async for chunk in request.stream():
        if len(chunks) >= limit:
            truncated = True
            continue
        room = limit - len(chunks)
        chunks.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True
    return bytes(chunks), truncated


def _record(request: Request, body: bytes, truncated: bool) -> Dict[str, Any]:
    forwarded = request.headers.get("x-forwarded-for", "")
    client = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else None
    )
    record = inbound_store.build_record(
        method=request.method,
        path=request.url.path,
        query=str(request.url.query or ""),
        client=client,
        headers=request.headers,
        body=body,
        truncated=truncated,
        mnemonic=MNEMONIC,
    )
    try:
        inbound_store.append(record)
    except Exception:
        # Отправителю важен ответ, а не наш диск. Ошибку записи только логируем.
        logger.exception("Не удалось записать входящий запрос в журнал")
    logger.info(
        "Входящий запрос: %s %s, %s байт, отправитель %s",
        record["method"],
        record["path"],
        record["size"],
        record["client"],
    )
    return record


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(content={"status": "Ok"})


@app.get("/")
@app.get("/is")
async def system_url() -> JSONResponse:
    """URL системы: страница, по которой проверяют, что ИС жива."""
    return JSONResponse(content=_identity())


@app.get("/push")
async def push_probe() -> JSONResponse:
    """Проверка доступности push-адреса без отправки данных."""
    return JSONResponse(
        content={
            "code": "OK",
            "message": "Адрес принимает push сообщения методом POST",
        }
    )


@app.head("/is")
@app.head("/push")
async def head_probe() -> PlainTextResponse:
    return PlainTextResponse(content="", status_code=200)


@app.api_route("/push", methods=["POST", "PUT", "PATCH"])
async def push_receive(request: Request) -> JSONResponse:
    """Приём push сообщения. Всегда 200, чтобы отправитель не копил повторы."""
    body, truncated = await _read_capped_body(request)
    record = _record(request, body, truncated)
    return JSONResponse(content={"code": "OK", "message_id": record["id"]})


@app.api_route("/{path:path}", methods=["POST", "PUT", "PATCH"])
async def catch_all(request: Request, path: str) -> JSONResponse:
    """Любой другой входящий вызов тоже сохраняем: путь может отличаться."""
    body, truncated = await _read_capped_body(request)
    record = _record(request, body, truncated)
    return JSONResponse(content={"code": "OK", "message_id": record["id"]})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("INBOUND_SERVER_PORT", "5001")),
    )
