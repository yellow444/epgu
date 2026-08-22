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

Нестрогий разбор не означает открытую дверь. Кого пускаем и как часто -
в ``inbound_guard``; отказы в журнал не пишутся, чтобы поток мусора не вытеснял
настоящие сообщения.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

import inbound_guard
import inbound_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("inbound")

MNEMONIC = os.getenv("IS_MNEMONIC", "")
PUBLIC_URL = os.getenv("INBOUND_PUBLIC_URL", "")


def _identity_is_public() -> bool:
    """Показывать ли мнемонику и адрес системы всем подряд.

    По умолчанию нет: это внутренние реквизиты регистрации, посторонним они
    ничего не дают, а нам подсказывают, кого сканировать.
    """
    return os.getenv("INBOUND_PUBLIC_IDENTITY", "0").strip().lower() in {"1", "true", "да"}

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
    identity: Dict[str, Any] = {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "endpoints": {
            "system": "/is",
            "push": "/push",
            "health": "/health",
        },
    }
    if _identity_is_public():
        identity["system"] = "ЕПГУ API client"
        identity["mnemonic"] = MNEMONIC
        identity["public_url"] = PUBLIC_URL
    return identity


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


def _sender(request: Request) -> str:
    peer = request.client.host if request.client else ""
    return inbound_guard.client_ip(peer, request.headers.get("x-forwarded-for", ""))


def _admit(request: Request) -> Tuple[Optional[JSONResponse], str]:
    """Пускать ли запрос до чтения тела.

    Возвращает готовый отказ или ничего и адрес отправителя. Отказы не
    журналируются: иначе поток отказов сам вытеснит настоящие сообщения,
    ради чего его обычно и устраивают.
    """
    ip = _sender(request)

    if not inbound_guard.net_allowed(ip):
        count = inbound_guard.note_rejected("сеть не разрешена")
        logger.warning("Отклонён запрос с %s: сеть не разрешена (всего %d)", ip, count)
        return JSONResponse(status_code=403, content={"code": "FORBIDDEN"}), ip

    if not inbound_guard.token_matches(request.headers.get(inbound_guard.TOKEN_HEADER, "")):
        count = inbound_guard.note_rejected("неверный секрет")
        logger.warning("Отклонён запрос с %s: неверный секрет (всего %d)", ip, count)
        return JSONResponse(status_code=401, content={"code": "UNAUTHORIZED"}), ip

    if not inbound_guard.rate_ok(ip):
        count = inbound_guard.note_rejected("слишком часто")
        logger.warning("Отклонён запрос с %s: слишком часто (всего %d)", ip, count)
        return (
            JSONResponse(
                status_code=429,
                content={"code": "TOO_MANY_REQUESTS"},
                headers={"Retry-After": "60"},
            ),
            ip,
        )

    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > inbound_store.max_body_bytes():
        inbound_guard.note_rejected("тело больше лимита")
        logger.warning("Отклонён запрос с %s: тело %s байт", ip, declared)
        # Отказываем до чтения: качать мегабайты, чтобы их выбросить, незачем.
        return (
            JSONResponse(
                status_code=413,
                content={
                    "code": "PAYLOAD_TOO_LARGE",
                    "limit": inbound_store.max_body_bytes(),
                },
            ),
            ip,
        )

    return None, ip


def _record(request: Request, body: bytes, truncated: bool, client: str) -> Dict[str, Any]:
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


@app.on_event("startup")
async def announce_protection() -> None:
    """Сказать в лог, чем закрыт порт. Без этого легко опубликовать адрес
    и не заметить, что не включена ни одна проверка отправителя."""
    state = inbound_guard.describe()
    logger.info(
        "Приёмник запущен. Сети: %s. Секрет: %s. Частота: %s в минуту, всплеск %s.",
        ", ".join(state["allow_nets"]) or "любые",
        "требуется" if state["token_required"] else "не требуется",
        state["rate_per_minute"],
        state["rate_burst"],
    )
    if not state["allow_nets"] and not state["token_required"]:
        logger.warning(
            "Отправитель ничем не ограничен. До публикации адреса задайте "
            "INBOUND_ALLOW_NETS или INBOUND_TOKEN."
        )
    if state["token_required"] and not inbound_guard.token_is_transferable():
        logger.error(
            "INBOUND_TOKEN содержит символы вне латиницы: такой заголовок "
            "отправитель передать не сможет. Возьмите строку из openssl rand -hex 32."
        )


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


@app.get("/{path:path}")
@app.head("/{path:path}")
async def probe_any(path: str) -> JSONResponse:
    """Проба любого адреса, который указали в карточке ИС.

    Путь для push в техпортале задаём мы сами, и он не обязан называться
    /push: встречается и /message, и что-нибудь своё. Приём и так работает по
    любому пути, а вот проверка доступности ходит методом GET, и 405 в ответ
    выглядит как неработающий адрес. Поэтому отвечаем ровно то же, что и на
    /push, но говорим, какой путь спросили.
    """
    return JSONResponse(
        content={
            "code": "OK",
            "message": "Адрес принимает push сообщения методом POST",
            "path": "/" + path.lstrip("/"),
        }
    )


@app.api_route("/push", methods=["POST", "PUT", "PATCH"])
async def push_receive(request: Request) -> JSONResponse:
    """Приём push сообщения. Своим - всегда 200, чтобы не копились повторы."""
    denied, client = _admit(request)
    if denied is not None:
        return denied
    body, truncated = await _read_capped_body(request)
    record = _record(request, body, truncated, client)
    return JSONResponse(content={"code": "OK", "message_id": record["id"]})


@app.api_route("/{path:path}", methods=["POST", "PUT", "PATCH"])
async def catch_all(request: Request, path: str) -> JSONResponse:
    """Любой другой входящий вызов тоже сохраняем: путь может отличаться."""
    denied, client = _admit(request)
    if denied is not None:
        return denied
    body, truncated = await _read_capped_body(request)
    record = _record(request, body, truncated, client)
    return JSONResponse(content={"code": "OK", "message_id": record["id"]})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("INBOUND_SERVER_PORT", "5001")),
    )
