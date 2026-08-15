"""Операторские эндпоинты журнала входящих запросов.

Подключаются к основному приложению, которое доступно только с локальной
машины. На публичном приёмнике (``inbound.py``) этих методов нет: наружу
отдавать содержимое входящих запросов нельзя.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

import inbound_store


def inbound_router() -> APIRouter:
    router = APIRouter(prefix="/inbound", tags=["inbound"])

    @router.get("/messages")
    async def messages_route(limit: int = Query(50, ge=1, le=500)):
        """Последние входящие запросы, свежие сверху."""
        return JSONResponse(
            content={
                "total": inbound_store.count(),
                "journal": str(inbound_store.journal_path()),
                "messages": inbound_store.read_last(limit),
            }
        )

    @router.post("/clear")
    async def clear_route():
        """Очистить журнал. Полезно между прогонами теста."""
        inbound_store.clear()
        return JSONResponse(content={"status": "Ok"})

    return router
