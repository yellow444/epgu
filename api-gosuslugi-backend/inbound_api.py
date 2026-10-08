"""Операторские эндпоинты журнала входящих запросов.

Подключаются к основному приложению, которое доступно только с локальной
машины. На публичном приёмнике (``inbound.py``) этих методов нет: наружу
отдавать содержимое входящих запросов нельзя.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

import inbound_store

Accept = Callable[[Mapping[str, Any]], bool]

# Дополнения могут сузить то, что показывает прежний журнал. Например, с
# несколькими организациями запрос на поддомен другой организации виден ей, а
# в общий журнал не попадает. Каждый элемент - фабрика: она вызывается один
# раз на запрос и возвращает проверку записи. Запись видна, если её
# пропускают все проверки.
legacy_record_filters: List[Callable[[], Accept]] = []


def _legacy_accept() -> Optional[Accept]:
    checks = [factory() for factory in list(legacy_record_filters)]
    if not checks:
        return None
    return lambda record: all(check(record) for check in checks)


def check_public_url(url: str) -> Dict[str, Any]:
    """Проверить, что адрес ИС виден из интернета и ведёт к нам.

    Запрос уходит наружу и должен вернуться на наш же приёмник, пройдя
    через обратный прокси. Это единственная проверка, которая ловит
    настоящие грабли: закрытый порт, чужой сертификат, прокси, который
    отвечает своей заглушкой вместо нас.
    """
    import os
    import ssl
    import time
    import urllib.error
    import urllib.request
    from urllib.parse import urlsplit

    public = (url or os.getenv("INBOUND_PUBLIC_URL", "")).strip().rstrip("/")
    if not public:
        raise HTTPException(
            status_code=400,
            detail="Укажите внешний адрес, например https://smev.example.ru",
        )
    parts = urlsplit(public)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise HTTPException(status_code=400, detail="Адрес должен начинаться с https://")

    checks = []
    ours = False
    for path, expect in (("/is", "endpoints"), ("/push", "code")):
        started = time.monotonic()
        item: Dict[str, Any] = {"path": path, "url": public + path}
        try:
            request = urllib.request.Request(public + path, method="GET")
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(4000).decode("utf-8", "replace")
                item["status"] = response.status
                item["body"] = body[:400]
                item["ours"] = expect in body
                ours = ours or item["ours"]
        except urllib.error.HTTPError as err:
            item["status"] = err.code
            item["body"] = err.read(400).decode("utf-8", "replace")
            item["ours"] = False
        except ssl.SSLError as err:
            item["status"] = 0
            item["error"] = "Сертификат не принят: %s" % err.reason
        except Exception as err:
            item["status"] = 0
            item["error"] = "%s: %s" % (type(err).__name__, str(err)[:120])
        item["seconds"] = round(time.monotonic() - started, 2)
        checks.append(item)

    hints = []
    if not ours:
        hints.append(
            "Адрес не привёл к нашему приёмнику. Проверьте, что прокси на внешнем "
            "хосте отправляет /is и /push на порт 58080 этого стенда."
        )
    if parts.scheme == "https" and any(item.get("status") == 0 for item in checks):
        hints.append(
            "Если ошибка про сертификат, проверьте цепочку: техпортал ходит с "
            "обычным доверенным сертификатом, самоподписанный не подойдёт."
        )
    if parts.scheme == "http":
        hints.append("Техпортал ждёт https, обычный http он не примет.")
    if ours:
        hints.append(
            "Адрес отвечает нашим приёмником. Теперь пропишите его в техпортале: "
            "URL системы " + public + "/is, URL push " + public + "/push."
        )
    return {
        "url": public,
        "reachable": ours,
        "checks": checks,
        "hints": hints,
        "trusted_proxies": os.getenv("INBOUND_TRUSTED_PROXIES", ""),
        "allow_nets": os.getenv("INBOUND_ALLOW_NETS", ""),
        "token_set": bool(os.getenv("INBOUND_TOKEN", "")),
    }


def inbound_router() -> APIRouter:
    router = APIRouter(prefix="/inbound", tags=["inbound"])

    @router.get("/messages")
    async def messages_route(limit: int = Query(50, ge=1, le=500)):
        """Последние входящие запросы, свежие сверху."""
        accept = _legacy_accept()
        return JSONResponse(
            content={
                "total": inbound_store.count(accept),
                "journal": str(inbound_store.journal_path()),
                "messages": inbound_store.read_last(limit, accept),
            }
        )

    @router.post("/check-public")
    def check_public_route(url: str = Query("", max_length=300)):
        """Проверить, что адрес ИС виден из интернета и ведёт к нам."""
        return JSONResponse(content=check_public_url(url))

    @router.post("/clear")
    async def clear_route():
        """Очистить журнал. Полезно между прогонами теста.

        Если журнал сужен фильтрами, удаляются только те записи, что он
        показывает: чужие запросы очистка не трогает.
        """
        accept = _legacy_accept()
        if accept is None:
            inbound_store.clear()
        else:
            inbound_store.clear(keep=lambda record: not accept(record))
        return JSONResponse(content={"status": "Ok"})

    return router
