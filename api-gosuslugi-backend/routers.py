"""
Дополнительные FastAPI-роутеры, не входящие в спецификацию API ЕПГУ напрямую,
но необходимые UI и диагностике:

- /version       — расширенный health + информация о текущей среде / spec version
- /environments  — справочник известных сред (test/prod) для UI
- /services/{code} — описание одной услуги

Подключается из app.py: ``app.include_router(diagnostics_router())``.
"""

from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, HTTPException, Path
from fastapi.responses import JSONResponse

from config import (
    ENVIRONMENTS,
    SPEC_SOURCE,
    SPEC_VERSION,
    detect_environment,
    serialize_service,
)


def diagnostics_router(
    *,
    pycades_module: Any,
    services_dict: Dict[str, Dict[str, Any]],
    get_hosts: Callable[[], Dict[str, str]],
    get_runtime: Optional[Callable[[], Dict[str, Any]]] = None,
) -> APIRouter:
    """
    Сформировать роутер с диагностическими эндпоинтами.

    Параметры:
      pycades_module: ссылка на модуль pycades (для версии).
      services_dict:  актуальный (резолвнутый) каталог услуг.
      get_hosts:      колбэк, возвращающий {'esia_host','svcdev_host','tsa_address'}.
                      Колбэк нужен, потому что host'ы могут переопределяться рантайм-настройками.
      get_runtime:    опц. колбэк, возвращающий рантайм-конфигурацию (CORS allowed_origins,
                      срок жизни активного JWT, наличие токена). Используется для диагностики
                      без раскрытия самого токена.
    """
    router = APIRouter()

    @router.get("/version")
    async def version_route():
        """Расширенная диагностика: pycades, среда, host'ы, число услуг, версия спецификации, рантайм."""
        hosts = get_hosts()
        env_name = detect_environment(
            hosts.get("esia_host", ""), hosts.get("svcdev_host", "")
        )
        try:
            pycades_version = pycades_module.About().Version
            module_version = pycades_module.ModuleVersion()
        except Exception:  # pragma: no cover — для случаев когда CSP недоступен
            pycades_version = None
            module_version = None
        body: Dict[str, Any] = {
            "pycades": {
                "Version": pycades_version,
                "ModuleVersion": module_version,
            },
            "environment": env_name,
            "hosts": hosts,
            "services_count": len(services_dict),
            "spec_version": SPEC_VERSION,
            "spec_source": SPEC_SOURCE,
        }
        if get_runtime is not None:
            body["runtime"] = get_runtime()
        return JSONResponse(content=body, status_code=200)

    @router.get("/environments")
    async def environments_route():
        """Справочник известных сред (test/prod) ЕСИА/ЕПГУ."""
        return JSONResponse(content=ENVIRONMENTS, status_code=200)

    @router.get("/services/{code}")
    async def get_service(code: str = Path(..., description="Код услуги")):
        """Описание одной услуги по коду (404 — если не зарегистрирована)."""
        if code not in services_dict:
            raise HTTPException(
                status_code=404,
                detail=f"Услуга '{code}' не зарегистрирована",
            )
        return JSONResponse(content=serialize_service(code, services_dict[code]))

    return router
