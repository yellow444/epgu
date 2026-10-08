"""Заявления ФССП по типизированной форме: предпросмотр и отправка.

Услуги 60010153 (наличие исполнительного производства) и 10000000352 (ход
исполнительного производства) собираются построителем
``epgu.services.fssp``: форма передаёт поля, сервер проверяет их, собирает
``req.xml`` и ``piev_epgu.xml``, сверяет бизнес-запрос с официальной XSD и
только после этого резервирует номер заявления и отправляет архив. Шаблонов с
демонстрационными данными в этом пути нет.

Роутер не знает о маркере ЕСИА и транспорте: приложение передаёт свои
функции при подключении, поэтому один модуль работает и в публичном ядре, и в
сборке с дополнениями.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Literal, Optional, Tuple

import httpx
from epgu import validate_xml
from epgu.archive import OrderArchive
from epgu.errors import ValidationError
from epgu.services import fssp
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

SCHEMA_FILENAME = "piev_epgu.xsd"
# Номер заявления ЕПГУ появляется только при резервировании. В предпросмотре
# вместо него стоит единица, при отправке подставляется настоящий.
PREVIEW_ORDER_ID = 1


class PersonPayload(BaseModel):
    model_config = {"extra": "forbid"}

    fullName: str = Field(..., max_length=1000)
    gender: Literal["1", "2"]
    birthDate: date
    snils: str = Field(..., max_length=20)


class OrganizationPayload(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(..., max_length=1000)
    address: str = Field(..., max_length=200)
    inn: str = Field(..., max_length=20)
    ogrn: str = Field(..., max_length=20)


class RepresentativePayload(BaseModel):
    model_config = {"extra": "forbid"}

    document: Literal["01", "02", "03", "04", "06", "08"]
    issuedBy: str = Field(..., max_length=1000)
    number: str = Field(..., max_length=25)
    issuedOn: date
    principal: PersonPayload


class FsspPayload(BaseModel):
    """Поля формы. Заявитель - физлицо; от кого подаётся - representation."""

    model_config = {"extra": "forbid"}

    serviceCode: Literal["60010153", "10000000352"]
    region: str = Field(..., pattern="^[0-9]{2,11}$", description="ОКАТО региона (2-11 цифр)")
    side: Literal["1", "2"]
    representation: Literal["organization", "person", "self"] = "organization"
    applicant: PersonPayload
    organization: Optional[OrganizationPayload] = None
    representative: Optional[RepresentativePayload] = None
    includeClosed: bool = True
    caseNumber: str = Field("", max_length=40)


def _person(payload: PersonPayload) -> fssp.Person:
    return fssp.Person(
        full_name=payload.fullName,
        gender=fssp.Gender(payload.gender),
        birth_date=payload.birthDate,
        snils=payload.snils,
    )


def to_request(payload: FsspPayload) -> fssp.FsspRequest:
    representation: Optional[fssp.Representation] = None
    if payload.representation == "organization":
        if payload.organization is None:
            raise fssp.FsspContractError([("organization", "Укажите реквизиты организации")])
        organization = payload.organization
        representation = fssp.OrganizationRepresentation(
            name=organization.name,
            address=organization.address,
            inn=organization.inn,
            ogrn=organization.ogrn,
        )
    elif payload.representation == "person":
        if payload.representative is None:
            raise fssp.FsspContractError([("representative", "Укажите документ о полномочиях")])
        representative = payload.representative
        representation = fssp.PersonRepresentation(
            document=fssp.PowerDocument(representative.document),
            issued_by=representative.issuedBy,
            number=representative.number,
            issued_on=representative.issuedOn,
            principal=_person(representative.principal),
        )
    return fssp.FsspRequest(
        service_code=payload.serviceCode,
        side=fssp.Side(payload.side),
        applicant=_person(payload.applicant),
        representation=representation,
        include_closed=payload.includeClosed,
        case_number=payload.caseNumber,
    )


def schema_path() -> Path:
    root = os.getenv("XML_ROOT", "").strip()
    folder = Path(root) if root else Path(__file__).resolve().parent / "xml"
    return folder / SCHEMA_FILENAME


def _contract_error(error: fssp.FsspContractError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "message": "Заявление не прошло проверку",
            "errors": [{"field": field, "message": message} for field, message in error.errors],
        },
    )


def build_checked(
    payload: FsspPayload,
    *,
    order_id: int,
    moment: datetime,
    environment: fssp.Environment,
) -> Dict[str, bytes]:
    """Собрать оба файла и проверить бизнес-запрос по официальной XSD."""
    documents = fssp.build_documents(
        to_request(payload), order_id=order_id, moment=moment, environment=environment
    )
    schema = schema_path().read_bytes()
    try:
        validate_xml(documents[fssp.REQUEST_FILENAME], schema)
    except ValidationError as exc:
        # Поля уже проверены построителем; сюда попадает только расхождение
        # со схемой, которое нельзя отправлять.
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Бизнес-запрос не прошёл проверку по XSD ФССП",
                "errors": [{"field": "piev_epgu.xml", "message": str(exc)}],
            },
        ) from exc
    return documents


def build_archive(documents: Dict[str, bytes]) -> bytes:
    archive = OrderArchive()
    archive.add_file(fssp.TRANSPORT_FILENAME, documents[fssp.TRANSPORT_FILENAME])
    archive.add_file(fssp.REQUEST_FILENAME, documents[fssp.REQUEST_FILENAME])
    return archive.to_bytes()


def fssp_router(
    *,
    services: Callable[[str], Tuple[str, Dict[str, Any]]],
    ensure_available: Callable[[str, Dict[str, Any]], None],
    access_token: Callable[[], Any],
    reserve: Callable[..., Awaitable[int]],
    push_chunked: Callable[..., Awaitable[Tuple[Dict[str, Any], int]]],
    upstream_failure: Callable[[str, httpx.HTTPStatusError], HTTPException],
    client_dependency: Callable[..., Any],
    environment: Callable[[], fssp.Environment],
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> APIRouter:
    router = APIRouter(tags=["fssp"])

    @router.get("/fssp/contracts")
    def fssp_contracts():
        """Что умеет построитель: услуги, коды получателей, обязательные поля."""
        return {
            "environment": environment().value,
            "services": [
                {
                    "serviceCode": contract.service_code,
                    "title": contract.title,
                    "caseNumberRequired": contract.case_number_required,
                    "includeClosedSupported": contract.include_closed_supported,
                }
                for contract in fssp.CONTRACTS.values()
            ],
        }

    @router.post("/fssp/preview")
    def fssp_preview(payload: FsspPayload):
        """Проверить поля и показать оба файла. Ничего не отправляет."""
        code, service_data = services(payload.serviceCode)
        ensure_available(code, service_data)
        try:
            documents = build_checked(
                payload, order_id=PREVIEW_ORDER_ID, moment=now(), environment=environment()
            )
        except fssp.FsspContractError as exc:
            raise _contract_error(exc) from exc
        return JSONResponse(
            content={
                "serviceCode": code,
                "environment": environment().value,
                "orderIdPlaceholder": PREVIEW_ORDER_ID,
                "documents": {name: content.decode("utf-8") for name, content in documents.items()},
            }
        )

    @router.post("/fssp/submit")
    async def fssp_submit(
        payload: FsspPayload,
        client: httpx.AsyncClient = Depends(client_dependency),
    ):
        """Проверить, зарезервировать номер, собрать архив с этим номером и отправить."""
        code, service_data = services(payload.serviceCode)
        ensure_available(code, service_data)
        moment = now()
        try:
            # Сначала проверка: номер заявления не резервируется под заявление,
            # которое всё равно нельзя отправить.
            build_checked(
                payload, order_id=PREVIEW_ORDER_ID, moment=moment, environment=environment()
            )
        except fssp.FsspContractError as exc:
            raise _contract_error(exc) from exc
        session = access_token()
        meta = {
            "region": payload.region,
            "serviceCode": code,
            "targetCode": str(service_data["serviceTargetCode"]),
        }
        try:
            order_id = await reserve(meta, client, session)
            documents = build_checked(
                payload, order_id=order_id, moment=moment, environment=environment()
            )
            archive = build_archive(documents)
            submission = service_data.get("submission") or {}
            archive_name = str(submission.get("archiveNameTemplate") or "{orderId}-archive.zip")
            result, chunks = await push_chunked(
                meta,
                archive,
                order_id,
                client,
                session,
                chunk_size=int(submission.get("chunkSize") or 5_000_000),
                archive_name=archive_name.replace("{orderId}", str(order_id)),
            )
        except fssp.FsspContractError as exc:
            raise _contract_error(exc) from exc
        except httpx.HTTPStatusError as exc:
            raise upstream_failure("fssp submit", exc) from exc
        return {
            **result,
            # Строкой: длинный номер в JavaScript теряет точность.
            "orderId": str(order_id),
            "serviceCode": code,
            "environment": environment().value,
            "archiveSize": len(archive),
            "chunks": chunks,
        }

    return router


def environment_for(host: str) -> fssp.Environment:
    """Тестовый контур ЕПГУ - SVCDEV, остальное - продуктивная среда."""
    return fssp.Environment.SVCDEV if ".test." in (host or "") else fssp.Environment.PROD


__all__ = [
    "FsspPayload",
    "build_archive",
    "build_checked",
    "environment_for",
    "fssp_router",
    "to_request",
]
