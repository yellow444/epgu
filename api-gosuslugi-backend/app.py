import base64
import io
import json
import logging
import os
import re
import tempfile
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import quote, urlsplit

import httpx
from dotenv import find_dotenv, load_dotenv
from epgu.services.goskey import (
    CAPABILITIES as GOSKEY_CAPABILITIES,
)
from epgu.services.goskey import (
    ForeignLegalRecipient,
    GoskeyAttribute,
    GoskeyContractError,
    IndividualRecipient,
    IndividualSignRequest,
    LegalEntitySignRequest,
    RussianLegalRecipient,
    SigningVariant,
    TreasurySignRequest,
    UnsupportedGoskeyContractError,
    build_signed_archive,
    capability_for_service,
    select_transport,
    validate_submission_window,
)
from epgu.services.goskey import (
    TransportMode as GoskeyTransportMode,
)
from epgu.signature import CallableSigner
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi import Path as ApiPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from lxml import etree
from pydantic import BaseModel, Field

from config import (
    SPEC_SOURCE,
    SPEC_VERSION,
    SUBMISSION_MODE_ADAPTIVE,
    SUBMISSION_MODE_CHUNKED,
    SUBMISSION_MODE_PUSH,
    ServiceConfigError,
    load_services,
    serialize_service,
    validate_service_catalog,
)
from routers import diagnostics_router
from inbound_api import inbound_router
from setup_api import setup_router

try:
    import pycades
except ModuleNotFoundError:  # Core/catalogue tests do not require proprietary CSP bindings.
    pycades = None

# Загрузка переменных окружения
load_dotenv(find_dotenv())
production = os.getenv('production')
debug_enabled = os.getenv("DEBUG", "").strip().lower() in {"1", "true", "yes"}
if debug_enabled:
    import debugpy
    debugpy.listen(('0.0.0.0', 5678))
#    debugpy.wait_for_client()
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=log_level,
)
logger = logging.getLogger(__name__)
# httpx печатает полный URL каждого запроса на уровне INFO, а в нём едут API-Key
# (сегмент пути ext-app) и подпись. Код приложения специально не пускает этот
# материал в логи, поэтому чужие логгеры приглушаем до предупреждений: иначе
# ключ попадёт в docker compose logs при первом же обращении к ЕСИА.
for _third_party_logger in ("httpx", "httpcore"):
    logging.getLogger(_third_party_logger).setLevel(logging.WARNING)
logger.info(f"log_level:{log_level}")
logger.info(f"production:{production}")
# Глобальные конфигурационные переменные
API_KEY_DEFAULT = os.getenv('apikey', '')
KEY_PIN = os.getenv('KeyPin', '')
TSA_ADDRESS = os.getenv('TSAAddress', 'http://www.cryptopro.ru/tsp/tsp.srf')
ESIA_HOST = os.getenv('esia_host', 'https://esia-portal1.test.gosuslugi.ru')
SVCDEV_HOST = os.getenv('svcdev_host', 'https://svcdev-gostapi.test.gosuslugi.ru')
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) Ubuntu/12.04 Chromium/18.0.1025.168 Chrome/18.0.1025.168 Safari/535.19'
_local_xml_root = Path(__file__).resolve().with_name("xml")
XML_ROOT = Path(
    os.getenv("XML_ROOT")
    or (_local_xml_root if _local_xml_root.is_dir() else Path("/xml"))
).resolve()
# Глобальное состояние
CERTIFICATES = {}
CURRENT_CERT_ID = None
ACCESS_TKN_ESIA = ''
# Срок действия текущего JWT (unix timestamp). 0 - неизвестен.
ACCESS_TKN_EXP = 0
# Monotonic process-local authorization epoch.  Every token refresh, logout or
# certificate change advances it so an in-flight request cannot publish stale
# authorization state or continue a multi-request upload under another session.
SESSION_GENERATION = 0

# Uploads are materialized for ZIP/signing, so bound input before allocating an
# unbounded ``bytes`` object. The 50 MB aggregate limit leaves headroom for
# CAdES/base64 and ZIP copies inside the 512 MB signing runtime. The direct API
# separately enforces its 50 MB resulting-archive limit.
UPLOAD_READ_CHUNK_BYTES = 1_048_576
MAX_UPLOAD_FILE_BYTES = 50_000_000
MAX_UPLOAD_TOTAL_BYTES = 50_000_000
MAX_DOWNLOAD_BYTES = 100_000_000
DOWNLOAD_SPOOL_MEMORY_BYTES = 8_388_608
CHUNK_UPLOAD_DEADLINE_SECONDS = 300.0
TOKEN_EXPIRY_LEEWAY_SECONDS = 30


@dataclass(frozen=True)
class SessionSnapshot:
    """Bearer and authorization epoch captured for one upstream operation."""

    bearer: str
    generation: int


def _invalidate_access_token() -> int:
    """Revoke the process-local bearer and advance the authorization epoch."""
    global ACCESS_TKN_ESIA, ACCESS_TKN_EXP, SESSION_GENERATION
    ACCESS_TKN_ESIA = ""
    ACCESS_TKN_EXP = 0
    SESSION_GENERATION += 1
    return SESSION_GENERATION


def _require_access_token() -> SessionSnapshot:
    """Return a usable bearer snapshot or reject before an upstream side effect."""
    token = ACCESS_TKN_ESIA.strip()
    if not token:
        raise HTTPException(status_code=401, detail="Маркер доступа ЕСИА отсутствует")
    if ACCESS_TKN_EXP <= int(time.time()) + TOKEN_EXPIRY_LEEWAY_SECONDS:
        raise HTTPException(status_code=401, detail="Маркер доступа ЕСИА истёк или скоро истечёт")
    return SessionSnapshot(token, SESSION_GENERATION)


def _ensure_session_current(snapshot: SessionSnapshot) -> None:
    """Fail when logout, refresh or certificate selection changed the session."""
    if (
        snapshot.generation != SESSION_GENERATION
        or snapshot.bearer != ACCESS_TKN_ESIA
    ):
        raise HTTPException(
            status_code=409,
            detail="Сессия оператора изменилась; повторите операцию",
        )
    if ACCESS_TKN_EXP <= int(time.time()) + TOKEN_EXPIRY_LEEWAY_SECONDS:
        raise HTTPException(status_code=401, detail="Маркер доступа ЕСИА истёк или скоро истечёт")


def _upstream_http_failure(operation: str, error: httpx.HTTPStatusError) -> HTTPException:
    """Map an upstream HTTP failure without reflecting URLs, tokens or bodies."""
    status = error.response.status_code
    logger.warning("%s: upstream HTTP %s", operation, status)
    return HTTPException(
        status_code=status,
        detail="Внешний сервис вернул HTTP {}".format(status),
    )


def _internal_failure(operation: str, error: Exception) -> HTTPException:
    """Return an opaque internal error and log only its non-sensitive type."""
    logger.error("%s failed: %s", operation, type(error).__name__)
    return HTTPException(status_code=500, detail="Внутренняя ошибка обработки запроса")


def _positive_decimal_identifier(value: Any, field: str) -> str:
    """Validate an upstream identifier and serialize it without JS precision loss."""
    if isinstance(value, bool):
        valid = False
    elif isinstance(value, int):
        valid = value > 0
    elif isinstance(value, str):
        valid = bool(re.fullmatch(r"[1-9][0-9]*", value))
    else:
        valid = False
    if not valid:
        raise HTTPException(
            status_code=502,
            detail="ЕПГУ вернул некорректный {}".format(field),
        )
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="ЕПГУ вернул некорректный {}".format(field),
        ) from exc
    if parsed <= 0:
        raise HTTPException(
            status_code=502,
            detail="ЕПГУ вернул некорректный {}".format(field),
        )
    return str(parsed)


def _normalize_identifier_fields(payload: Any, fields: set[str]) -> Any:
    """Copy a JSON value while normalizing only explicitly known identifier keys."""
    if isinstance(payload, dict):
        return {
            key: (
                _positive_decimal_identifier(value, key)
                if key in fields
                else _normalize_identifier_fields(value, fields)
            )
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_normalize_identifier_fields(item, fields) for item in payload]
    return payload


def _decode_jwt_exp(jwt: str) -> int:
    """Извлечь exp (unix ts) из JWT без верификации подписи.
    Возвращает 0, если поле отсутствует или JWT битый.
    Подпись JWT проверяется на стороне ЕСИА; здесь нужен только срок жизни."""
    try:
        payload = jwt.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return int(data.get("exp", 0))
    except Exception:
        return 0

try:
    services_dict = load_services(os.environ.get("SERVICES"))
    validate_service_catalog(services_dict, xml_root=XML_ROOT)
except ServiceConfigError as exc:
    logger.critical("Некорректный реестр услуг: %s", exc)
    raise RuntimeError("Некорректный реестр услуг: {}".format(exc)) from exc

# Инициализация FastAPI


@asynccontextmanager
async def lifespan(_application: FastAPI):
    """Load optional CSP state without preventing catalogue-only operation."""
    try:
        load_certificates()
    except Exception as exc:
        logger.warning("CryptoPro certificates are unavailable: %s", exc)
    yield

app = FastAPI(
    root_path="/api",
    title="API Госуслуг (ЕПГУ) - backend",
    description=(
        "Реализация Спецификации API ЕПГУ v1.14 (правки v1.12.1 по разделам "
        f"ГОСТ TLS / СМЭВ4). Источник: {SPEC_SOURCE}"
    ),
    version=SPEC_VERSION,
    lifespan=lifespan,
)
# CORS: список доменов через запятую или "*" (см. docs/security.md, .env.example).
_allowed_origins_raw = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:50080,http://127.0.0.1:50080"
).strip()
ALLOWED_ORIGINS = (
    ["*"]
    if _allowed_origins_raw in ("", "*")
    else [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Аутентификация использует Bearer header, не browser cookies. Credentials
    # здесь не нужны и несовместимы с безопасной wildcard-конфигурацией.
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)


def _normalized_origin(value: str) -> str:
    return value.strip().rstrip("/").lower()


_MUTATION_ORIGINS = {
    _normalized_origin(origin)
    for origin in ALLOWED_ORIGINS
    if origin and origin != "*"
}


@app.middleware("http")
async def reject_cross_origin_mutations(request: Request, call_next):
    """Block browser CSRF against process-global token/signing state.

    CLI/SDK clients normally send neither ``Origin`` nor ``Referer`` and remain
    supported. Browser mutations must originate from an explicit allow-list;
    a wildcard CORS setting never authorizes state-changing requests.
    """
    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        browser_origin = origin
        if not browser_origin and referer:
            parsed = urlsplit(referer)
            browser_origin = (
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed.scheme and parsed.netloc
                else "null"
            )
        if browser_origin and _normalized_origin(browser_origin) not in _MUTATION_ORIGINS:
            return JSONResponse(
                status_code=403,
                content={"detail": "Cross-origin state-changing request is forbidden"},
            )
    return await call_next(request)
app.include_router(
    diagnostics_router(
        pycades_module=pycades,
        services_dict=services_dict,
        get_hosts=lambda: {
            "esia_host": ESIA_HOST,
            "svcdev_host": SVCDEV_HOST,
            "tsa_address": TSA_ADDRESS,
        },
        get_runtime=lambda: {
            "allowed_origins": ALLOWED_ORIGINS,
            "access_tkn_exp": ACCESS_TKN_EXP,
            "has_access_tkn": bool(ACCESS_TKN_ESIA),
        },
    )
)
# Журнал входящих запросов от ЕПГУ. Пишет его отдельный публичный приёмник
# (inbound.py), здесь только чтение для оператора.
app.include_router(inbound_router())
# Мастер настройки: почта поддержки и источники сертификатов. Доступен только
# с localhost, наружу эти методы не публикуются.
app.include_router(setup_router())

# Pydantic-модели


class APIKeyRequest(BaseModel):
    api_key: str


class OrderRequest(BaseModel):
    region: str = Field(
        ...,
        pattern="^[0-9]{2,11}$",
        description='Runtime OKATO region code (2-11 digits)',
    )
    serviceCode: str = Field(..., min_length=1, description='Service code')
    targetCode: str = Field(..., min_length=1, description='Target code')


class GoskeyRequest(BaseModel):
    """Typed frontend contract mapped to the official Goskey request models."""

    model_config = {"extra": "forbid"}

    serviceCode: str = Field(..., pattern="^(10000000374|60025907|60079416|60080470)$")
    region: str = Field(
        ...,
        pattern="^[0-9]{2,11}$",
        description="Runtime OKATO code (2-11 digits)",
    )
    variant: Optional[Literal["unep", "ukep"]] = None
    recipientType: Literal["individual", "russian-legal", "foreign-legal"] = "individual"
    snils: Optional[str] = None
    oid: Optional[str] = None
    ogrn: Optional[str] = None
    rafp: Optional[str] = None
    innUser: Optional[str] = None
    signExpiration: datetime
    description: str = Field(..., min_length=1, max_length=250)
    orgName: str = Field(..., min_length=1, max_length=250)
    orgInn: str = Field(..., min_length=1, max_length=250)
    backlink: Optional[str] = Field(None, max_length=250)
    orderId: Optional[int] = Field(None, gt=0)

# Хелперы


def load_certificates() -> List[str]:
    global CERTIFICATES, CURRENT_CERT_ID
    # Certificate choice is an operator authorization decision.  A reload must
    # always revoke the previous choice and must never pick the first store
    # entry implicitly (store ordering is not a stable identity).
    CERTIFICATES = {}
    CURRENT_CERT_ID = None
    _invalidate_access_token()
    if pycades is None:
        raise RuntimeError("pycades недоступен; установите CryptoPro CSP для операций подписи")
    try:
        store = pycades.Store()
        store.Open(
            pycades.CADESCOM_CONTAINER_STORE,
            pycades.CAPICOM_MY_STORE,
            pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
        )
        certs = store.Certificates
        if certs.Count == 0:
            logger.exception("Сертификаты не найдены в хранилище.")
            raise Exception("Сертификаты не найдены.")
        CERTIFICATES = {
            str(cert.Thumbprint): cert
            for cert in [certs.Item(i) for i in range(1, certs.Count + 1)]
        }
        cert_ids = list(CERTIFICATES.keys())
        return cert_ids
    except Exception as e:
        logger.error("Ошибка загрузки сертификатов: %s", type(e).__name__)
        raise


def parse_string_to_json(input_str: str) -> dict:
    result = {}
    key = None
    value = []
    inside_quotes = False
    for part in input_str.split(", "):
        if inside_quotes:
            value.append(part)
            if part.endswith('"'):
                inside_quotes = False
                result[key] = " ".join(value).strip('"')
                key, value = None, []
        else:
            if "=" in part:
                key, val = part.split("=", 1)
                key = key.strip()
                if val.startswith('"') and not val.endswith('"'):
                    inside_quotes = True
                    value = [val]
                else:
                    result[key] = val.strip('"').strip()
            else:
                raise ValueError(f"Некорректный формат части: {part}")
    return result


def get_current_certificate_details() -> dict:
    if CURRENT_CERT_ID is None or CURRENT_CERT_ID not in CERTIFICATES:
        raise Exception("Текущий сертификат не установлен.")
    cert = CERTIFICATES[CURRENT_CERT_ID]
    return parse_string_to_json(cert.SubjectName)


def _certificate_text_attribute(cert: Any, name: str) -> str:
    """Read a public certificate property without exposing provider errors."""
    try:
        value = getattr(cert, name, None)
    except Exception:
        return ""
    if value is None or callable(value):
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _certificate_summary(cert_id: str, cert: Any) -> Dict[str, Any]:
    """Return only public identity/validity fields needed for explicit choice."""
    subject_name = _certificate_text_attribute(cert, "SubjectName")
    try:
        subject = parse_string_to_json(subject_name)
    except (TypeError, ValueError):
        subject = {}
    common_name = str(subject.get("CN") or "")
    organization = str(subject.get("O") or "")
    label = common_name or str(subject.get("SN") or "") or organization or "Unknown"
    return {
        "id": cert_id,
        "subject": label,
        "common_name": common_name,
        "organization": organization,
        "valid_from": _certificate_text_attribute(cert, "ValidFromDate"),
        "valid_to": _certificate_text_attribute(cert, "ValidToDate"),
        "selected": cert_id == CURRENT_CERT_ID,
    }


def _confined_xml_path(relative_name: str) -> Path:
    """Resolve a profile-owned XML path without allowing traversal."""
    relative = PurePosixPath(str(relative_name).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise HTTPException(status_code=500, detail="Небезопасный путь XML-профиля")
    resolved = (XML_ROOT / Path(*relative.parts)).resolve()
    if XML_ROOT not in resolved.parents:
        raise HTTPException(status_code=500, detail="XML-профиль вышел за пределы XML_ROOT")
    return resolved


@lru_cache(maxsize=32)
def _load_schema(schema_file: str) -> etree.XMLSchema:
    path = _confined_xml_path(schema_file)
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    return etree.XMLSchema(etree.parse(str(path), parser=parser))


def validate_xml_content(xml_content: bytes, schema_file: Optional[str] = None) -> bool:
    """Parse XML safely and optionally validate it against its own profile XSD."""
    try:
        secure_parser = etree.XMLParser(
            resolve_entities=False, no_network=True, huge_tree=False,
        )
        xml_doc = etree.fromstring(xml_content, parser=secure_parser)
        if xml_doc.getroottree().docinfo.doctype:
            raise HTTPException(status_code=400, detail="DOCTYPE в XML запрещён")
        if schema_file:
            _load_schema(schema_file).assertValid(xml_doc)
        return True
    except HTTPException:
        raise
    except Exception as e:
        logger.info("XML validation rejected input: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="XML не прошёл безопасную синтаксическую/XSD-проверку") from e


def _sign_cades_detached(content: bytes) -> bytes:
    """Return a detached CAdES-BES signature as DER bytes via CryptoPro."""
    global TSA_ADDRESS, CURRENT_CERT_ID, KEY_PIN
    if pycades is None:
        raise HTTPException(status_code=503, detail="pycades/CryptoPro CSP недоступен")
    if CURRENT_CERT_ID not in CERTIFICATES:
        raise HTTPException(
            status_code=409,
            detail="Сертификат подписи не выбран",
        )
    cert = CERTIFICATES[CURRENT_CERT_ID]
    signer = pycades.Signer()
    signer.Certificate = cert
    signer.CheckCertificate = True
    signer.TSAAddress = TSA_ADDRESS
    signer.KeyPin = KEY_PIN
    signedData = pycades.SignedData()
    signedData.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
    base64_message = base64.b64encode(content)
    signedData.Content = base64_message.decode("utf-8")
    bDetached = int(1)
    signature = signedData.SignCades(
        signer, pycades.CADESCOM_CADES_BES, bDetached)
    signature = signature.replace("\r\n", "")
    signature += "=" * ((4 - len(signature) % 4) % 4)
    return base64.b64decode(signature)


def signkey(api_key: str) -> str:
    """Sign an organization API key and encode it for the ESIA URL parameter."""
    signature = _sign_cades_detached(api_key.encode("utf-8"))
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

# Зависимость для асинхронного HTTP клиента


async def get_async_client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        connect=float(os.getenv("UPSTREAM_CONNECT_TIMEOUT", "15")),
        read=float(os.getenv("UPSTREAM_READ_TIMEOUT", "300")),
        write=float(os.getenv("UPSTREAM_WRITE_TIMEOUT", "300")),
        pool=float(os.getenv("UPSTREAM_POOL_TIMEOUT", "30")),
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        yield client


async def _read_upload_limited(
    upload: UploadFile,
    *,
    total_bytes: int,
) -> Tuple[bytes, int]:
    """Read one spooled upload with per-file and per-request hard limits."""
    buffer = io.BytesIO()
    file_bytes = 0
    try:
        while True:
            # Read at most one byte beyond either remaining allowance so an
            # oversized body is rejected without loading the rest into memory.
            read_size = min(
                UPLOAD_READ_CHUNK_BYTES,
                MAX_UPLOAD_FILE_BYTES - file_bytes + 1,
                MAX_UPLOAD_TOTAL_BYTES - total_bytes + 1,
            )
            chunk = await upload.read(max(1, read_size))
            if not chunk:
                break
            file_bytes += len(chunk)
            total_bytes += len(chunk)
            if file_bytes > MAX_UPLOAD_FILE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Файл {!r} больше допустимых {} байт".format(
                        upload.filename or "",
                        f"{MAX_UPLOAD_FILE_BYTES:,}".replace(",", " "),
                    ),
                )
            if total_bytes > MAX_UPLOAD_TOTAL_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Суммарный размер файлов больше допустимых {} байт".format(
                        f"{MAX_UPLOAD_TOTAL_BYTES:,}".replace(",", " ")
                    ),
                )
            buffer.write(chunk)
    finally:
        await upload.seek(0)
    return buffer.getvalue(), total_bytes


def _reject_generated_submission(submission: Dict[str, Any]) -> None:
    """Keep generated, typed contracts out of the generic upload endpoints."""
    if any(document.get("generator") == "goskey" for document in submission["documents"]):
        raise HTTPException(
            status_code=409,
            detail="Профиль Госключа должен отправляться только через /goskey/submit",
        )


def _remaining_chunk_timeout(started_at: float) -> float:
    remaining = CHUNK_UPLOAD_DEADLINE_SECONDS - (time.monotonic() - started_at)
    if remaining <= 0:
        raise HTTPException(status_code=504, detail="Отправка частей превысила лимит 5 минут")
    return remaining


async def _post_chunk_with_deadline(
    client: httpx.AsyncClient,
    url: str,
    *,
    started_at: float,
    files: Dict[str, Tuple[Optional[str], Any, Optional[str]]],
    headers: Dict[str, str],
) -> httpx.Response:
    """Send one chunk without allowing all requests together to exceed 5 minutes."""
    remaining = _remaining_chunk_timeout(started_at)
    try:
        response = await client.post(
            url,
            files=files,
            headers=headers,
            timeout=remaining,
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Отправка частей превысила лимит 5 минут",
        ) from exc
    _remaining_chunk_timeout(started_at)
    return response


def _get_service_data(service_code: str) -> Tuple[str, Dict[str, Any]]:
    """Вернуть код и описание услуги из локального каталога."""
    normalized = (service_code or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="В meta должен быть указан serviceCode.")
    service_data = services_dict.get(normalized)
    if service_data is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Услуга '{normalized}' не зарегистрирована. "
                f"Доступные коды: {sorted(services_dict.keys())}"
            ),
        )
    return normalized, service_data


def _ensure_service_available(service_code: str, service_data: Dict[str, Any]) -> None:
    """Reject a reference-only profile before any external side effect."""
    if not service_data.get("available") or service_data.get("status") != "verified":
        raise HTTPException(
            status_code=409,
            detail=(
                "Услуга {} доступна только для справки: {}".format(
                    service_code,
                    service_data.get("unavailableReason") or "профиль не верифицирован",
                )
            ),
        )


def _validate_meta(meta_data: Dict[str, Any], *, require_available: bool = True) -> Tuple[str, Dict[str, Any]]:
    service_code = str(meta_data.get("serviceCode") or meta_data.get("eServiceCode") or "")
    code, service_data = _get_service_data(service_code)
    if require_available:
        _ensure_service_available(code, service_data)
    expected_target = str(service_data.get("serviceTargetCode") or service_data.get("targetCode") or "")
    if str(meta_data.get("targetCode") or "") != expected_target:
        raise HTTPException(
            status_code=400,
            detail="targetCode услуги {} должен быть {}".format(code, expected_target),
        )
    region = str(meta_data.get("region") or "").strip()
    if not re.fullmatch(r"\d{2,11}", region):
        raise HTTPException(
            status_code=400,
            detail="region должен содержать ОКАТО пользователя: от 2 до 11 цифр",
        )
    return code, service_data


def _upstream_meta(meta_data: Dict[str, Any]) -> Dict[str, str]:
    """Remove UI-only fields before sending the strict v1.14 meta object."""
    return {
        "region": str(meta_data["region"]),
        "serviceCode": str(meta_data.get("serviceCode") or meta_data.get("eServiceCode")),
        "targetCode": str(meta_data["targetCode"]),
    }


def _safe_format_template(template: str, context: Dict[str, str]) -> str:
    """Substitute a validated profile filename template."""
    if not template:
        return template
    try:
        return template.format(**context)
    except KeyError as exc:
        raise HTTPException(
            status_code=500,
            detail="Неизвестный placeholder профиля: {}".format(exc.args[0]),
        ) from exc


def _build_submission_context(service_data: Dict[str, Any], order_id: str = "") -> Dict[str, str]:
    """Подготовить значения для шаблонов имён файлов и архива."""
    now = datetime.now(timezone.utc).astimezone()
    return {
        "orderId": order_id or "",
        "guid": str(uuid.uuid4()),
        "date": now.date().isoformat(),
        "now": now.isoformat(timespec="seconds"),
    }


def _restore_submission_context(meta_data: Dict[str, Any], context: Dict[str, str]) -> None:
    raw = meta_data.get("submissionContext")
    if raw is None:
        return
    if isinstance(raw, dict):
        raw = raw.get("guid")
    try:
        context["guid"] = str(uuid.UUID(str(raw)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail="submissionContext должен быть UUID") from exc


def _resolve_submission(service_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the versioned profile into the backend's internal shape."""
    submission = service_data.get("submission", {})
    mode = submission.get("mode", SUBMISSION_MODE_PUSH)
    documents = []
    for item in submission.get("documents", []):
        documents.append(
            {
                **item,
                "source_file": item.get("sourceFile") or item.get("source_file") or "",
                "template_file": item.get("outputName") or item.get("template_file") or "",
                "schema_file": item.get("schemaFile") or item.get("schema_file") or "",
                "validate_xml": item.get("validation") == "xsd" or bool(item.get("validate_xml")),
                "required": bool(item.get("required", True)),
            }
        )
    archive_template = submission.get("archiveNameTemplate") or submission.get(
        "archive_name_template", "application.zip"
    )
    return {
        "mode": mode,
        "documents": documents,
        "archive_name_template": archive_template,
        "chunk_size": int(submission.get("chunkSize", 5_000_000)),
        "allow_additional_files": bool(submission.get("allowAdditionalFiles", False)),
    }


def _service_documents_for_upload(
    service_data: Dict[str, Any],
    submission_context: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Сформировать ожидания по документам из профиля услуги.

    Each result retains validation/signature/required metadata.
    """
    documents = _resolve_submission(service_data).get("documents", [])
    resolved: List[Dict[str, Any]] = []
    for doc in documents:
        source_file = doc.get("source_file", "")
        rendered = _safe_format_template(
            doc.get("template_file") or source_file, submission_context
        )
        resolved.append({**doc, "rendered_name": rendered})
    return resolved


async def _iter_file_payloads(
    files_upload: List[UploadFile],
    service_code: str,
    order_id: str = "",
    submission_context: Dict[str, str] | None = None,
) -> Tuple[List[Tuple[str, bytes, Optional[Dict[str, Any]]]], List[str], List[str]]:
    """Собрать пары (имя_в_архиве, bytes) для передачи в zip.

    Возвращает:
    - список файлов для архива (имя + данные);
    - список незарегистрированных имён файлов (не попали в профиль документа);
    - список обязательных имён документов, которые отсутствуют в загрузке.
    """
    context = submission_context or _build_submission_context(
        services_dict.get(service_code, {}), order_id
    )
    service_data = services_dict.get(service_code, {})
    submission_docs = _service_documents_for_upload(service_data, context)
    expected: Dict[str, Dict[str, Any]] = {}
    for item in submission_docs:
        for candidate in (item.get("source_file"), item.get("rendered_name")):
            if candidate:
                expected[str(candidate)] = item
    required_names = [
        str(item["rendered_name"])
        for item in submission_docs
        if item.get("required") and item.get("rendered_name")
    ]
    seen_names: List[str] = []
    prepared: List[Tuple[str, bytes, Optional[Dict[str, Any]]]] = []
    unknown_files = []
    missing_files = []
    seen_uploads = set()
    seen_archive_names = set()
    total_bytes = 0
    for file in files_upload:
        filename = file.filename or ""
        normalized = PurePosixPath(filename.replace("\\", "/"))
        if not filename or normalized.is_absolute() or ".." in normalized.parts or len(normalized.parts) != 1:
            raise HTTPException(status_code=400, detail="Небезопасное имя файла: {!r}".format(filename))
        if filename in seen_uploads:
            raise HTTPException(status_code=400, detail="Файл передан дважды: {}".format(filename))
        seen_uploads.add(filename)
        content, total_bytes = await _read_upload_limited(
            file,
            total_bytes=total_bytes,
        )
        descriptor = expected.get(filename)
        rendered_name = descriptor.get("rendered_name") if descriptor else None
        if descriptor and rendered_name:
            if rendered_name in seen_archive_names:
                raise HTTPException(
                    status_code=400,
                    detail="Несколько upload-файлов дают одно имя в архиве: {}".format(rendered_name),
                )
            prepared.append((str(rendered_name), content, descriptor))
            seen_names.append(rendered_name)
            seen_archive_names.add(rendered_name)
        else:
            if not _resolve_submission(service_data)["allow_additional_files"]:
                raise HTTPException(status_code=400, detail="Файл не разрешён профилем: {}".format(filename))
            if filename in seen_archive_names:
                raise HTTPException(status_code=400, detail="Дублирующееся имя в архиве: {}".format(filename))
            prepared.append((filename, content, None))
            unknown_files.append(filename)
            seen_archive_names.add(filename)
    for rendered_name in required_names:
        if rendered_name and rendered_name not in seen_names:
            missing_files.append(rendered_name)
    return prepared, unknown_files, missing_files


def _build_archive(prepared_files: List[Tuple[str, bytes, Optional[Dict[str, Any]]]]) -> bytes:
    """Validate profile-owned documents and create the exact ZIP payload."""
    names = {name for name, _, _ in prepared_files}
    for file_name, file_content, descriptor in prepared_files:
        if descriptor and str(descriptor.get("mediaType") or "").endswith("xml"):
            validation = descriptor.get("validation")
            schema_file = descriptor.get("schema_file") if validation == "xsd" else None
            if validation in {"xsd", "well-formed"}:
                validate_xml_content(file_content, schema_file)
        if descriptor and descriptor.get("signature") == "detached-cades":
            signature_name = "{}.sig".format(file_name)
            if signature_name not in names:
                raise HTTPException(
                    status_code=400,
                    detail="Для файла {} обязательна отделённая подпись {}".format(
                        file_name, signature_name
                    ),
                )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_name, file_content, _ in prepared_files:
            zip_file.writestr(file_name, file_content)
    return zip_buffer.getvalue()


def _validated_order_response(response: httpx.Response, *, expected_order_id: Optional[int] = None) -> Dict[str, Any]:
    """Decode an EPGU upload response and enforce its required ``orderId``."""
    try:
        result = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="ЕПГУ вернул не-JSON ответ на отправку") from exc
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="ЕПГУ вернул неверный формат ответа на отправку")
    try:
        normalized_order_id = _positive_decimal_identifier(result.get("orderId"), "orderId")
        returned_order_id = int(normalized_order_id)
    except HTTPException as exc:
        raise HTTPException(status_code=502, detail="ЕПГУ не вернул корректный orderId") from exc
    if expected_order_id is not None and returned_order_id != expected_order_id:
        raise HTTPException(
            status_code=502,
            detail="ЕПГУ вернул orderId {} вместо {}".format(returned_order_id, expected_order_id),
        )
    return {**result, "orderId": normalized_order_id}


def _goskey_request(payload: GoskeyRequest):
    """Map the UI DTO to the reusable ``epgu.services.goskey`` domain model."""
    try:
        variant = SigningVariant(payload.variant) if payload.variant else None
        capability = capability_for_service(payload.serviceCode, variant)
        capability.require_verified()
        attributes = (
            GoskeyAttribute("orgName", payload.orgName),
            GoskeyAttribute("orgINN", payload.orgInn),
        )
        common = {
            "sign_expiration": payload.signExpiration,
            "description": payload.description,
            "attributes": attributes,
            "backlink": payload.backlink,
        }
        if payload.serviceCode == "10000000374":
            if payload.recipientType != "individual" or variant is None:
                raise GoskeyContractError(
                    "service 10000000374 requires individual recipient and variant"
                )
            return IndividualSignRequest(
                variant=variant,
                recipient=IndividualRecipient(snils=payload.snils, oid=payload.oid),
                **common,
            )
        if payload.serviceCode == "60025907":
            if payload.recipientType == "russian-legal":
                recipient = RussianLegalRecipient(
                    ogrn=payload.ogrn or "",
                    snils=payload.snils,
                    oid=payload.oid,
                )
            elif payload.recipientType == "foreign-legal":
                recipient = ForeignLegalRecipient(
                    rafp=payload.rafp or "",
                    inn_user=payload.innUser or "",
                )
            else:
                raise GoskeyContractError(
                    "service 60025907 requires russian-legal or foreign-legal recipient"
                )
            return LegalEntitySignRequest(recipient=recipient, **common)
        if payload.serviceCode == "60080470":
            if payload.recipientType != "individual":
                raise GoskeyContractError("service 60080470 requires individual recipient")
            return TreasurySignRequest(
                recipient=IndividualRecipient(snils=payload.snils, oid=payload.oid),
                **common,
            )
        # ``60079416`` reaches require_verified() and fails closed before here.
        raise UnsupportedGoskeyContractError("Goskey service is reference-only")
    except UnsupportedGoskeyContractError:
        raise
    except GoskeyContractError:
        raise
    except (TypeError, ValueError) as exc:
        raise GoskeyContractError(str(exc)) from exc


def _serialize_goskey_capability(capability) -> Dict[str, Any]:
    result = asdict(capability)
    for key in ("operation", "variant", "state"):
        if result.get(key) is not None:
            result[key] = result[key].value
    return result


async def _reserve_upstream_order(
    meta: Dict[str, str], client: httpx.AsyncClient, session: SessionSnapshot
) -> int:
    _ensure_session_current(session)
    response = await client.post(
        f"{SVCDEV_HOST}/api/gusmev/order",
        json=meta,
        headers={"Authorization": f"Bearer {session.bearer}"},
    )
    _ensure_session_current(session)
    response.raise_for_status()
    return int(_validated_order_response(response)["orderId"])


async def _push_goskey_archive(
    meta: Dict[str, str],
    archive: bytes,
    client: httpx.AsyncClient,
    session: SessionSnapshot,
) -> Tuple[Dict[str, Any], int]:
    _ensure_session_current(session)
    response = await client.post(
        f"{SVCDEV_HOST}/api/gusmev/push",
        files={
            "meta": (None, json.dumps(meta), "application/json"),
            "file": ("goskey.zip", archive, "application/octet-stream"),
        },
        headers={"Authorization": f"Bearer {session.bearer}"},
    )
    _ensure_session_current(session)
    response.raise_for_status()
    return _validated_order_response(response), 1


async def _push_goskey_archive_chunked(
    meta: Dict[str, str],
    archive: bytes,
    order_id: int,
    client: httpx.AsyncClient,
    session: SessionSnapshot,
    *,
    chunk_size: int = 5_000_000,
) -> Tuple[Dict[str, Any], int]:
    total = max(1, (len(archive) + chunk_size - 1) // chunk_size)
    started_at = time.monotonic()
    result: Dict[str, Any] = {}
    for current in range(total):
        _ensure_session_current(session)
        content = archive[current * chunk_size:(current + 1) * chunk_size]
        name = "goskey.zip" if total == 1 else "goskey.z{:03d}".format(current + 1)
        files: Dict[str, Tuple[Optional[str], Any, Optional[str]]] = {
            "meta": (None, json.dumps(meta), "application/json"),
            "file": (name, content, "application/octet-stream"),
            "orderId": (None, str(order_id), None),
        }
        if total > 1:
            files["chunk"] = (None, str(current), None)
            files["chunks"] = (None, str(total), None)
        response = await _post_chunk_with_deadline(
            client,
            f"{SVCDEV_HOST}/api/gusmev/push/chunked",
            started_at=started_at,
            files=files,
            headers={"Authorization": f"Bearer {session.bearer}"},
        )
        _ensure_session_current(session)
        response.raise_for_status()
        expected_status = 200 if current == total - 1 else 206
        if response.status_code != expected_status:
            raise HTTPException(
                status_code=502,
                detail="Часть {}/{}: ожидался HTTP {}, получен {}".format(
                    current + 1, total, expected_status, response.status_code
                ),
            )
        result = _validated_order_response(response, expected_order_id=order_id)
    return result, total

# Эндпоинты


@app.post("/get_certificates")
async def get_certificates_endpoint():
    return JSONResponse(
        content=[
            _certificate_summary(cert_id, cert)
            for cert_id, cert in CERTIFICATES.items()
        ]
    )


@app.post("/set_current_certificate")
async def set_current_certificate(cert_id: str):
    global CURRENT_CERT_ID
    if cert_id not in CERTIFICATES:
        logger.info("Запрошен неизвестный certificate id")
        raise HTTPException(
            status_code=400, detail="Сертификат не найден.")
    if CURRENT_CERT_ID != cert_id:
        CURRENT_CERT_ID = cert_id
        # A bearer is obtained with a signature made by the selected
        # certificate.  It must never survive an identity change.
        _invalidate_access_token()
    return JSONResponse(content=None, status_code=200)


@app.post("/get_current_certificate")
async def get_current_certificate_endpoint():
    try:
        details = get_current_certificate_details()
        return JSONResponse(content={"certId": CURRENT_CERT_ID, "subject": details}, status_code=200)
    except Exception as e:
        logger.info("Текущий сертификат недоступен: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Текущий сертификат не установлен") from e


@app.post("/session/clear")
async def clear_session():
    """Forget all process-global operator authorization/signing state."""
    global CURRENT_CERT_ID
    _invalidate_access_token()
    CURRENT_CERT_ID = None
    return {"cleared": True}


@app.get("/status")
async def home_route():
    if pycades is None:
        raise HTTPException(status_code=503, detail="pycades/CryptoPro CSP недоступен")
    version = pycades.About().Version
    module_version = pycades.ModuleVersion()
    return JSONResponse(content={"Version": version, "ModuleVersion": module_version}, status_code=200)


@app.get("/hc")
async def check_route():
    if pycades is None:
        return JSONResponse(content={"status": "Degraded", "pycades": False}, status_code=503)
    version = pycades.About()
    if version:
        return JSONResponse(content={"status": "Ok"}, status_code=200)
    else:
        return JSONResponse(content={"status": "Error"}, status_code=404)


@app.post("/accessTkn_esia")
async def access_tkn_esia(request: APIKeyRequest, client: httpx.AsyncClient = Depends(get_async_client)):
    global ACCESS_TKN_ESIA, ACCESS_TKN_EXP, ESIA_HOST, API_KEY_DEFAULT
    if not request.api_key:
        raise HTTPException(status_code=400, detail="Некорректный API ключ.")
    api_key_data = request.api_key if request.api_key != "string" else API_KEY_DEFAULT
    if not api_key_data:
        raise HTTPException(status_code=400, detail="API ключ не настроен.")
    # Once a refresh starts, an earlier bearer must not survive a failed or
    # malformed provider response and accidentally authorize later requests.
    refresh_generation = _invalidate_access_token()
    try:
        signature = signkey(api_key_data)
        encoded_api_key = quote(api_key_data, safe="")
        url = f"{ESIA_HOST}/esia-rs/api/public/v1/orgs/ext-app/{encoded_api_key}/tkn"
        # Сам URL в лог не попадает: в нём API-Key и подпись.
        logger.info(
            "Запрос маркера ЕСИА: %s/esia-rs/api/public/v1/orgs/ext-app/<api-key>/tkn",
            ESIA_HOST,
        )
        response = await client.get(url, params={"signature": signature}, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError as err:
            raise HTTPException(
                status_code=502,
                detail="ЕСИА вернула некорректный ответ маркера",
            ) from err
        access_token = body.get("accessTkn") if isinstance(body, dict) else None
        if not isinstance(access_token, str) or not access_token.strip():
            raise HTTPException(
                status_code=502,
                detail="ЕСИА вернула некорректный ответ маркера",
            )
        access_token_exp = _decode_jwt_exp(access_token)
        if access_token_exp <= int(time.time()) + TOKEN_EXPIRY_LEEWAY_SECONDS:
            raise HTTPException(
                status_code=502,
                detail="ЕСИА вернула некорректный срок действия маркера",
            )
        # Logout, another refresh, or a certificate change while awaiting ESIA
        # wins.  The older request must not resurrect its bearer afterwards.
        if refresh_generation != SESSION_GENERATION:
            raise HTTPException(
                status_code=409,
                detail="Сессия оператора изменилась; повторите получение маркера",
            )
        ACCESS_TKN_ESIA = access_token
        ACCESS_TKN_EXP = access_token_exp
        # Do not reflect undocumented provider fields (which may contain
        # diagnostics or secret material) to the browser.
        return {"accessTkn": access_token, "exp": access_token_exp}
    except httpx.HTTPStatusError as err:
        logger.warning(
            "ESIA token request failed with HTTP %s",
            err.response.status_code,
        )
        raise HTTPException(
            status_code=err.response.status_code,
            detail="ЕСИА отклонила запрос маркера",
        ) from err
    except httpx.RequestError as err:
        logger.warning("ESIA token request failed: %s", type(err).__name__)
        raise HTTPException(
            status_code=502,
            detail="Сетевая ошибка при запросе маркера ЕСИА",
        ) from err
    except HTTPException:
        raise
    except Exception as err:
        # Provider exceptions can embed the signed request URL.  Log only the
        # type so API-Key/signature material never reaches logs or clients.
        logger.error("ESIA token operation failed: %s", type(err).__name__)
        raise HTTPException(
            status_code=500,
            detail="Не удалось получить маркер ЕСИА",
        ) from err


@app.post("/order")
async def order_endpoint(request_data: OrderRequest, client: httpx.AsyncClient = Depends(get_async_client)):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        payload = request_data.model_dump()
        _validate_meta(payload)
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/gusmev/order"
        _ensure_session_current(session)
        response = await client.post(
            url,
            json=_upstream_meta(payload),
            headers={
                "Authorization": f"Bearer {session.bearer}",
                "Content-Type": "application/json",
            },
        )
        _ensure_session_current(session)
        response.raise_for_status()
        return _validated_order_response(response)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("order", err) from err
    except HTTPException:
        raise
    except Exception as err:
        raise _internal_failure("order", err) from err


def safe_parse_order(order_details: Any) -> Optional[Dict[str, Any]]:
    """Parse the nested order object without reflecting its upstream payload."""
    if not isinstance(order_details, dict):
        raise HTTPException(status_code=502, detail="ЕПГУ вернул некорректные детали запроса")
    order_str = order_details.get("order")
    if not isinstance(order_str, str) or not order_str:
        return None
    try:
        parsed = json.loads(order_str)
    except json.JSONDecodeError as err:
        raise HTTPException(
            status_code=502,
            detail="ЕПГУ вернул некорректные детали запроса",
        ) from err
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=502, detail="ЕПГУ вернул некорректные детали запроса")
    return parsed


@app.post("/order/{orderId}")
async def order_with_id(
    orderId: int = ApiPath(..., gt=0, description="Order ID"),
    request_data: Optional[OrderRequest] = None,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/gusmev/order/{orderId}"
        _ensure_session_current(session)
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {session.bearer}",
            },
        )
        _ensure_session_current(session)
        response.raise_for_status()
        order_details = response.json()
        file_details = []
        order_obj = safe_parse_order(order_details)
        if not order_obj:
            raise HTTPException(status_code=404, detail="Детали запроса отсутствуют")
        order_obj = _normalize_identifier_fields(
            order_obj,
            {"orderId", "currentStatusHistoryId"},
        )
        response_service_code = str(
            order_obj.get("eserviceId") or order_obj.get("eServiceCode") or ""
        ).strip()
        for file in order_obj.get("orderResponseFiles", []):
            if file.get("link") and file.get("fileName"):
                if not response_service_code:
                    raise HTTPException(
                        status_code=502,
                        detail="ЕПГУ не вернул код услуги для скачивания вложения",
                    )
                link = file["link"].rstrip("/").split("/")[-1]
                file_details.append({
                    "objectId": order_obj["currentStatusHistoryId"],
                    "objectType": link,
                    "mnemonic": file["fileName"],
                    "eserviceCode": response_service_code,
                })
        if file_details:
            return JSONResponse(
                content={
                    "message": "Детали запроса успешно получены.",
                    "fileDetails": file_details,
                    "orderDetails": order_obj,
                },
                status_code=200,
            )
        else:
            return JSONResponse(
                content={
                    "message": "Детали запроса отсутствуют.",
                    "orderDetails": order_obj,
                },
                status_code=200,)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("order details", err) from err
    except HTTPException as err:
        logger.info("order details rejected with HTTP %s", err.status_code)
        raise err
    except Exception as err:
        raise _internal_failure("order details", err) from err


@app.post("/order/{orderId}/cancel")
async def cancel_order(
    orderId: int = ApiPath(..., gt=0, description="Order ID"),
    request_data: Optional[OrderRequest] = None,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/gusmev/order/{orderId}/cancel"
        _ensure_session_current(session)
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {session.bearer}",
            },
        )
        _ensure_session_current(session)
        response.raise_for_status()
        order_details = (
            _normalize_identifier_fields(response.json(), {"orderId"})
            if response.content
            else {}
        )
        return JSONResponse(
            content={
                "message": "Детали запроса отсутствуют.",
                "orderDetails": order_details,
            },
            status_code=200,
        )
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("cancel order", err) from err
    except HTTPException as err:
        logger.info("cancel order rejected with HTTP %s", err.status_code)
        raise err
    except Exception as err:
        raise _internal_failure("cancel order", err) from err


@app.get("/getUpdatedAfter")
async def get_updated_after(
    pageNum: int,
    pageSize: int,
    updatedAfter: str,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/gusmev/order/getUpdatedAfter"
        params = {"pageNum": pageNum, "pageSize": pageSize,
                  "updatedAfter": updatedAfter}
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {session.bearer}"},
            params=params,
        )
        _ensure_session_current(session)
        response.raise_for_status()
        body = _normalize_identifier_fields(response.json(), {"orderId"})
        return JSONResponse(content=body, status_code=200)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("getUpdatedAfter", err) from err
    except Exception as err:
        raise _internal_failure("getUpdatedAfter", err) from err


@app.get("/getOrdersStatus")
async def get_orders_status(
    pageNum: int,
    pageSize: int,
    orderIds: List[int] = Query([]),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/gusmev/order/getOrdersStatus"
        params = {"pageNum": pageNum, "pageSize": pageSize,
                  "orderIds": ",".join(map(str, orderIds))}
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {session.bearer}"},
            params=params,
        )
        _ensure_session_current(session)
        response.raise_for_status()
        body = _normalize_identifier_fields(response.json(), {"orderId"})
        return JSONResponse(content=body, status_code=200)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("getOrdersStatus", err) from err
    except Exception as err:
        raise _internal_failure("getOrdersStatus", err) from err


@app.post("/dictionary/{code}")
async def get_dictionary(
    code: str,
    treeFiltering: str = Query("ONELEVEL", pattern="^(ONELEVEL|SUBTREE)$"),
    parentRefItemValue: Optional[str] = None,
    pageNum: Optional[int] = None,
    pageSize: Optional[int] = None,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        session = _require_access_token()
        url = f"{SVCDEV_HOST}/api/nsi/v1/dictionary/{quote(code, safe='')}"
        payload: Dict[str, Any] = {"treeFiltering": treeFiltering}
        if parentRefItemValue is not None:
            payload["parentRefItemValue"] = parentRefItemValue
        if pageNum is not None:
            payload["pageNum"] = pageNum
        if pageSize is not None:
            payload["pageSize"] = pageSize
        response = await client.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {session.bearer}"},
        )
        _ensure_session_current(session)
        response.raise_for_status()
        body = response.json()
        error = body.get("error") if isinstance(body, dict) else None
        if isinstance(error, dict) and error.get("code") not in (None, 0, "0"):
            logger.warning("dictionary: upstream application error")
            raise HTTPException(
                status_code=502,
                detail="Справочник ЕПГУ вернул ошибку",
            )
        return JSONResponse(content=body, status_code=200)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("dictionary", err) from err
    except HTTPException:
        raise
    except Exception as err:
        raise _internal_failure("dictionary", err) from err


@app.post("/download_file/{objectId}/{objectType}")
async def download_file(
    objectId: int,
    objectType: str,
    mnemonic: str,
    eserviceCode: str,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    spooled = tempfile.SpooledTemporaryFile(max_size=DOWNLOAD_SPOOL_MEMORY_BYTES)
    try:
        if objectId <= 0:
            raise HTTPException(status_code=422, detail="objectId должен быть положительным")
        session = _require_access_token()
        encoded_type = quote(objectType, safe="")
        download_url = f"{SVCDEV_HOST}/api/gusmev/files/download/{objectId}/{encoded_type}"
        _ensure_session_current(session)
        async with client.stream(
            "GET",
            download_url,
            params={"mnemonic": mnemonic, "eserviceCode": eserviceCode},
            headers={
                "Authorization": f"Bearer {session.bearer}",
                "User-Agent": USER_AGENT,
            },
            follow_redirects=True,
        ) as response:
            _ensure_session_current(session)
            response.raise_for_status()
            declared_length = response.headers.get("content-length")
            if declared_length and int(declared_length) > MAX_DOWNLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Файл ответа превышает 100 MB")
            downloaded = 0
            async for block in response.aiter_bytes(UPLOAD_READ_CHUNK_BYTES):
                _ensure_session_current(session)
                downloaded += len(block)
                if downloaded > MAX_DOWNLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Файл ответа превышает 100 MB")
                spooled.write(block)
            media_type = response.headers.get("content-type", "application/octet-stream")
        spooled.seek(0)
        filename = PurePosixPath(mnemonic.replace("\\", "/")).name or "download"
        encoded_filename = quote(filename, safe="")

        def iter_spooled_file():
            try:
                while True:
                    block = spooled.read(UPLOAD_READ_CHUNK_BYTES)
                    if not block:
                        break
                    yield block
            finally:
                spooled.close()

        return StreamingResponse(
            iter_spooled_file(),
            media_type=media_type,
            headers={
                "Content-Disposition": (
                    "attachment; filename=\"download\"; filename*=UTF-8''{}".format(
                        encoded_filename
                    )
                )
            },
        )
    except httpx.HTTPStatusError as err:
        spooled.close()
        raise _upstream_http_failure("download", err) from err
    except HTTPException:
        spooled.close()
        raise
    except Exception as err:
        spooled.close()
        raise _internal_failure("download", err) from err


@app.get("/goskey/capabilities")
async def get_goskey_capabilities():
    """Expose SDK-backed Goskey capability states and source contradictions."""
    return [
        _serialize_goskey_capability(capability)
        for capability in GOSKEY_CAPABILITIES.values()
    ]


@app.post("/goskey/preview")
async def preview_goskey_request(payload: GoskeyRequest):
    """Build deterministic, XSD-oriented ``req.xml`` without signing/submitting."""
    _, service_data = _get_service_data(payload.serviceCode)
    _ensure_service_available(payload.serviceCode, service_data)
    try:
        request_model = _goskey_request(payload)
        xml = request_model.to_xml()
        capability = request_model.capability
        return {
            "serviceCode": capability.service_code,
            "variant": capability.variant.value if capability.variant else None,
            "capability": _serialize_goskey_capability(capability),
            "fileName": "req.xml",
            "xml": xml.decode("utf-8"),
            "requiresDetachedSignature": True,
        }
    except UnsupportedGoskeyContractError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GoskeyContractError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/goskey/submit")
async def submit_goskey_request(
    request_json: str = Form(..., alias="request"),
    documents: List[UploadFile] = File(...),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    """Generate, sign and submit a verified Goskey request with adaptive transport."""
    try:
        payload = GoskeyRequest.model_validate_json(request_json)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Некорректный JSON запроса Госключа") from exc
    code, service_data = _get_service_data(payload.serviceCode)
    _ensure_service_available(code, service_data)
    if pycades is None:
        raise HTTPException(status_code=503, detail="Для Госключа требуется pycades/CryptoPro CSP")

    try:
        # Маркер спрашиваем до подписи: без него отправлять всё равно некуда,
        # а подпись - обращение к закрытому ключу, и делать его зря не нужно.
        session = _require_access_token()
        request_model = _goskey_request(payload)
        validate_submission_window(payload.signExpiration)
        document_payloads: Dict[str, bytes] = {}
        casefold_names = set()
        total_bytes = 0
        for upload in documents:
            name = upload.filename or ""
            folded = name.casefold()
            if folded in casefold_names:
                raise GoskeyContractError("document names must be unique ignoring case")
            casefold_names.add(folded)
            content, total_bytes = await _read_upload_limited(
                upload,
                total_bytes=total_bytes,
            )
            if not content:
                raise GoskeyContractError("document {!r} is empty".format(name))
            document_payloads[name] = content
        if not document_payloads:
            raise GoskeyContractError("at least one business document is required")
        archive = build_signed_archive(
            request_model,
            document_payloads,
            CallableSigner(_sign_cades_detached),
        )
        decision = select_transport(len(archive), payload.orderId)
        meta = {
            "region": payload.region,
            "serviceCode": code,
            "targetCode": str(service_data["serviceTargetCode"]),
        }
        if decision.mode is GoskeyTransportMode.PUSH:
            result, chunks_count = await _push_goskey_archive(meta, archive, client, session)
        else:
            order_id = decision.order_id
            if decision.reserve_order:
                order_id = await _reserve_upstream_order(meta, client, session)
            assert order_id is not None
            result, chunks_count = await _push_goskey_archive_chunked(
                meta,
                archive,
                order_id,
                client,
                session,
                chunk_size=_resolve_submission(service_data)["chunk_size"],
            )
        return {
            **result,
            "serviceCode": code,
            "transport": decision.mode.value,
            "archiveSize": len(archive),
            "chunks": chunks_count,
            "signedFiles": 1 + len(document_payloads),
        }
    except UnsupportedGoskeyContractError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GoskeyContractError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise _upstream_http_failure("goskey submit", exc) from exc


@app.get("/services")
async def get_services():
    """
    Возвращает список услуг. Каждый элемент списка - объект с ключами:
    - serviceCode: номер сервиса (например, "1")
    - description: описание услуги
    - req_file: имя XML файла запроса
    - piev_epgu_file: имя XML файла приложения
    """
    services_list = []
    for key, value in services_dict.items():
        services_list.append(serialize_service(key, value))
    return JSONResponse(content=services_list)


@app.get("/services/{code}")
async def get_service(code: str):
    """Возвращает описание одной услуги из реестра."""
    if code not in services_dict:
        raise HTTPException(status_code=404, detail="Услуга не найдена")
    _, service_data = _get_service_data(code)
    return JSONResponse(content=serialize_service(code, service_data))


@app.get("/xsd")
async def get_xsd(
    simple_type_name: str,
    service: str = Query("60010153", description="Код услуги, определяющий XSD"),
):
    """Return an enumeration from the selected service's own XSD."""
    code, service_data = _get_service_data(service)
    _ensure_service_available(code, service_data)
    schema_file = next(
        (
            item.get("schema_file")
            for item in _resolve_submission(service_data)["documents"]
            if item.get("schema_file")
        ),
        None,
    )
    if not schema_file:
        raise HTTPException(status_code=404, detail="У услуги нет локальной XSD")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        schema_tree = etree.parse(str(_confined_xml_path(str(schema_file))), parser=parser)
    except (OSError, etree.XMLSyntaxError) as exc:
        raise HTTPException(status_code=500, detail="Не удалось прочитать XSD профиля") from exc

    ns = {"xs": "http://www.w3.org/2001/XMLSchema"}
    simple_type = next(
        (
            item
            for item in schema_tree.findall(".//xs:simpleType", ns)
            if item.get("name") == simple_type_name
        ),
        None,
    )
    if simple_type is None:
        return []
    result = []
    for enum in simple_type.findall(".//xs:enumeration", ns):
        annotation_elem = enum.find("xs:annotation/xs:documentation", ns)
        documentation = (
            annotation_elem.text.strip()
            if annotation_elem is not None and annotation_elem.text
            else ""
        )
        result.append({"value": enum.get("value"), "documentation": documentation})
    return result


@app.get("/xml")
async def get_xml(service: str = Query(..., description="Код услуги (см. /services), например '60010153'")):
    code, service_data = _get_service_data(service)
    _ensure_service_available(code, service_data)

    submission_context = _build_submission_context(service_data)
    submission_profile = _resolve_submission(service_data)
    documents_profile = submission_profile.get("documents", [])

    response_files: Dict[str, str] = {}
    files_payload = []
    try:
        for item in documents_profile:
            source_file = item.get("source_file")
            if not source_file:
                continue
            rendered_name = _safe_format_template(
                item.get("template_file", source_file), submission_context
            )
            path = _confined_xml_path(str(source_file))
            content = path.read_text(encoding="utf-8")
            document_key = item.get("id", source_file)
            response_files[document_key] = content
            if rendered_name != document_key:
                response_files[rendered_name] = content
            files_payload.append(
                {
                    "id": item.get("id"),
                    "name": rendered_name,
                    "sourceFile": source_file,
                    "outputName": rendered_name,
                    "templateFile": rendered_name,
                    "required": bool(item.get("required")),
                    "mediaType": item.get("mediaType", "application/xml"),
                    "schemaFile": item.get("schema_file") or None,
                    "validation": item.get("validation", "none"),
                    "signature": item.get("signature", "none"),
                    "content": content,
                }
            )
    except HTTPException:
        raise
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=500, detail="Не удалось прочитать XML-профиль") from exc

    return {
        "service": serialize_service(code, service_data),
        "files": files_payload,
        "documents": [item.get("id") for item in documents_profile],
        "submissionMode": submission_profile.get("mode", SUBMISSION_MODE_PUSH),
        "archiveNameTemplate": submission_profile.get(
            "archive_name_template", "piev_epgu.zip"
        ),
        "submissionContext": submission_context["guid"],
        "transforms": service_data.get("transforms", []),
        **response_files,
    }


@app.post("/zipsize")
async def zipsize(
    request: Request,
    files_upload: List[UploadFile] = None,
):
    try:
        zip_buffer = io.BytesIO()
        total_bytes = 0
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            if files_upload:
                for file in files_upload:
                    # Проверяем, не разорвал ли клиент соединение
                    if await request.is_disconnected():
                        logger.info(
                            "Клиент разорвал соединение, прекращаем обработку")
                        raise HTTPException(
                            status_code=499, detail="Client disconnected")

                    file_content, total_bytes = await _read_upload_limited(
                        file,
                        total_bytes=total_bytes,
                    )
                    zip_file.writestr(file.filename, file_content)
        zip_buffer.seek(0)
        archive_size = len(zip_buffer.getvalue())
        return {"zip_size": archive_size}
    except HTTPException:
        raise
    except Exception as e:
        raise _internal_failure("zipsize", e) from e


@app.post("/push")
async def push(
    meta: str = Form(...),
    files_upload: List[UploadFile] = None,
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        meta_data = json.loads(meta)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in meta: {e}")
        raise HTTPException(
            status_code=400, detail=f"Invalid JSON in meta: {e}")
    try:
        if not isinstance(meta_data, dict):
            raise HTTPException(status_code=400, detail="meta должен быть JSON-объектом")
        service_code, service_data = _validate_meta(meta_data)
        submission = _resolve_submission(service_data)
        _reject_generated_submission(submission)
        if submission.get("mode") not in {SUBMISSION_MODE_PUSH, SUBMISSION_MODE_ADAPTIVE}:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Услуга {service_code} отправляется через /push/chunked, "
                    "переключите метод отправки."
                ),
            )

        submission_context = _build_submission_context(service_data)
        _restore_submission_context(meta_data, submission_context)

        prepared_files, _, missing_files = await _iter_file_payloads(
            files_upload or [],
            service_code=service_code,
            order_id="",
            submission_context=submission_context,
        )
        if missing_files:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Не переданы обязательные файлы услуги "
                    f"{service_code}: {', '.join(missing_files)}"
                ),
            )

        archive = _build_archive(prepared_files)
        if len(archive) > 50_000_000:
            raise HTTPException(
                status_code=413,
                detail="Архив больше 50 МБ: сначала зарезервируйте orderId и используйте /push/chunked",
            )

        archive_name = _safe_format_template(
            submission.get("archive_name_template", "piev_epgu.zip"),
            submission_context,
        )
        if not archive_name.lower().endswith(".zip"):
            archive_name = f"{archive_name}.zip"

        files = {
            "meta": (None, json.dumps(_upstream_meta(meta_data)), "application/json"),
            "file": (archive_name, archive, "application/octet-stream"),
        }
        response = await client.post(
            f"{SVCDEV_HOST}/api/gusmev/push",
            files=files,
            headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
        )
        response.raise_for_status()
        return _validated_order_response(response)
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("push", err) from err
    except HTTPException:
        raise
    except Exception as e:
        raise _internal_failure("push", e) from e


@app.post("/push/chunked")
async def push_chunked(
    files_upload: List[UploadFile] = None,
    meta: str = Form(...),
    orderId: str = Form(...),
    chunks: Optional[int] = Form(None),
    chunk: Optional[int] = Form(None),
    client: httpx.AsyncClient = Depends(get_async_client),
):
    global ACCESS_TKN_ESIA, SVCDEV_HOST
    try:
        meta_data = json.loads(meta)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in meta: {e}")
        raise HTTPException(
            status_code=400, detail=f"Invalid JSON in meta: {e}")
    try:
        if not isinstance(meta_data, dict):
            raise HTTPException(status_code=400, detail="meta должен быть JSON-объектом")
        service_code, service_data = _validate_meta(meta_data)
        submission = _resolve_submission(service_data)
        _reject_generated_submission(submission)
        if submission.get("mode") not in {SUBMISSION_MODE_CHUNKED, SUBMISSION_MODE_ADAPTIVE}:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Услуга {service_code} не использует /push/chunked, "
                    "переключите метод отправки."
                ),
            )
        try:
            parsed_order_id = int(orderId)
            if parsed_order_id <= 0:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="orderId должен быть положительным числом") from exc
        if (chunks is None) != (chunk is None):
            raise HTTPException(
                status_code=400,
                detail="Legacy-поля chunk и chunks должны передаваться вместе",
            )
        if chunks is not None and (chunks != 1 or chunk != 0):
            raise HTTPException(
                status_code=400,
                detail="Backend сам делит ZIP; передайте legacy chunk=0 и chunks=1 либо не передавайте их",
            )

        submission_context = _build_submission_context(
            service_data, order_id=orderId
        )
        _restore_submission_context(meta_data, submission_context)

        prepared_files, _, missing_files = await _iter_file_payloads(
            files_upload or [],
            service_code=service_code,
            order_id=orderId,
            submission_context=submission_context,
        )
        if missing_files:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Не переданы обязательные файлы услуги "
                    f"{service_code}: {', '.join(missing_files)}"
                ),
            )

        archive = _build_archive(prepared_files)

        archive_name = _safe_format_template(
            submission.get("archive_name_template", "{orderId}-archive"),
            submission_context,
        )
        archive_basename = f"{archive_name}.zip" if not archive_name.lower().endswith(".zip") else archive_name
        chunk_size = submission["chunk_size"]
        total_chunks = max(1, (len(archive) + chunk_size - 1) // chunk_size)
        upstream_meta = json.dumps(_upstream_meta(meta_data))
        started_at = time.monotonic()
        result: Dict[str, Any] = {}
        for current_chunk in range(total_chunks):
            start = current_chunk * chunk_size
            chunk_payload = archive[start:start + chunk_size]
            if total_chunks == 1:
                chunked_name = archive_basename
            else:
                archive_base = archive_basename[:-4]
                chunked_name = "{}.z{:03d}".format(archive_base, current_chunk + 1)
            files: Dict[str, Tuple[Optional[str], Any, Optional[str]]] = {
                "meta": (None, upstream_meta, "application/json"),
                "file": (chunked_name, chunk_payload, "application/octet-stream"),
                "orderId": (None, str(parsed_order_id), None),
            }
            if total_chunks > 1:
                files["chunk"] = (None, str(current_chunk), None)
                files["chunks"] = (None, str(total_chunks), None)
            response = await _post_chunk_with_deadline(
                client,
                f"{SVCDEV_HOST}/api/gusmev/push/chunked",
                started_at=started_at,
                files=files,
                headers={"Authorization": f"Bearer {ACCESS_TKN_ESIA}"},
            )
            response.raise_for_status()
            expected_status = 200 if current_chunk == total_chunks - 1 else 206
            if response.status_code != expected_status:
                raise HTTPException(
                    status_code=502,
                    detail="Часть {}/{}: ожидался HTTP {}, получен {}".format(
                        current_chunk + 1, total_chunks, expected_status, response.status_code
                    ),
                )
            result = _validated_order_response(response, expected_order_id=parsed_order_id)
        return result
    except httpx.HTTPStatusError as err:
        raise _upstream_http_failure("push chunked", err) from err
    except HTTPException:
        raise
    except Exception as e:
        raise _internal_failure("push chunked", e) from e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", 5000)))

