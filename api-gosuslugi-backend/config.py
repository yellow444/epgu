"""Validated environment and service-profile configuration for the backend.

The service registry is generated from the public API Госуслуг catalogue by
``scripts/build_service_profiles.py``.  A catalogue entry and an executable
profile are deliberately different states: reference-only services remain
visible in the UI, but cannot be submitted with another agency's XML.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, MutableMapping, Optional

SPEC_VERSION = "1.14"
SPEC_SOURCE = "https://partners.gosuslugi.ru/catalog/api_for_gu"
CATALOG_OBSERVED_AT = "2026-08-12"

SUBMISSION_MODE_PUSH = "push"
SUBMISSION_MODE_CHUNKED = "chunked"
SUBMISSION_MODE_ADAPTIVE = "adaptive"
SUBMISSION_MODES = {
    SUBMISSION_MODE_PUSH,
    SUBMISSION_MODE_CHUNKED,
    SUBMISSION_MODE_ADAPTIVE,
}

ENVIRONMENTS: Dict[str, Dict[str, str]] = {
    "test": {
        "esia_host": "https://esia-portal1.test.gosuslugi.ru",
        "svcdev_host": "https://svcdev-gostapi.test.gosuslugi.ru",
        "esia_tech_portal": "https://esia-portal1.test.gosuslugi.ru/console/tech",
        "agreements": "https://svcdev-betalk.test.gosuslugi.ru/settings/third-party/agreements/acting",
    },
    "prod": {
        "esia_host": "https://esia.gosuslugi.ru",
        "svcdev_host": "https://www.gosuslugi.ru",
        "esia_tech_portal": "https://esia.gosuslugi.ru/console/tech/",
        "agreements": "https://lk.gosuslugi.ru/settings/third-party/agreements/acting",
    },
    # Compatibility gateway used by examples in older service appendices.
    "test-beta": {
        "esia_host": "https://esia-portal1.test.gosuslugi.ru",
        "svcdev_host": "https://svcdev-beta.test.gosuslugi.ru",
        "esia_tech_portal": "https://esia-portal1.test.gosuslugi.ru/console/tech",
        "agreements": "https://svcdev-betalk.test.gosuslugi.ru/settings/third-party/agreements/acting",
    },
}

_PROFILE_FILE = Path(__file__).with_name("service_profiles.json")
_ALLOWED_PLACEHOLDERS = {"orderId", "guid"}
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


class ServiceConfigError(ValueError):
    """The service registry is structurally unsafe or internally inconsistent."""


def _read_builtins(path: Path = _PROFILE_FILE) -> Dict[str, Dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceConfigError("Не удалось прочитать реестр услуг {}: {}".format(path, exc)) from exc
    if payload.get("schemaVersion") != 1 or not isinstance(payload.get("services"), dict):
        raise ServiceConfigError("service_profiles.json имеет неподдерживаемую схему")
    return {str(code): value for code, value in payload["services"].items()}


def _safe_relative_file(value: str, field: str) -> None:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not value or ".." in path.parts:
        raise ServiceConfigError("{} должен быть безопасным относительным путём: {!r}".format(field, value))


def _validate_template(value: str, field: str) -> None:
    unknown = set(_PLACEHOLDER.findall(value)) - _ALLOWED_PLACEHOLDERS
    if unknown:
        raise ServiceConfigError("{} содержит неизвестные placeholders: {}".format(field, sorted(unknown)))
    _safe_relative_file(value, field)


def validate_service_catalog(
    services: Mapping[str, Mapping[str, Any]],
    *,
    xml_root: Optional[Path] = None,
) -> None:
    """Validate all profiles eagerly, optionally checking local template files."""
    if not isinstance(services, Mapping):
        raise ServiceConfigError("SERVICES должен быть JSON-объектом code -> profile")
    for code, value in services.items():
        if not isinstance(code, str) or not code.isdigit():
            raise ServiceConfigError("Код услуги должен состоять из цифр: {!r}".format(code))
        if not isinstance(value, Mapping):
            raise ServiceConfigError("Профиль услуги {} должен быть объектом".format(code))
        if str(value.get("serviceCode")) != code:
            raise ServiceConfigError("serviceCode профиля {} не совпадает с ключом".format(code))
        if value.get("status") not in {"verified", "reference", "disabled"}:
            raise ServiceConfigError("У услуги {} неизвестный status".format(code))
        if not isinstance(value.get("available"), bool):
            raise ServiceConfigError("У услуги {} available должен быть bool".format(code))
        if value.get("available") and value.get("status") != "verified":
            raise ServiceConfigError("Только verified-профиль {} может быть available".format(code))
        if value.get("protocol") not in {"gusmev-order", "geps", "equeue", "reference"}:
            raise ServiceConfigError("У услуги {} неизвестный protocol".format(code))

        submission = value.get("submission")
        if not isinstance(submission, Mapping):
            raise ServiceConfigError("У услуги {} нет submission".format(code))
        if submission.get("mode") not in SUBMISSION_MODES:
            raise ServiceConfigError("У услуги {} неизвестный submission.mode".format(code))
        archive_name = str(submission.get("archiveNameTemplate") or "")
        _validate_template(archive_name, "{}.archiveNameTemplate".format(code))
        chunk_size = submission.get("chunkSize")
        if not isinstance(chunk_size, int) or chunk_size < 5_000_000 or chunk_size > 50_000_000:
            raise ServiceConfigError("У услуги {} chunkSize должен быть 5..50 MB".format(code))

        documents = submission.get("documents")
        if not isinstance(documents, list) or not documents:
            raise ServiceConfigError("У услуги {} нет описаний XML-документов".format(code))
        ids = set()
        output_names = set()
        for item in documents:
            if not isinstance(item, Mapping):
                raise ServiceConfigError("Документ услуги {} должен быть объектом".format(code))
            document_id = str(item.get("id") or "")
            output_name = str(item.get("outputName") or "")
            if not document_id or document_id in ids:
                raise ServiceConfigError("Неуникальный id документа услуги {}: {!r}".format(code, document_id))
            ids.add(document_id)
            _validate_template(output_name, "{}.{}.outputName".format(code, document_id))
            if output_name in output_names:
                raise ServiceConfigError("Дублирующееся имя документа услуги {}: {}".format(code, output_name))
            output_names.add(output_name)
            if item.get("signature") not in {"none", "detached-cades"}:
                raise ServiceConfigError("Неизвестный signature у {}.{}".format(code, document_id))
            if not isinstance(item.get("required"), bool):
                raise ServiceConfigError("required у {}.{} должен быть bool".format(code, document_id))
            source_file = item.get("sourceFile")
            if source_file:
                _safe_relative_file(str(source_file), "{}.{}.sourceFile".format(code, document_id))
            schema_file = item.get("schemaFile")
            if schema_file:
                _safe_relative_file(str(schema_file), "{}.{}.schemaFile".format(code, document_id))
            generator = item.get("generator")
            if generator not in {None, "goskey"}:
                raise ServiceConfigError("Неизвестный generator у {}.{}".format(code, document_id))
            if value.get("available") and not source_file and not generator:
                raise ServiceConfigError(
                    "Рабочий документ {}.{} не имеет sourceFile/generator".format(code, document_id)
                )
            if xml_root is not None and source_file:
                path = (xml_root / str(source_file)).resolve()
                if xml_root.resolve() not in path.parents or not path.is_file():
                    raise ServiceConfigError("Не найден шаблон {}.{}: {}".format(code, document_id, path))
            if xml_root is not None and schema_file:
                path = (xml_root / str(schema_file)).resolve()
                if xml_root.resolve() not in path.parents or not path.is_file():
                    raise ServiceConfigError("Не найдена XSD {}.{}: {}".format(code, document_id, path))


def _deep_merge(base: MutableMapping[str, Any], override: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), MutableMapping):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def load_services(override_json: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load built-ins and apply a strict, lossless ``SERVICES`` overlay.

    Existing profiles are deep-merged so a legacy operator override of region
    or title cannot accidentally erase transport/documents.  A new service must
    provide a complete profile and pass the same validation as a built-in.
    """
    result = copy.deepcopy(DEFAULT_SERVICES)
    if override_json:
        try:
            overrides = json.loads(override_json)
        except json.JSONDecodeError as exc:
            raise ServiceConfigError("SERVICES содержит невалидный JSON: {}".format(exc)) from exc
        if not isinstance(overrides, dict):
            raise ServiceConfigError("SERVICES должен быть JSON-объектом code -> profile")
        for code, override in overrides.items():
            if not isinstance(override, Mapping):
                raise ServiceConfigError("Override услуги {} должен быть объектом".format(code))
            if code in result:
                _deep_merge(result[code], override)
                result[code]["serviceCode"] = code
            else:
                candidate = copy.deepcopy(dict(override))
                candidate.setdefault("serviceCode", code)
                result[code] = candidate
    validate_service_catalog(result)
    return result


def detect_environment(esia_host: str, svcdev_host: str) -> str:
    """Return ``test``, ``prod``, ``test-beta`` or ``custom`` for two hosts."""
    normalized_esia = esia_host.rstrip("/")
    normalized_epgu = svcdev_host.rstrip("/")
    for name, urls in ENVIRONMENTS.items():
        if (
            urls["esia_host"].rstrip("/") == normalized_esia
            and urls["svcdev_host"].rstrip("/") == normalized_epgu
        ):
            return name
    return "custom"


def _legacy_document(item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        **dict(item),
        "source_file": item.get("sourceFile", ""),
        "template_file": item.get("outputName", ""),
        "schema_file": item.get("schemaFile", ""),
        "validate_xml": item.get("validation") == "xsd",
    }


def serialize_service(code: str, value: Mapping[str, Any]) -> Dict[str, Any]:
    """Serialize a full profile plus compatibility aliases for the current UI."""
    submission = value["submission"]
    documents = [_legacy_document(item) for item in submission["documents"]]
    req_document = next((item for item in documents if item.get("role") == "transport"), documents[0])
    business_document = next((item for item in documents if item.get("role") == "business"), documents[-1])
    return {
        **copy.deepcopy(dict(value)),
        "serviceCode": code,
        "req_file": req_document.get("source_file", ""),
        "piev_epgu_file": business_document.get("source_file", ""),
        "submissionMode": submission["mode"],
        "archiveNameTemplate": submission["archiveNameTemplate"],
        "submissionDocuments": documents,
        "transforms": copy.deepcopy(value.get("transforms", [])),
    }


DEFAULT_SERVICES: Dict[str, Dict[str, Any]] = _read_builtins()
validate_service_catalog(DEFAULT_SERVICES)


__all__ = [
    "CATALOG_OBSERVED_AT",
    "DEFAULT_SERVICES",
    "ENVIRONMENTS",
    "SPEC_SOURCE",
    "SPEC_VERSION",
    "SUBMISSION_MODE_ADAPTIVE",
    "SUBMISSION_MODE_CHUNKED",
    "SUBMISSION_MODE_PUSH",
    "ServiceConfigError",
    "detect_environment",
    "load_services",
    "serialize_service",
    "validate_service_catalog",
]
