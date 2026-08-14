#!/usr/bin/env python3
"""Build the backend service-profile registry from the official catalogue.

The transport and archive composition below are reviewed facts from the
service specifications.  A profile is marked ``verified`` only when the repo
contains a service-specific editable template, schema where applicable, and
contract tests.  Other catalogue entries remain selectable/referenceable in
the UI but cannot be submitted through an invented generic XML format.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = ROOT / "docs" / "api_for_gu"
OUTPUT = ROOT / "api-gosuslugi-backend" / "service_profiles.json"


def doc(
    document_id: str,
    output_name: str,
    *,
    required: bool = True,
    signature: str = "none",
    role: str = "business",
) -> Dict[str, Any]:
    return {
        "id": document_id,
        "outputName": output_name,
        "required": required,
        "mediaType": "application/xml",
        "signature": signature,
        "role": role,
    }


def service(
    agency: str,
    mode: str,
    documents: List[Dict[str, Any]],
    *,
    protocol: str = "gusmev-order",
    signature: str = "none",
    variants: List[str] | None = None,
    additional_endpoints: List[str] | None = None,
) -> Dict[str, Any]:
    endpoints = {
        "chunked": ["/api/gusmev/order", "/api/gusmev/push/chunked"],
        "push": ["/api/gusmev/push"],
        "adaptive": ["/api/gusmev/push", "/api/gusmev/order", "/api/gusmev/push/chunked"],
    }[mode]
    return {
        "agency": agency,
        "protocol": protocol,
        "signature": signature,
        "variants": variants or [],
        "submission": {
            "mode": mode,
            "endpoints": endpoints,
            "archiveNameTemplate": "{orderId}-archive.zip" if mode != "push" else "application.zip",
            "chunkSize": 5_000_000,
            "documents": documents,
            "allowAdditionalFiles": True,
        },
        "additionalEndpoints": additional_endpoints or [],
    }


PROFILES: Dict[str, Dict[str, Any]] = {
    "10000000374": service(
        "Минцифры / Госключ",
        "adaptive",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
        variants=["УНЭП", "УКЭП"],
    ),
    "10000000352": service(
        "ФССП России",
        "chunked",
        [doc("transport", "req.xml", role="transport"), doc("request", "piev_epgu.xml")],
    ),
    "60010153": service(
        "ФССП России",
        "chunked",
        [doc("transport", "req.xml", role="transport"), doc("request", "piev_epgu.xml")],
    ),
    "10000000367": service(
        "ФССП России",
        "chunked",
        [doc("transport", "req.xml", role="transport"), doc("request", "piev_epgu.xml")],
        variants=["Petition", "IRequestOther"],
    ),
    "10000000396": service(
        "ФССП России",
        "chunked",
        [doc("transport", "req.xml", role="transport"), doc("request", "piev_epgu.xml")],
    ),
    "10000000109": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
    ),
    "10000000110": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
    ),
    "60013502": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
    ),
    "60013730": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
    ),
    "60019724": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
        variants=["ЗНП", "СНПАР"],
    ),
    "10000000585": service(
        "МВД России",
        "chunked",
        [doc("request", "attach.xml")],
        variants=["заключение договора", "расторжение договора", "выплата ВКС"],
    ),
    "60057731": service("МВД России", "chunked", [doc("request", "req.xml")]),
    "60025907": service(
        "Минцифры / Госключ",
        "adaptive",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
    ),
    "60048912": service(
        "Роскомнадзор",
        "chunked",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
    ),
    "60078836": service(
        "МВД России",
        "chunked",
        [doc("request", "attach.xml", signature="detached-cades")],
        signature="detached-cades",
    ),
    "10000000804": service(
        "МВД России / Госавтоинспекция",
        "chunked",
        [doc("transport", "trans_{guid}.xml", role="transport"), doc("request", "attach.xml")],
        variants=["новое ТС", "бывшее в эксплуатации ТС"],
        additional_endpoints=[
            "/api/gusmev/equeue/slots",
            "/api/gusmev/equeue/slot/{slotId}/book",
        ],
    ),
    "60011906": service("Генеральная прокуратура РФ", "chunked", [doc("request", "req.xml")]),
    "60080315": service(
        "Социальный фонд России",
        "chunked",
        [doc("request", "req_{guid}.xml"), doc("transport", "trans_{guid}.xml", role="transport")],
    ),
    "10000000588": service(
        "МВД России",
        "chunked",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
        variants=[
            "постановка иностранного гражданина",
            "снятие иностранного гражданина",
            "регистрационный учёт гражданина РФ",
        ],
    ),
    "60079416": service(
        "Минцифры / Госключ",
        "adaptive",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
    ),
    "60080470": service(
        "Минцифры / Госключ",
        "adaptive",
        [doc("request", "req.xml", signature="detached-cades")],
        signature="detached-cades",
    ),
}


def build_profiles() -> Dict[str, Any]:
    """Return the deterministic registry payload without mutating the tree."""
    catalogue = json.loads((DOCS_ROOT / "catalog.json").read_text(encoding="utf-8"))
    inventory_path = DOCS_ROOT / "extracted" / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8")) if inventory_path.exists() else {"assets": []}
    assets_by_code: Dict[str, List[Dict[str, Any]]] = {}
    for asset in inventory["assets"]:
        assets_by_code.setdefault(str(asset["serviceCode"]), []).append(
            {
                "path": asset["asset"],
                "kind": asset["kind"],
                "sha256": asset["sha256"],
                "wellFormed": asset["wellFormed"],
                "rootName": asset["rootName"],
                "namespace": asset.get("namespace", ""),
            }
        )

    output: Dict[str, Any] = {
        "schemaVersion": 1,
        "catalogObservedAt": catalogue["catalogObservedAt"],
        "catalogSource": catalogue["sourcePage"],
        "services": {},
    }
    for item in catalogue["documents"]:
        code = item.get("serviceCode")
        if not code:
            continue
        profile = dict(PROFILES[str(code)])
        profile.update(
            {
                "serviceCode": code,
                "title": item["title"],
                "description": item["title"],
                # Runtime OKATO belongs to the applicant/operator, never to a
                # reusable service profile.
                "region": "",
                "targetCode": "-{}".format(code),
                "eServiceCode": code,
                "serviceTargetCode": "-{}".format(code),
                "status": "reference",
                "available": False,
                "unavailableReason": (
                    "Формат и транспорт каталогизированы по официальной спецификации, "
                    "но рабочий шаблон этого варианта ещё не прошёл XSD/golden-проверку."
                ),
                "spec": {
                    "version": Path(str(item["file"])).stem,
                    "published": item["published"],
                    "source": item["url"],
                    "sha256": item["sha256"],
                    "localFile": item["file"],
                },
                "officialAssets": assets_by_code.get(str(code), []),
            }
        )
        if code == "60010153":
            profile["unavailableReason"] = (
                "Официальная схема и транспорт проверены, но текущий XML содержит "
                "демонстрационные данны. Отправка закрыта до типизированной формы и fail-closed валидации полей."
            )
            profile["submission"]["documents"][0].update(
                {"sourceFile": "req.xml", "validation": "well-formed"}
            )
            profile["submission"]["documents"][1].update(
                {
                    "sourceFile": "piev_epgu.xml",
                    "schemaFile": "piev_epgu.xsd",
                    "validation": "xsd",
                }
            )
            profile["transforms"] = [
                {
                    "documentId": "transport",
                    "selector": {
                        "namespace": "urn://x-artifacts-fssp-ru/mvv/smev3/epgu/1.0.1",
                        "localName": "OrderId",
                    },
                    "value": "{orderId}",
                },
                {
                    "documentId": "transport",
                    "selector": {
                        "namespace": "urn://x-artifacts-fssp-ru/mvv/smev3/epgu/1.0.1",
                        "localName": "Date",
                    },
                    "value": "{now}",
                },
                {
                    "documentId": "transport",
                    "selector": {
                        "namespace": "urn://x-artifacts-fssp-ru/mvv/smev3/epgu/1.0.1",
                        "localName": "StatementDate",
                    },
                    "value": "{date}",
                },
                {
                    "documentId": "request",
                    "selector": {
                        "namespace": "http://www.fssprus.ru/namespace/incoming/2019/1",
                        "localName": "ExternalKey",
                    },
                    "value": "{orderId}",
                },
                {
                    "documentId": "request",
                    "selector": {
                        "namespace": "http://www.fssprus.ru/namespace/incoming/2019/1",
                        "localName": "DocDate",
                    },
                    "value": "{date}",
                },
            ]
        goskey_capabilities = {
            "10000000374": [
                {
                    "id": "unep",
                    "label": "УНЭП физического лица",
                    "state": "verified",
                    "namespace": "urn://mpkey.gosuslugi.ru/sign_document/1.0.0",
                    "reason": "Проверено по опубликованной XSD.",
                },
                {
                    "id": "ukep",
                    "label": "УКЭП физического лица",
                    "state": "reference",
                    "namespace": "urn://mpkey.gosuslugi.ru/sign_document_ukep/1.0.0",
                    "reason": "Для опубликованного UKEP namespace в документе отсутствует XSD.",
                },
            ],
            "60025907": [
                {
                    "id": "legal-entity",
                    "label": "УКЭП юридического лица или ИП",
                    "state": "verified",
                    "namespace": "urn://mpkey.gosuslugi.ru/sign_document_ukep_legalperson/1.0.0",
                    "reason": "Проверено по опубликованной XSD; обязательность Description взята из XSD.",
                }
            ],
            "60079416": [
                {
                    "id": "decipher",
                    "label": "Расшифрование документов",
                    "state": "reference",
                    "namespace": "urn://mpkey.gosuslugi.ru/deciphering_document/1.0.0",
                    "reason": "Официальные источники противоречат друг другу: FileName/Description и лимит 50/20 документов.",
                }
            ],
            "60080470": [
                {
                    "id": "treasury",
                    "label": "УКЭП с сертификатом Федерального казначейства",
                    "state": "verified",
                    "namespace": "urn://mpkey.gosuslugi.ru/sign_document_ukep_roskazna/1.0.0",
                    "reason": "Проверено по опубликованной XSD.",
                }
            ],
        }
        if code in goskey_capabilities:
            profile["capabilities"] = goskey_capabilities[code]
            profile["submission"]["documents"][0]["generator"] = "goskey"
            has_verified = any(
                capability["state"] == "verified"
                for capability in goskey_capabilities[code]
            )
            if has_verified:
                profile["status"] = "verified"
                profile["available"] = True
                profile["unavailableReason"] = ""
        output["services"][str(code)] = profile

    missing = sorted(set(PROFILES) - set(output["services"]))
    if missing:
        raise RuntimeError("Profiles absent from official catalogue: {}".format(missing))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the checked-in registry matches the deterministic output",
    )
    args = parser.parse_args()
    output = build_profiles()
    serialized = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != serialized:
            print("{} is stale; run scripts/build_service_profiles.py".format(OUTPUT))
            return 1
        print("Verified {} service profiles; registry is current".format(len(output["services"])))
        return 0
    OUTPUT.write_text(serialized, encoding="utf-8")
    print("Wrote {} profiles to {}".format(len(output["services"]), OUTPUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
