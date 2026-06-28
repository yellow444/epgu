"""
Конфигурационные структуры backend'а: известные среды ЕСИА/ЕПГУ и каталог услуг
по умолчанию.

Сверка с порталом партнёров - 2026-05-12.
Источник: https://partners.gosuslugi.ru/catalog/api_for_gu

Эти константы экспортируются в `app.py` и используются роутерами в `routers.py`.
Каталог по умолчанию полностью переопределяется переменной окружения `SERVICES`
(JSON-объект code -> {description, req_file, piev_epgu_file, region, targetCode,
eServiceCode, serviceTargetCode}).
"""

from typing import Any, Dict


# Известные среды (актуальны на 2026-05-12).
# - test: SVCDEV - тестовый контур (раздел 1.2 спец. v1.12.1)
# - prod: продуктовый контур (ГОСТ TLS / lk.gosuslugi.ru)
# См. также https://github.com/ofstudio/go-api-epgu (раздел «Адреса Портала Госуслуг»).
ENVIRONMENTS: Dict[str, Dict[str, str]] = {
    "test": {
        "esia_host": "https://esia-portal1.test.gosuslugi.ru",
        "svcdev_host": "https://svcdev-beta.test.gosuslugi.ru",
        "esia_tech_portal": "https://esia-portal1.test.gosuslugi.ru/console/tech",
        "agreements": "https://svcdev-betalk.test.gosuslugi.ru/settings/third-party/agreements/acting",
    },
    "prod": {
        "esia_host": "https://esia.gosuslugi.ru",
        "svcdev_host": "https://lk.gosuslugi.ru",
        "esia_tech_portal": "https://esia.gosuslugi.ru/console/tech/",
        "agreements": "https://lk.gosuslugi.ru/settings/third-party/agreements/acting",
    },
}


# Каталог услуг по умолчанию.
# Коды соответствуют отдельным спецификациям из каталога партнёрского портала.
#   - 60010153   : ФССП - наличие исполнительного производства
#     Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx
#   - 60010154   : ФССП - предоставление информации о ходе ИП
#     Specifikaciya_API_EPGU_Predostavlenie_informacii_o_hode_IP_v_7.docx
#   - 10000000367: Подача заявлений/ходатайств/объяснений
#     Specifikaciya_API_EPGU_Podacha_zayavlenij_..._v1.3_18_06_2024.docx
#   - 10000000109: Доставка пенсии и социальных выплат ПФР/СФР
#     services/sfr/10000000109-zdp
DEFAULT_SERVICES: Dict[str, Dict[str, Any]] = {
    "60010153": {
        "description": "Наличие исполнительного производства (ФССП)",
        "req_file": "req.xml",
        "piev_epgu_file": "piev_epgu.xml",
        "region": "45000000000",
        "targetCode": "-60010153",
        "eServiceCode": "60010153",
        "serviceTargetCode": "-60010153",
    },
    "60010154": {
        "description": "Ход исполнительного производства (ФССП)",
        "req_file": "req.xml",
        "piev_epgu_file": "piev_epgu.xml",
        "region": "45000000000",
        "targetCode": "-60010154",
        "eServiceCode": "60010154",
        "serviceTargetCode": "-60010154",
    },
    "10000000367": {
        "description": "Подача заявлений/ходатайств/объяснений",
        "req_file": "req.xml",
        "piev_epgu_file": "piev_epgu.xml",
        "region": "45000000000",
        "targetCode": "-10000000367",
        "eServiceCode": "10000000367",
        "serviceTargetCode": "-10000000367",
    },
    "10000000109": {
        "description": "Доставка пенсии и социальных выплат ПФР/СФР",
        "req_file": "req.xml",
        "piev_epgu_file": "piev_epgu.xml",
        "region": "45000000000",
        "targetCode": "-10000000109",
        "eServiceCode": "10000000109",
        "serviceTargetCode": "-10000000109",
    },
}


# Версия спецификации API ЕПГУ, на которую ориентирован backend.
SPEC_VERSION = "1.13"
SPEC_SOURCE = "https://partners.gosuslugi.ru/catalog/api_for_gu"


def detect_environment(esia_host: str, svcdev_host: str) -> str:
    """Определить имя среды (test/prod/custom) по парe host'ов."""
    for name, urls in ENVIRONMENTS.items():
        if urls["esia_host"] == esia_host and urls["svcdev_host"] == svcdev_host:
            return name
    return "custom"


def serialize_service(code: str, value: Dict[str, Any]) -> Dict[str, Any]:
    """Привести запись услуги к плоскому виду для UI."""
    return {
        "serviceCode": code,
        "description": value.get("description", ""),
        "req_file": value.get("req_file", ""),
        "piev_epgu_file": value.get("piev_epgu_file", ""),
        "region": value.get("region", ""),
        "targetCode": value.get("targetCode", ""),
        "eServiceCode": value.get("eServiceCode", code),
        "serviceTargetCode": value.get("serviceTargetCode", ""),
    }
