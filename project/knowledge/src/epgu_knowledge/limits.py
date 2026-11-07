"""Общие ограничения параметров чтения знаний.

Одни и те же значения используют пакет, HTTP API v1 и MCP-сервер, чтобы
опубликованные схемы совпадали с тем, что реально принимает обработчик.
"""
from __future__ import annotations

SCHEMA_VERSION = "1.0"

DOMAINS = (
    "transition", "epgu", "esia", "smev", "signing", "max", "digital_ruble", "diagnostics",
)
OFFICIALITY = (
    "official", "official_historical", "official_catalog", "operator_docs",
    "unofficial_implementation", "developer_experience",
)

MIN_LIMIT = 1
MAX_LIMIT = 50
DEFAULT_LIMIT = 10
MAX_QUERY_LEN = 200
# Курсор поиска непрозрачен; длина реального курсора заметно меньше предела.
MAX_CURSOR_LEN = 200
# Идентификаторы маршрутов, узлов и источников в параметрах запросов.
MAX_ID_LEN = 64
