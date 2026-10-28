# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Локальная и безопасная проверка XML заявления по XSD услуги."""

from __future__ import annotations

from typing import Union

from .errors import ConfigError, ValidationError

XmlContent = Union[str, bytes, bytearray]


def _as_xml_bytes(content: XmlContent, name: str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    raise TypeError(f"{name} должен быть str или bytes")


def validate_xml(xml_content: XmlContent, xsd_content: XmlContent) -> None:
    """Проверить XML по XSD и выбросить :class:`ValidationError` при ошибке.

    Внешние сущности, DTD и сетевые обращения отключены. Функция ничего не
    возвращает при успехе. Зависимость ``lxml`` ставится через extra ``xml``.
    """
    try:
        from lxml import etree  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - проверяется без extra вручную
        raise ConfigError(
            "Для XSD-валидации установите пакет с extra: pip install 'epgu-api[xml]'"
        ) from exc

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        remove_comments=False,
    )
    try:
        schema_document = etree.fromstring(_as_xml_bytes(xsd_content, "xsd_content"), parser)
        schema = etree.XMLSchema(schema_document)
    except (etree.XMLSyntaxError, etree.XMLSchemaParseError) as exc:
        raise ValidationError(f"Некорректная XSD-схема: {exc}") from exc

    try:
        document = etree.fromstring(_as_xml_bytes(xml_content, "xml_content"), parser)
    except etree.XMLSyntaxError as exc:
        raise ValidationError(f"Некорректный XML: {exc}") from exc
    if document.getroottree().docinfo.doctype:
        raise ValidationError("Некорректный XML: DTD запрещён")

    try:
        if schema.validate(document):
            return
    except etree.XMLSchemaValidateError as exc:
        raise ValidationError(f"Ошибка XSD-валидации: {exc}") from exc
    messages = [str(error) for error in schema.error_log[:5]]
    detail = "; ".join(messages) or "документ не соответствует схеме"
    raise ValidationError(f"XML не соответствует XSD: {detail}")
