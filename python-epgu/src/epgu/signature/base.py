"""Протокол подписанта."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    """Контракт формирователя отсоединённой ГОСТ-подписи (CAdES-BES).

    Реализация должна вернуть DER-байты отсоединённой подписи PKCS#7/CMS над
    переданными данными. Кодирование (base64 / base64url) делает вызывающий код.
    """

    def sign(self, data: bytes) -> bytes:
        """Подписать ``data`` и вернуть отсоединённую подпись (DER-байты)."""
        ...
