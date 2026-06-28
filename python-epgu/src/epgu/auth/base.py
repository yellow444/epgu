"""Протокол поставщика маркера доступа."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .token import Token


@runtime_checkable
class TokenProvider(Protocol):
    """Источник актуального маркера доступа для :class:`~epgu.client.EpguClient`."""

    def get_token(self) -> Token:
        """Вернуть действующий маркер, при необходимости получив/обновив его."""
        ...


class StaticToken:
    """Обёртка для заранее полученного маркера (например, вставленного вручную)."""

    def __init__(self, access_token: str) -> None:
        self._token = Token(access_token=access_token)

    def get_token(self) -> Token:
        return self._token
