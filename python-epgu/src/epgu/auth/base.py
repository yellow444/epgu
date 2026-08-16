# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Протокол поставщика маркера доступа."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..errors import AuthError
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
        try:
            self._token = Token(access_token=access_token)
        except ValueError as exc:
            raise AuthError(str(exc)) from exc

    def get_token(self) -> Token:
        """Вернуть неизменяемый заранее переданный маркер."""
        return self._token
