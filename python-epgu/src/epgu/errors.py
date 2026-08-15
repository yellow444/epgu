"""Иерархия исключений библиотеки.

Все ошибки наследуются от :class:`EpguError`, поэтому пользовательский код
может ловить либо конкретный тип, либо общий базовый класс.
"""

from __future__ import annotations

from typing import Any, Optional


class EpguError(Exception):
    """Базовое исключение библиотеки."""


class ConfigError(EpguError):
    """Некорректная конфигурация клиента (нет токена, подписанта и т.п.)."""


class SignatureError(EpguError):
    """Ошибка при формировании ГОСТ-подписи."""


class AuthError(EpguError):
    """Ошибка получения/обновления маркера доступа (ЕСИА)."""


class HttpError(EpguError):
    """HTTP-ошибка при обращении к API ЕПГУ/ЕСИА.

    Attributes:
        status_code: код ответа HTTP.
        body: тело ответа (как текст).
        url: запрошенный URL.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        body: Any = None,
        url: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.url = url

    def __str__(self) -> str:  # pragma: no cover - тривиально
        base = super().__str__()
        if self.status_code is not None:
            return f"[{self.status_code}] {base}"
        return base


class ApiError(HttpError):
    """API вернул ошибку прикладного уровня (код/сообщение в теле ответа).

    Attributes:
        code: машиночитаемый код ошибки ЕПГУ, если присутствует.
    """

    def __init__(self, message: str, *, code: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.code = code


class OrderRejectedError(ApiError):
    """Заявление отклонено ведомством (терминальный статус с ошибкой)."""


class ValidationError(EpguError):
    """Локальная валидация данных не пройдена (например, XML не соответствует XSD)."""
