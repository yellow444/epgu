"""Подписант на основе произвольной функции."""

from __future__ import annotations

from typing import Callable

from ..errors import SignatureError


class CallableSigner:
    """Оборачивает любую функцию ``bytes -> bytes`` в :class:`Signer`.

    Удобно, когда подпись формируется внешним сервисом, аппаратным токеном или
    утилитой командной строки (csptest, openssl с движком ГОСТ и т.п.).

    Example:
        >>> def my_sign(data: bytes) -> bytes:
        ...     return call_external_service(data)
        >>> signer = CallableSigner(my_sign)
    """

    def __init__(self, func: Callable[[bytes], bytes]) -> None:
        self._func = func

    def sign(self, data: bytes) -> bytes:
        try:
            result = self._func(data)
        except Exception as exc:  # noqa: BLE001 - оборачиваем любую ошибку подписи
            raise SignatureError(f"Внешний подписант завершился ошибкой: {exc}") from exc
        if not isinstance(result, (bytes, bytearray)):
            raise SignatureError(
                "Функция подписи должна возвращать bytes (DER-подпись), "
                f"получено {type(result).__name__}"
            )
        return bytes(result)
