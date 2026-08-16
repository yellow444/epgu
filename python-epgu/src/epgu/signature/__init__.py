# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Абстракция ГОСТ-подписи (КЭП) и её реализации.

Подпись вынесена за интерфейс :class:`Signer`, чтобы библиотека не зависела
жёстко от КриптоПро/pycades. Вы можете:

* использовать готовый :class:`CryptoProSigner` (требует установленного
  КриптоПро CSP и модуля ``pycades``);
* подключить свою реализацию через :class:`CallableSigner`
  (например, внешний микросервис подписи или аппаратный токен).
"""

from typing import Any

from .base import Signer
from .callable import CallableSigner

__all__ = ["Signer", "CallableSigner", "CryptoProSigner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401,D401 - динамический экспорт
    # CryptoProSigner импортирует pycades только при обращении, чтобы пакет
    # ставился и работал там, где КриптоПро отсутствует.
    if name == "CryptoProSigner":
        from .cryptopro import CryptoProSigner

        return CryptoProSigner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
