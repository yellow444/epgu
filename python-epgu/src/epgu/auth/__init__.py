"""Аутентификация в ЕСИА: получение маркера доступа.

Поддерживаются два сценария:

* :class:`OrgTokenProvider` - для **организаций** (информационных систем):
  маркер ``ext-app`` выдаётся по API-Key и ГОСТ-подписи (без участия человека).
* :class:`AasClient` - для **граждан**: OAuth2 (Authorization Code) ЕСИА, когда
  пользователь подтверждает доступ в браузере.
"""

from .base import StaticToken, TokenProvider
from .citizen import AasClient
from .org import OrgTokenProvider
from .token import Token

__all__ = [
    "Token",
    "TokenProvider",
    "StaticToken",
    "OrgTokenProvider",
    "AasClient",
]
