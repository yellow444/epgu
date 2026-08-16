# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""epgu - Python-клиент API Госуслуг (ЕПГУ/ЕСИА).

Подача заявлений, отслеживание статусов и работа с файлами - для граждан и
организаций. Подпись (КЭП) и аутентификация вынесены за интерфейсы, поэтому
библиотека работает и с КриптоПро, и с внешним сервисом подписи.

Быстрый старт (организация)::

    import os
    from epgu import EpguClient, OrderMeta, TEST
    from epgu.auth import OrgTokenProvider
    from epgu.signature import CryptoProSigner

    signer = CryptoProSigner(thumbprint=os.environ["EPGU_CERT_THUMBPRINT"],
                             pin=os.environ.get("EPGU_KEY_PIN"))
    auth = OrgTokenProvider(api_key=os.environ["EPGU_API_KEY"], signer=signer, env=TEST)

    meta = OrderMeta(region=os.environ["EPGU_REGION"],
                     service_code=os.environ["EPGU_SERVICE_CODE"],
                     target_code=os.environ["EPGU_TARGET_CODE"])
    with EpguClient(auth, env=TEST) as epgu:
        order_id = epgu.create_order(meta)
"""

from . import geps
from .archive import OrderArchive
from .client import EpguClient
from .const import PROD, TEST, TEST_BETA, TSA_TEST, Env
from .errors import (
    ApiError,
    AuthError,
    ConfigError,
    EpguError,
    HttpError,
    OrderRejectedError,
    SignatureError,
    ValidationError,
)
from .models import (
    DictionaryItem,
    DictionaryResult,
    Order,
    OrderFile,
    OrderMeta,
    OrdersPage,
    OrderStatus,
)
from .xml_validation import validate_xml

__version__ = "0.3.0"

__all__ = [
    "__version__",
    # клиент и модели
    "geps",
    "EpguClient",
    "OrderArchive",
    "OrderMeta",
    "Order",
    "OrderFile",
    "OrderStatus",
    "OrdersPage",
    "DictionaryItem",
    "DictionaryResult",
    "validate_xml",
    # контуры
    "Env",
    "TEST",
    "TEST_BETA",
    "PROD",
    "TSA_TEST",
    # ошибки
    "EpguError",
    "ConfigError",
    "AuthError",
    "SignatureError",
    "HttpError",
    "ApiError",
    "OrderRejectedError",
    "ValidationError",
]
