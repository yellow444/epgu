"""epgu - Python-клиент API Госуслуг (ЕПГУ/ЕСИА).

Подача заявлений, отслеживание статусов и работа с файлами - для граждан и
организаций. Подпись (КЭП) и аутентификация вынесены за интерфейсы, поэтому
библиотека работает и с КриптоПро, и с внешним сервисом подписи.

Быстрый старт (организация)::

    from epgu import EpguClient, OrderMeta, TEST
    from epgu.auth import OrgTokenProvider
    from epgu.signature import CryptoProSigner

    signer = CryptoProSigner(pin="1234567890")
    auth = OrgTokenProvider(api_key="...", signer=signer, env=TEST)

    with EpguClient(auth, env=TEST) as epgu:
        meta = OrderMeta(region="45000000000", service_code="10001449665",
                         target_code="-10001449665")
        order_id = epgu.create_order(meta)
"""

from .archive import OrderArchive
from .client import EpguClient
from .const import PROD, TEST, TSA_TEST, Env
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
from .models import Order, OrderFile, OrderMeta, OrderStatus

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # клиент и модели
    "EpguClient",
    "OrderArchive",
    "OrderMeta",
    "Order",
    "OrderFile",
    "OrderStatus",
    # контуры
    "Env",
    "TEST",
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
