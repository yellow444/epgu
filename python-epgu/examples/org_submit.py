"""Пример: подача заявления от имени ОРГАНИЗАЦИИ (информационной системы).

Что нужно заранее:
  * зарегистрированная ИС в техпортале ЕСИА (мнемоника, сертификат);
  * API-Key организации-потребителя;
  * КриптоПро CSP + pycades и контейнер с КЭП (или свой CallableSigner).

Запуск (тестовый контур):
    python -m examples.org_submit
"""

from epgu import EpguClient, OrderArchive, OrderMeta, TEST
from epgu.auth import OrgTokenProvider
from epgu.services import submit_application
from epgu.signature import CryptoProSigner

API_KEY = "ВАШ_API_KEY"


def main() -> None:
    # 1. Подписант на КриптоПро (первый сертификат в хранилище).
    signer = CryptoProSigner(pin="1234567890")

    # 2. Провайдер маркера доступа организации (ext-app).
    auth = OrgTokenProvider(API_KEY, signer, env=TEST)

    # 3. Параметры услуги (пример: «Наличие исполнительного производства»).
    meta = OrderMeta(
        region="45000000000",
        service_code="10001449665",
        target_code="-10001449665",
    )

    # 4. Комплект документов (XML заявления + данные ПИЭВ с подписью).
    archive = OrderArchive(signer=signer)
    archive.add_file("req.xml", b"<req>...</req>")
    archive.add_signed_file("piev_epgu.xml", b"<piev>...</piev>")

    # 5. Подача «под ключ»: создать заявление, загрузить, дождаться статуса.
    with EpguClient(auth, env=TEST) as epgu:
        result = submit_application(epgu, meta, archive, wait=True)
        print("orderId:", result.order_id)
        print("push:", result.push_response)
        if result.order:
            print("status:", result.order.status_code)


if __name__ == "__main__":
    main()
