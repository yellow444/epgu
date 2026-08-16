"""Интерактивный пример безопасного OAuth2 Authorization Code потока ЕСИА."""

import os

from epgu import TEST, EpguClient
from epgu.auth import AasClient
from epgu.signature import CryptoProSigner


def main() -> None:
    signer = CryptoProSigner(
        thumbprint=os.environ["EPGU_CERT_THUMBPRINT"],
        pin=os.environ.get("EPGU_KEY_PIN"),
    )
    with AasClient(
        os.environ["ESIA_CLIENT_ID"],
        signer,
        env=TEST,
        redirect_uri=os.environ["ESIA_REDIRECT_URI"],
        scope="openid fullname",
    ) as aas:
        authorization_url, expected_state = aas.authorization_url()
        print("Откройте ссылку в браузере и подтвердите доступ:")
        print(authorization_url)

        callback_url = input("Вставьте полный callback URL: ").strip()
        token = aas.exchange_callback(callback_url, expected_state=expected_state)

    print("Access token получен; срок жизни, сек:", token.expires_in)
    with EpguClient(token.access_token, env=TEST) as client:
        page = client.updated_after("2026-01-01T00:00:00.000+0300", page_num=0)
        print("Найдено заявлений:", page.total_count)


if __name__ == "__main__":
    main()
