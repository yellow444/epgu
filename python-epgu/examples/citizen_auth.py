"""Пример: авторизация ГРАЖДАНИНА через ЕСИА (OAuth2 Authorization Code).

Гражданин переходит по ссылке, подтверждает доступ в ЕСИА, после чего ваша
информационная система получает ``code`` на redirect_uri и обменивает его на
маркер доступа. Дальше с этим маркером можно работать как с любым другим.

Запуск:
    python -m examples.citizen_auth
"""

from epgu import EpguClient, TEST
from epgu.auth import AasClient
from epgu.signature import CryptoProSigner

CLIENT_ID = "MNEMONIC_OF_YOUR_IS"  # мнемоника ИС в ЕСИА
REDIRECT_URI = "https://your-app.example/esia/callback"


def main() -> None:
    signer = CryptoProSigner(pin="1234567890")
    aas = AasClient(
        CLIENT_ID,
        signer,
        env=TEST,
        redirect_uri=REDIRECT_URI,
        scope="openid fullname",
    )

    # Шаг 1. Сформировать ссылку и отправить гражданина в ЕСИА.
    url, state = aas.authorization_url()
    print("Откройте ссылку в браузере и подтвердите доступ:")
    print(url)
    print("Сохраните state для проверки:", state)

    # Шаг 2. После возврата на redirect_uri вы получите ?code=...&state=...
    code = input("Вставьте полученный code: ").strip()

    # Шаг 3. Обменять код на маркер доступа.
    token = aas.exchange_code(code, state=state)
    print("access_token получен, истекает через:", token.expires_in, "сек")

    # Шаг 4. Использовать маркер.
    with EpguClient(token.access_token, env=TEST) as epgu:
        # например, запросить статусы заявлений гражданина
        statuses = epgu.updated_after("2024-01-01T00:00:00.000+0300")
        print("Заявлений обновлено:", len(statuses))


if __name__ == "__main__":
    main()
