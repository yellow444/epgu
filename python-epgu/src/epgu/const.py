"""Константы и адреса контуров ЕПГУ/ЕСИА."""

from __future__ import annotations

# User-Agent, как в рабочем бэкенде проекта: некоторые узлы ЕПГУ/ЕСИА
# капризничают к «нестандартным» агентам.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) "
    "Ubuntu/12.04 Chromium/18.0.1025.168 Chrome/18.0.1025.168 Safari/535.19"
)


class Env:
    """Готовые наборы адресов для тестового и боевого контуров.

    Attributes:
        esia: хост ЕСИА (авторизация, выдача маркеров).
        epgu: хост ЕПГУ (API gusmev / nsi).
    """

    def __init__(self, esia: str, epgu: str) -> None:
        self.esia = esia.rstrip("/")
        self.epgu = epgu.rstrip("/")


# Тестовый контур (SVCDEV / test.gosuslugi.ru).
TEST = Env(
    esia="https://esia-portal1.test.gosuslugi.ru",
    epgu="https://svcdev-beta.test.gosuslugi.ru",
)

# Боевой контур.
PROD = Env(
    esia="https://esia.gosuslugi.ru",
    epgu="https://api.gosuslugi.ru",
)

# Служба меток времени (TSA) тестового контура КриптоПро.
TSA_TEST = "http://testca2012.cryptopro.ru/tsp/tsp.srf"
