# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
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


# Тестовый контур прямого ГОСТ TLS из спецификации API ЕПГУ 1.14.
TEST = Env(
    esia="https://esia-portal1.test.gosuslugi.ru",
    epgu="https://svcdev-gostapi.test.gosuslugi.ru",
)

# Боевой контур прямого ГОСТ TLS из спецификации API ЕПГУ 1.14.
PROD = Env(
    esia="https://esia.gosuslugi.ru",
    epgu="https://www.gosuslugi.ru",
)

# Старый тестовый шлюз из примеров ранних версий спецификации. Оставлен как
# явный opt-in для интеграций, которым его ещё не отключили.
TEST_BETA = Env(
    esia="https://esia-portal1.test.gosuslugi.ru",
    epgu="https://svcdev-beta.test.gosuslugi.ru",
)

# Служба меток времени (TSA) тестового контура КриптоПро.
TSA_TEST = "http://testca2012.cryptopro.ru/tsp/tsp.srf"
