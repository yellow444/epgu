"""Проверки того, что секреты не утекают в логи.

API-Key организации едет сегментом пути в запросе маркера ЕСИА, а подпись -
параметром запроса. httpx печатает полный URL на уровне INFO, поэтому его
логгер должен быть приглушён: иначе ключ попадёт в вывод контейнера при первом
же обращении к ЕСИА.
"""

import logging

import app  # noqa: F401  импорт настраивает логгеры


def test_third_party_http_loggers_do_not_print_urls():
    for name in ("httpx", "httpcore"):
        level = logging.getLogger(name).level
        assert level >= logging.WARNING, (
            f"логгер {name} печатает URL запросов, а в них API-Key и подпись"
        )


def test_application_logger_is_not_muted():
    # Приглушать надо только чужие логгеры, свой уровень трогать нельзя.
    assert logging.getLogger("app").level <= logging.INFO
