"""Общая настройка тестов backend.

Приложение требует вход на любом методе. Тесты подачи, Госпочты, каталога и
остального проверяют сами методы, поэтому по умолчанию в них подставлен
вошедший администратор, а дополнительные проверки доступа отключены.

Тесты, помеченные ``real_auth``, работают с настоящей проверкой сессии: так
проверяются вход, выход, пользователи и проверки доступа дополнений.
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_auth: настоящая проверка сессии без подставленного пользователя"
    )


@pytest.fixture(autouse=True)
def _signed_in_admin(request, monkeypatch):
    if request.node.get_closest_marker("real_auth"):
        return
    import auth_api
    from auth import Account

    account = Account(
        id="acc_" + "0" * 32,
        login="test-admin",
        display_name="Тестовый администратор",
        installation_admin=True,
    )

    def signed_in(req):
        req.state.account = account
        return account

    monkeypatch.setattr(auth_api, "_resolve", signed_in)
    monkeypatch.setattr(auth_api, "authorizers", [])
