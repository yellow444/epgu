"""Вход в установку: сессии, пользователи, закрытость методов."""

import io
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

pytestmark = pytest.mark.real_auth

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DB_FILE", str(tmp_path / "auth" / "auth.sqlite3"))
    import auth
    import auth_store

    auth_store._initialized_for = None
    auth.throttle.reset()
    return tmp_path


@pytest.fixture()
def client(store):
    import app as application

    return TestClient(application.app)


def make_admin(login="admin"):
    import auth

    return auth.create_account(login, PASSWORD, installation_admin=True, source="cli")


def signed_in(client, login="admin", password=PASSWORD):
    response = client.post("/auth/login", json={"login": login, "password": password})
    assert response.status_code == 200, response.text
    return response


def test_every_method_needs_a_session(client):
    for method, path in (
        ("get", "/services"), ("get", "/version"), ("post", "/get_certificates"),
        ("get", "/geps/messages"), ("get", "/inbound/messages"), ("post", "/order"),
        ("get", "/auth/session"), ("get", "/auth/accounts"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code == 401, path
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/auth/mode").status_code == 200
    # Неизвестный путь не превращается в подсказку, есть он или нет.
    assert client.get("/no-such-route").status_code == 404


def test_first_admin_only_by_local_command(client, monkeypatch):
    import auth_cli

    assert client.get("/auth/mode").json()["bootstrap_required"] is True
    assert client.post("/auth/accounts", json={"login": "root", "password": PASSWORD}).status_code == 401
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert auth_cli.main(["create-admin", "--login", "root", "--password-stdin"]) == 0
    assert client.get("/auth/mode").json()["bootstrap_required"] is False
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert auth_cli.main(["create-admin", "--login", "root2", "--password-stdin"]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert auth_cli.main(["create-admin", "--login", "root3", "--password-stdin", "--additional"]) == 2


def test_login_session_cookie_and_logout(client):
    make_admin()
    response = signed_in(client)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "token" not in response.json() and PASSWORD not in response.text
    assert response.json()["account"]["login"] == "admin"
    assert client.get("/services").status_code == 200
    assert client.get("/auth/session").json()["account"]["installation_admin"] is True
    client.post("/auth/logout")
    assert client.get("/services").status_code == 401


def test_wrong_password_and_unknown_login_look_the_same(client):
    make_admin()
    wrong = client.post("/auth/login", json={"login": "admin", "password": "wrong password!!"})
    unknown = client.post("/auth/login", json={"login": "nobody", "password": "wrong password!!"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_forged_cookie_or_header_is_not_a_session(client):
    admin = make_admin()
    assert client.get("/services", headers={"X-Account-Id": admin.id}).status_code == 401
    client.cookies.set("epgu_session", admin.id)
    assert client.get("/services").status_code == 401


def test_repeated_failures_are_throttled(store):
    import auth

    make_admin()
    moment = time.time()
    for _ in range(5):
        with pytest.raises(auth.AuthError):
            auth.login("admin", "wrong password!!", now=moment)
    with pytest.raises(auth.AuthError, match="Слишком много"):
        auth.login("admin", PASSWORD, now=moment)
    assert auth.login("admin", PASSWORD, now=moment + 3600)["account"].login == "admin"


def test_idle_session_expires(store):
    import auth

    make_admin()
    moment = time.time()
    issued = auth.login("admin", PASSWORD, now=moment)
    with pytest.raises(auth.AccessDenied):
        auth.resolve_session(issued["token"], now=moment + auth.session_idle_seconds() + 1)


def test_admin_manages_users_and_operator_cannot(client):
    make_admin()
    signed_in(client)
    created = client.post(
        "/auth/accounts",
        json={"login": "operator", "password": PASSWORD, "display_name": "Оператор"},
    )
    assert created.status_code == 200 and created.json()["installation_admin"] is False
    assert PASSWORD not in client.get("/auth/accounts").text
    operator = TestClient(client.app)
    signed_in(operator, "operator")
    assert operator.get("/services").status_code == 200
    assert operator.get("/auth/accounts").status_code == 403
    assert operator.post("/auth/accounts", json={"login": "x-user", "password": PASSWORD}).status_code == 403

    operator_id = created.json()["id"]
    assert client.post("/auth/accounts/%s/disabled" % operator_id, json={"disabled": True}).status_code == 200
    assert operator.get("/services").status_code == 401  # сессии отключённого гаснут
    assert operator.post("/auth/login", json={"login": "operator", "password": PASSWORD}).status_code == 401
    client.post("/auth/accounts/%s/disabled" % operator_id, json={"disabled": False})
    new_password = "another long password 1"
    assert client.post("/auth/accounts/%s/password" % operator_id, json={"password": new_password}).status_code == 200
    signed_in(operator, "operator", new_password)


def test_last_admin_and_self_cannot_be_disabled(client):
    admin = make_admin()
    signed_in(client)
    response = client.post("/auth/accounts/%s/disabled" % admin.id, json={"disabled": True})
    assert response.status_code == 400


def test_password_change_ends_sessions(client):
    make_admin()
    signed_in(client)
    other = TestClient(client.app)
    signed_in(other)
    new_password = "brand new long password"
    assert client.post("/auth/password", json={"current": "wrong", "new": new_password}).status_code == 400
    assert client.post("/auth/password", json={"current": PASSWORD, "new": new_password}).status_code == 200
    assert other.get("/services").status_code == 401
    signed_in(client, password=new_password)


def test_passwords_are_salted_scrypt(store):
    import auth_store

    make_admin("admin")
    make_admin("admin2")
    with auth_store.read() as db:
        stored = [row["password_hash"] for row in db.execute("SELECT password_hash FROM accounts")]
    assert all(value.startswith("scrypt$") and PASSWORD not in value for value in stored)
    assert len(set(stored)) == 2


def test_extension_points_are_applied(client, monkeypatch):
    import auth_api

    make_admin()
    calls = []

    def deny_version(request, account):
        calls.append(auth_api.route_path(request))
        if auth_api.route_path(request) == "/version":
            raise HTTPException(status_code=403, detail="нет")

    monkeypatch.setattr(auth_api, "authorizers", [deny_version])
    monkeypatch.setattr(auth_api, "session_extensions", [lambda account: {"extra": account.login}])
    monkeypatch.setattr(auth_api, "mode_extensions", [lambda: {"edition": "test"}])
    session = signed_in(client).json()
    assert session["extra"] == "admin"
    assert client.get("/auth/mode").json()["edition"] == "test"
    assert client.get("/version").status_code == 403
    assert client.get("/services").status_code == 200
    assert "/services" in calls
