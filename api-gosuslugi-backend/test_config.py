"""
Тесты на config.py и app._decode_jwt_exp — без зависимостей от pycades/CSP.
Запускаются на любой Python-машине: pytest test_config.py.
"""

import base64
import json

import pytest


def test_default_services_has_known_codes():
    from config import DEFAULT_SERVICES

    # Услуги, описанные в docs/SERVICES.md как «по умолчанию».
    for code in ("60010153", "60010154", "10000000367", "10000000109"):
        assert code in DEFAULT_SERVICES, f"Услуга {code} должна быть в DEFAULT_SERVICES"


def test_default_services_shape():
    from config import DEFAULT_SERVICES

    required = {
        "description",
        "req_file",
        "piev_epgu_file",
        "region",
        "targetCode",
        "eServiceCode",
        "serviceTargetCode",
    }
    for code, value in DEFAULT_SERVICES.items():
        missing = required - value.keys()
        assert not missing, f"У услуги {code} не хватает полей: {missing}"


def test_environments_have_test_and_prod():
    from config import ENVIRONMENTS

    assert "test" in ENVIRONMENTS
    assert "prod" in ENVIRONMENTS
    for name, env in ENVIRONMENTS.items():
        assert env["esia_host"].startswith("https://"), name
        assert env["svcdev_host"].startswith("https://"), name


def test_detect_environment_test():
    from config import detect_environment, ENVIRONMENTS

    assert (
        detect_environment(
            ENVIRONMENTS["test"]["esia_host"],
            ENVIRONMENTS["test"]["svcdev_host"],
        )
        == "test"
    )


def test_detect_environment_prod():
    from config import detect_environment, ENVIRONMENTS

    assert (
        detect_environment(
            ENVIRONMENTS["prod"]["esia_host"],
            ENVIRONMENTS["prod"]["svcdev_host"],
        )
        == "prod"
    )


def test_detect_environment_custom():
    from config import detect_environment

    assert detect_environment("https://example.test", "https://example.test") == "custom"


def test_serialize_service_keeps_code():
    from config import DEFAULT_SERVICES, serialize_service

    code = next(iter(DEFAULT_SERVICES))
    out = serialize_service(code, DEFAULT_SERVICES[code])
    assert out["serviceCode"] == code
    assert "description" in out
    assert "region" in out


def test_spec_version_matches_app_version():
    """SPEC_VERSION в config должен совпадать с версией FastAPI-приложения."""
    from config import SPEC_VERSION

    # Импортируем app только если pycades доступен; иначе пропускаем мягко.
    pytest.importorskip("pycades", reason="pycades недоступен — тест в CI без CSP")
    from app import app  # noqa: WPS433 — поздний импорт ради опциональной зависимости

    assert app.version == SPEC_VERSION


def _make_jwt(payload: dict) -> str:
    """Сформировать JWT без подписи (для теста _decode_jwt_exp)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}."


def test_decode_jwt_exp_valid():
    pytest.importorskip("pycades", reason="pycades недоступен")
    from app import _decode_jwt_exp

    jwt = _make_jwt({"exp": 1893456000, "sub": "test"})
    assert _decode_jwt_exp(jwt) == 1893456000


def test_decode_jwt_exp_missing_field():
    pytest.importorskip("pycades", reason="pycades недоступен")
    from app import _decode_jwt_exp

    jwt = _make_jwt({"sub": "no-exp"})
    assert _decode_jwt_exp(jwt) == 0


def test_decode_jwt_exp_broken_jwt():
    pytest.importorskip("pycades", reason="pycades недоступен")
    from app import _decode_jwt_exp

    assert _decode_jwt_exp("not-a-jwt") == 0
    assert _decode_jwt_exp("") == 0
    assert _decode_jwt_exp("a.b") == 0
