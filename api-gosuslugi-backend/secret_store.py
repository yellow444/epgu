"""Источник секретов для бэкенда.

Сейчас секреты берутся из переменных окружения: на стенде и в разработке это
достаточно и привычно. В проде так нельзя, поэтому доступ к секретам с самого
начала идёт через одну функцию: чтобы перейти на мастер-пароль или на внешнее
хранилище, достаточно добавить провайдер здесь, не трогая остальной код.

Правила, которые не должны нарушаться ни одним провайдером:

- значение секрета никогда не возвращается наружу через API;
- значение секрета никогда не попадает в логи, включая сообщения об ошибках;
- наружу отдаётся только факт наличия и длина.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

# Провайдер по умолчанию. Переключается переменной SECRET_PROVIDER, когда
# появится реализация с мастер-паролем.
PROVIDER_ENV = "env"
PROVIDER_MASTER_PASSWORD = "master-password"

_runtime_overrides: Dict[str, str] = {}


def provider_name() -> str:
    return os.getenv("SECRET_PROVIDER", PROVIDER_ENV).strip().lower() or PROVIDER_ENV


def get_secret(name: str, default: str = "") -> str:
    """Вернуть секрет. Значение не логируется и не отдаётся в API."""
    if name in _runtime_overrides:
        return _runtime_overrides[name]
    if provider_name() == PROVIDER_MASTER_PASSWORD:
        # Место для провайдера с мастер-паролем. Пока его нет, честно падаем,
        # а не делаем вид, что секрет прочитан.
        raise RuntimeError(
            "Провайдер секретов с мастер-паролем ещё не реализован; "
            "уберите SECRET_PROVIDER или задайте значение в окружении"
        )
    # Сохранённое из интерфейса важнее того, с чем стартовал контейнер.
    import settings_store

    return settings_store.get(name, default)


def set_runtime_secret(name: str, value: Optional[str]) -> None:
    """Задать секрет на время жизни процесса, не записывая его на диск.

    Нужен для операторского сценария: ввести пароль в UI и не хранить его
    нигде. При перезапуске контейнера значение теряется, это ожидаемо.
    """
    if value:
        _runtime_overrides[name] = value
    else:
        _runtime_overrides.pop(name, None)


def clear_runtime_secrets() -> None:
    _runtime_overrides.clear()


def describe(name: str) -> Dict[str, object]:
    """Безопасное описание секрета для UI: есть или нет, откуда и какой длины.

    Источник называется честно: оператор должен понимать, что именно
    подействует, если он поменяет .env или сохранит настройки из интерфейса.
    """
    import settings_store

    if name in _runtime_overrides:
        source = "память процесса"
    elif name in settings_store.load():
        source = "сохранено из интерфейса"
    else:
        source = "окружение"
    value = get_secret(name) if provider_name() == PROVIDER_ENV else ""
    return {
        "name": name,
        "configured": bool(value),
        "length": len(value),
        "source": source,
    }
