"""Настройки, сохранённые оператором из интерфейса.

Переменные окружения задаются при старте контейнера, и чтобы поменять их,
нужно править .env и перезапускать стенд. Для настройки почты это неудобно:
адрес сервера и логин подбираются с нескольких попыток.

Поэтому то, что оператор сохранил из интерфейса, кладётся в файл на томе и
читается при каждом обращении. Такие значения имеют приоритет над окружением:
сохранение из UI это явное действие, оно должно побеждать значение, с которым
контейнер когда-то стартовал.

Файл живёт в томе, поэтому переживает и перезапуск, и пересборку образа. Прав
на него ровно столько, сколько нужно владельцу процесса.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, Iterable, Mapping

logger = logging.getLogger(__name__)

DEFAULT_FILE = "/var/lib/epgu-mail/settings.env"

# Сохранять из интерфейса можно только это. Список закрытый: иначе через
# сохранение настроек можно было бы подменить, например, адрес ЕСИА.
ALLOWED_KEYS = {
    "MAIL_IMAP_HOST",
    "MAIL_IMAP_PORT",
    "MAIL_SMTP_HOST",
    "MAIL_SMTP_PORT",
    "MAIL_USER",
    "MAIL_FROM",
    "MAIL_USE_SSL",
    "MAIL_PASSWORD",
    "IS_MNEMONIC",
    "INBOUND_PUBLIC_URL",
    # Выключатель автоматического забора Госпочты. Хранится здесь, а не только
    # в окружении: включать почту через пересборку контейнера неудобно, а
    # решение это осознанное - чтение запускает процессуальные сроки.
    "GEPS_SCHEDULE_ENABLED",
    # Реквизиты организации: повторяются в каждом письме Оператору, поэтому
    # вводятся один раз и подставляются в шаблоны.
    "ORG_FULL_NAME",
    "ORG_SHORT_NAME",
    "ORG_INN",
    "ORG_OGRN",
    "ORG_OKTMO",
    "ORG_ROLE",
    "CONTACT_NAME",
    "CONTACT_ROLE",
    "CONTACT_PHONE",
    "CONTACT_EMAIL",
}

# Поля реквизитов и плейсхолдеры писем, которые они закрывают.
PROFILE_FIELDS = {
    "ORG_FULL_NAME": ("полное наименование", "наименование организации"),
    "ORG_SHORT_NAME": ("организация",),
    "ORG_INN": ("ИНН",),
    "ORG_OGRN": ("ОГРН",),
    "ORG_OKTMO": ("ОКТМО",),
    "ORG_ROLE": ("вендор / потребитель",),
    "IS_MNEMONIC": ("мнемоника ИС",),
    "CONTACT_NAME": ("ФИО",),
    "CONTACT_ROLE": ("должность",),
    "CONTACT_PHONE": ("телефон",),
    "CONTACT_EMAIL": ("smev@домен организации",),
}

# Значения этих ключей наружу не отдаются никогда.
SECRET_KEYS = {"MAIL_PASSWORD"}

_LINE = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$")


def settings_path() -> Path:
    return Path(os.getenv("SETTINGS_FILE", DEFAULT_FILE))


def load() -> Dict[str, str]:
    path = settings_path()
    if not path.exists():
        return {}
    values: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = _LINE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip()
            if key in ALLOWED_KEYS:
                values[key] = value
    except OSError as err:
        logger.warning("Не удалось прочитать файл настроек: %s", type(err).__name__)
    return values


def get(name: str, default: str = "") -> str:
    """Значение из сохранённых настроек, иначе из окружения."""
    saved = load()
    if name in saved and saved[name] != "":
        return saved[name]
    return os.getenv(name, default)


def save(values: Mapping[str, str]) -> Dict[str, str]:
    """Записать настройки. Пустая строка удаляет значение.

    Возвращает то, что стало записано, без секретов.
    """
    unknown = set(values) - ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Недопустимые ключи настроек: {', '.join(sorted(unknown))}")

    current = load()
    for key, value in values.items():
        if value == "":
            current.pop(key, None)
        else:
            current[key] = str(value).strip()

    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "# Настройки, сохранённые из интерфейса.",
        "# Имеют приоритет над переменными окружения контейнера.",
        "# Файл содержит пароль, поэтому наружу не отдаётся и в git не попадает.",
        "",
    ]
    body += [f"{key}={current[key]}" for key in sorted(current)]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        # На некоторых томах права не выставляются, это не повод падать.
        logger.info("Права на файл настроек выставить не удалось")
    logger.info("Настройки сохранены, ключей: %s", len(current))
    return describe(current)


def clear() -> Dict[str, int]:
    """Удалить все сохранённые настройки вместе с паролем."""
    path = settings_path()
    removed = len(load())
    try:
        path.unlink()
    except FileNotFoundError:
        removed = 0
    logger.info("Настройки сброшены, удалено ключей: %s", removed)
    return {"removed": removed}


def describe(values: Mapping[str, str] | None = None) -> Dict[str, str]:
    """Сохранённые значения для интерфейса, без секретов."""
    values = load() if values is None else values
    result: Dict[str, str] = {}
    for key, value in values.items():
        result[key] = "задан" if key in SECRET_KEYS else value
    return result


def dotenv_fragment(keys: Iterable[str] | None = None) -> str:
    """Кусок .env, чтобы перенести настройки на другую машину.

    Пароль не подставляется: его значение не покидает контейнер.
    """
    saved = load()
    keys = sorted(keys or saved)
    lines = []
    for key in keys:
        if key not in saved:
            continue
        if key in SECRET_KEYS:
            lines.append(f"{key}=<пароль приложения, введите сами>")
        else:
            lines.append(f"{key}={saved[key]}")
    return "\n".join(lines)
