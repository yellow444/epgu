"""Источники сертификатов: папка на диске, вложения из почты, USB-токен.

Оператору не должно быть важно, откуда взялся сертификат. Модуль сводит все
источники к одному виду: список файлов с описанием и кнопка установки.

Про USB честно: контейнер не видит токен. Docker Desktop на Windows не
пробрасывает USB, поэтому здесь мы умеем только показать, что видит КриптоПро
внутри контейнера, и выдать пошаговый гайд для хоста. Если токен пробросили
через usbipd, ридер появится в том же списке сам.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
CSPTEST = "/opt/cprocsp/bin/amd64/csptest"
CPCONFIG = "/opt/cprocsp/sbin/amd64/cpconfig"

CERT_SUFFIXES = {".cer", ".crt", ".der", ".pem", ".p7b", ".p7c"}
CONTAINER_SUFFIXES = {".zip", ".tgz", ".tar", ".gz", ".pfx", ".p12"}

# Хранилища, в которые разрешено ставить. Личные сертификаты в доверенные
# корни не кладём: это отдельная операция и отдельный смысл.
ALLOWED_STORES = {"uMy", "mroot", "uRoot", "mCA"}


def cert_dir() -> Path:
    return Path(os.getenv("CERT_INBOX_DIR", "/var/lib/epgu-mail"))


def keys_dir() -> Path:
    """Каталог ключевых контейнеров КриптоПро.

    Держится отдельно от каталога документов: провайдер ищет контейнеры
    именно здесь, и класть их вперемешку с инструкциями и архивами нельзя.
    """
    return Path(os.getenv("KEYS_DIR", "/var/opt/cprocsp/keys/app"))


def cryptopro_available() -> bool:
    return Path(CERTMGR).exists()


def _run(args: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False
    )


def describe_certificate(path: Path) -> Dict[str, Any]:
    """Что внутри файла сертификата. Без КриптоПро отдаём только размер."""
    info: Dict[str, Any] = {"subject": "", "issuer": "", "thumbprint": "", "valid_to": ""}
    if not cryptopro_available():
        return info
    try:
        result = _run([CERTMGR, "-list", "-file", str(path)])
    except (OSError, subprocess.SubprocessError) as err:
        logger.info("certmgr не смог прочитать файл: %s", type(err).__name__)
        return info
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "subject":
            info["subject"] = value
        elif key == "issuer":
            info["issuer"] = value
        elif key.startswith("sha1"):
            info["thumbprint"] = value
        elif key == "not valid after":
            info["valid_to"] = value
    return info


def scan_folder(folder: Optional[Path] = None) -> Dict[str, Any]:
    """Что лежит в каталоге сертификатов: файлы и ключевые контейнеры."""
    folder = folder or cert_dir()
    files: List[Dict[str, Any]] = []
    containers: List[Dict[str, Any]] = []
    if folder.exists():
        for entry in sorted(folder.iterdir()):
            if entry.is_dir():
                keys = sorted(p.name for p in entry.glob("*.key"))
                if keys:
                    containers.append(
                        {
                            "name": entry.name,
                            "path": str(entry),
                            "keys": keys,
                            "empty": all((entry / k).stat().st_size == 0 for k in keys),
                        }
                    )
                continue
            suffix = entry.suffix.lower()
            if suffix not in CERT_SUFFIXES and suffix not in CONTAINER_SUFFIXES:
                continue
            item: Dict[str, Any] = {
                "name": entry.name,
                "path": str(entry),
                "size": entry.stat().st_size,
                "kind": "certificate" if suffix in CERT_SUFFIXES else "archive",
            }
            if suffix in CERT_SUFFIXES:
                item.update(describe_certificate(entry))
            files.append(item)
    return {
        "folder": str(folder),
        "exists": folder.exists(),
        "files": files,
        "containers": containers,
    }


def import_certificate(path: Path, store: str = "uMy", *, link_container: str = "", pin: str = "") -> Dict[str, Any]:
    """Поставить сертификат в хранилище КриптоПро.

    ``link_container`` связывает сертификат с ключевым контейнером: без этого
    подписать им ничего нельзя. Приложение читает сертификаты из хранилища
    контейнера, поэтому при связке добавляем ``-to-container``.
    """
    if not cryptopro_available():
        raise RuntimeError("В этом образе нет КриптоПро, устанавливать нечем")
    if store not in ALLOWED_STORES:
        raise ValueError("Недопустимое хранилище")
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError("Файл сертификата не найден")

    args = [CERTMGR, "-install", "-store", store, "-file", str(resolved)]
    if link_container:
        # certmgr по умолчанию ищет ключ обмена, у сертификатов подписи его нет.
        args += ["-cont", link_container, "-at_signature", "-to-container"]
        if pin:
            args += ["-pin", pin]
    result = _run(args, timeout=60)
    ok = result.returncode == 0
    logger.info(
        "Установка сертификата в %s: %s", store, "успешно" if ok else "отказ"
    )
    return {
        "installed": ok,
        "store": store,
        "file": resolved.name,
        # Вывод certmgr не содержит секретов: это описание сертификата.
        "output": (result.stdout or result.stderr)[-2000:],
    }


def readers_status() -> Dict[str, Any]:
    """Что КриптоПро видит внутри контейнера: ридеры и ключевые контейнеры."""
    if not cryptopro_available():
        return {"available": False, "readers": [], "containers": [], "tokens": []}
    readers: List[str] = []
    try:
        result = _run([CPCONFIG, "-hardware", "reader", "-view"])
        for line in result.stdout.splitlines():
            if line.strip().lower().startswith("nick name"):
                readers.append(line.split(":", 1)[1].strip())
    except (OSError, subprocess.SubprocessError):
        pass
    containers: List[str] = []
    try:
        result = _run([CSPTEST, "-keyset", "-enum_cont", "-verifyc", "-fqcn"])
        containers = [
            line.strip() for line in result.stdout.splitlines() if line.strip().startswith("\\\\")
        ]
    except (OSError, subprocess.SubprocessError):
        pass
    tokens = [name for name in readers if name.upper() not in {"HDIMAGE"}]
    return {
        "available": True,
        "readers": readers,
        "containers": containers,
        "tokens": tokens,
        "token_visible": bool(tokens),
    }


def usb_guide() -> List[Dict[str, Any]]:
    """Пошаговый гайд для хоста: как достать с токена то, что нужно подписи."""
    return [
        {
            "id": "check-host",
            "title": "Проверить, что токен виден на хосте",
            "text": (
                "КриптоПро на Windows должен видеть носитель. Команда выводит "
                "список ридеров: там появится Rutoken, JaCarta или ESMART."
            ),
            "commands": [
                '"C:\\Program Files (x86)\\Crypto Pro\\CSP\\csptest.exe" -card -enum',
            ],
        },
        {
            "id": "list-containers",
            "title": "Посмотреть контейнеры на токене",
            "text": "Полное имя контейнера понадобится на следующем шаге.",
            "commands": [
                '"C:\\Program Files (x86)\\Crypto Pro\\CSP\\csptest.exe" -keyset -enum_cont -verifyc -fqcn',
            ],
        },
        {
            "id": "install-personal",
            "title": "Поставить личный сертификат из контейнера",
            "text": (
                "Сертификат встанет в личное хранилище пользователя Windows и "
                "свяжется с закрытым ключом на токене."
            ),
            "commands": [
                '"C:\\Program Files (x86)\\Crypto Pro\\CSP\\certmgr.exe" -inst -cont "\\\\.\\Aktiv Rutoken lite\\имя_контейнера"',
            ],
        },
        {
            "id": "export-public",
            "title": "Выгрузить открытую часть в файл",
            "text": (
                "Это единственное, что нужно приложению в контейнере: открытая "
                "часть сертификата. Закрытый ключ остаётся на токене и никуда "
                "не копируется."
            ),
            "commands": [
                '"C:\\Program Files (x86)\\Crypto Pro\\CSP\\certmgr.exe" -export -dest cert.cer -cont "\\\\.\\Aktiv Rutoken lite\\имя_контейнера"',
            ],
        },
        {
            "id": "put-to-folder",
            "title": "Положить файл в папку сертификатов",
            "text": (
                "Дальше приложение справится само: файл появится в списке, "
                "останется нажать установку."
            ),
            "commands": [f"copy cert.cer {cert_dir()}"],
        },
        {
            "id": "signing-limits",
            "title": "Про подпись самим токеном",
            "text": (
                "Подписывать ключом с токена контейнер не сможет: Docker "
                "Desktop на Windows не пробрасывает USB. Варианты: пробросить "
                "устройство через usbipd-win и поднять pcscd в образе, либо "
                "запускать бэкенд на хосте рядом с установленным КриптоПро."
            ),
            "commands": [],
        },
    ]
