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
import re
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


def _backup_keys() -> str:
    """Скопировать каталог ключей перед удалением сертификата.

    certmgr уносит ключевой контейнер вместе с сертификатом, а закрытый ключ
    восстановить неоткуда. Копия стоит копейки и один раз спасает.
    """
    import shutil
    from datetime import datetime, timezone

    source = keys_dir()
    if not source.exists() or not any(source.iterdir()):
        return ""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = cert_dir() / ("keys-backup-" + stamp)
    # Два удаления в одну секунду не должны отнимать друг у друга копию.
    counter = 2
    while target.exists():
        target = cert_dir() / ("keys-backup-%s-%d" % (stamp, counter))
        counter += 1
    try:
        shutil.copytree(source, target)
    except OSError as err:
        logger.warning("Копию ключей сделать не удалось: %s", type(err).__name__)
        return ""
    logger.info("Ключи скопированы перед удалением: %s", target)
    return str(target)


def delete_certificate(
    thumbprint: str,
    *,
    store: str = "uMy",
    containers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Убрать сертификат из хранилищ.

    Хранилищ на самом деле два, и это легко упустить. Обычное хранилище лежит
    в файловой системе контейнера, а приложение читает сертификаты из
    ключевого контейнера.

    Важное, проверенное на стенде: certmgr удаляет сертификат вместе с
    привязанным ключевым контейнером. То есть кнопка "удалить сертификат" в
    придачу уносит закрытый ключ, и вернуть его неоткуда. Поэтому перед
    удалением делаем копию каталога ключей и возвращаем путь к ней: если ключ
    был нужен, его можно положить обратно.
    """
    if not cryptopro_available():
        raise RuntimeError("В этом образе нет КриптоПро, удалять нечем")
    if store not in ALLOWED_STORES:
        raise ValueError("Недопустимое хранилище")
    clean = str(thumbprint or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", clean):
        raise ValueError("Отпечаток должен быть 40 шестнадцатеричными цифрами")

    backup = _backup_keys()
    removed: List[str] = []
    output: List[str] = []

    result = _run([CERTMGR, "-delete", "-store", store, "-thumbprint", clean, "-silent"], timeout=60)
    output.append((result.stdout or result.stderr)[-1000:])
    if result.returncode == 0:
        removed.append(store)

    for container in containers or []:
        result = _run(
            [CERTMGR, "-delete", "-container", container, "-thumbprint", clean, "-silent"],
            timeout=60,
        )
        output.append((result.stdout or result.stderr)[-1000:])
        if result.returncode == 0:
            removed.append(container)

    logger.info(
        "Удаление сертификата %s: очищено мест %d", clean[:8], len(removed)
    )
    return {
        "deleted": bool(removed),
        "removed_from": removed,
        "thumbprint": clean,
        "keys_backup": backup,
        "keys_left": sorted(item.name for item in keys_dir().glob("*.000")) if keys_dir().exists() else [],
        # Вывод certmgr описывает сертификат и не содержит секретов.
        "output": "\n".join(part for part in output if part)[-2000:],
    }


BACKUP_NAME = re.compile(r"^keys-backup-\d{8}-\d{6}(-\d+)?$")


def list_key_backups() -> List[Dict[str, Any]]:
    """Копии каталога ключей, сделанные перед удалением сертификатов."""
    root = cert_dir()
    if not root.exists():
        return []
    backups: List[Dict[str, Any]] = []
    for item in sorted(root.glob("keys-backup-*"), reverse=True):
        if not item.is_dir() or not BACKUP_NAME.match(item.name):
            continue
        containers = []
        for container in sorted(item.glob("*.000")):
            keys = sorted(path.name for path in container.glob("*.key"))
            containers.append({"name": container.name, "keys": keys})
        stamp = item.name.replace("keys-backup-", "")
        backups.append(
            {
                "name": item.name,
                "path": str(item),
                # Метка в имени: 20260821-055659 читается как дата и время UTC.
                "made_at": "%s-%s-%s %s:%s:%s UTC"
                % (
                    stamp[0:4], stamp[4:6], stamp[6:8],
                    stamp[9:11], stamp[11:13], stamp[13:15],
                ),
                "containers": containers,
            }
        )
    return backups


def restore_key_backup(name: str) -> Dict[str, Any]:
    """Вернуть ключевые контейнеры из копии.

    Сертификат живёт внутри контейнера, поэтому вместе с ключами возвращается
    и он: приложение снова видит его в списке. Уже существующие файлы не
    трогаем, чтобы восстановление не затёрло рабочий ключ.
    """
    import shutil

    clean = str(name or "").strip()
    if not BACKUP_NAME.match(clean):
        raise ValueError("Недопустимое имя копии")
    source = cert_dir() / clean
    if not source.is_dir():
        raise ValueError("Копия не найдена")

    restored: List[str] = []
    skipped: List[str] = []
    target_root = keys_dir()
    target_root.mkdir(parents=True, exist_ok=True)
    for container in sorted(source.glob("*.000")):
        target = target_root / container.name
        target.mkdir(parents=True, exist_ok=True)
        for item in sorted(container.glob("*")):
            if not item.is_file():
                continue
            destination = target / item.name
            if destination.exists():
                skipped.append("%s/%s: уже на месте" % (container.name, item.name))
                continue
            try:
                shutil.copy2(item, destination)
            except OSError as err:
                skipped.append("%s/%s: %s" % (container.name, item.name, type(err).__name__))
                continue
            restored.append("%s/%s" % (container.name, item.name))
    logger.info("Восстановление из копии %s: файлов %d", clean, len(restored))
    return {"restored": restored, "skipped": skipped, "backup": clean}


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
