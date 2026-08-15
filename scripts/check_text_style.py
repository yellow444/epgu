#!/usr/bin/env python3
"""Проверить и починить типографику в текстах репозитория.

В проекте принято писать человеческим текстом: дефис вместо длинного тире,
``->`` вместо стрелок, никаких эмодзи, галочек, значков и псевдографики.
Правило легко нарушить незаметно, поэтому оно вынесено в проверяемый вид.

    python scripts/check_text_style.py          проверить и перечислить нарушения
    python scripts/check_text_style.py --fix    исправить на месте

Переводы строк каждого файла сохраняются: клиентские файлы должны остаться в
CRLF, иначе падает сборка CRA, а shell-скрипты в LF, иначе падает контейнер.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    ".md", ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".sh", ".txt", ".html", ".css", ".xml", ".xsd",
    ".template", ".example", ".conf",
}

# Пути, где типографика не наша: чужие лицензии, машинные файлы, снимок
# официальных документов и схемы ведомств. Официальные XSD и XML должны
# оставаться байт в байт такими, какими их опубликовали, даже в описаниях.
SKIPPED_PARTS = (
    "package-lock.json",
    "LICENSE",
    "NOTICE",
    "docs/api_for_gu/",
    "api-gosuslugi-backend/xml/",
    "node_modules/",
)

REPLACEMENTS: List[Tuple[str, str]] = [
    ("—", "-"),      # длинное тире
    ("–", "-"),      # среднее тире
    ("‒", "-"),
    ("―", "-"),
    ("→", "->"),
    ("←", "<-"),
    ("↔", "<->"),
    ("⇒", "=>"),
    ("⇐", "<="),
    ("…", "..."),
    ("•", "-"),      # маркер списка
    ("·", "-"),      # средняя точка
    (" ", " "),      # неразрывный пробел
    (" ", " "),
    (" ", " "),
]

# Значки и галочки удаляются вместе с идущим за ними пробелом.
DROPPED = re.compile(
    "[✓✔✗✘✅❌⚠⛔⭐❗❓"
    "▶◀●■─-╿️​‍]"
    "|[\U0001F000-\U0001FAFF]"
    "|[\U00002600-\U000027BF]"
)


def tracked_files() -> List[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    files = []
    for line in out.splitlines():
        if not line.strip():
            continue
        if any(part in line for part in SKIPPED_PARTS):
            continue
        path = ROOT / line
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.is_file():
            files.append(path)
    return files


def scrub(text: str) -> Tuple[str, Dict[str, int]]:
    found: Dict[str, int] = {}
    for source, target in REPLACEMENTS:
        count = text.count(source)
        if count:
            found[source] = count
            text = text.replace(source, target)
    dropped = DROPPED.findall(text)
    if dropped:
        found["значки"] = len(dropped)
        text = DROPPED.sub("", text)
        # После удаления значка часто остаётся двойной пробел.
        text = re.sub(r"[ \t]{2,}(?=\S)", " ", text)
    return text, found


def process(path: Path, fix: bool) -> Dict[str, int]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    crlf = text.count("\r\n")
    flat = text.replace("\r\n", "\n")
    cleaned, found = scrub(flat)
    if not found or not fix:
        return found
    if crlf:
        cleaned = cleaned.replace("\n", "\r\n")
    path.write_bytes(cleaned.encode("utf-8"))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="исправить файлы на месте")
    args = parser.parse_args()

    dirty = 0
    total = 0
    for path in tracked_files():
        found = process(path, args.fix)
        if not found:
            continue
        dirty += 1
        total += sum(found.values())
        details = ", ".join(f"{name}: {count}" for name, count in found.items())
        rel = path.relative_to(ROOT).as_posix()
        print(f"{rel}: {details}")

    if not dirty:
        print("Типографика в порядке: запрещённых символов нет.")
        return 0
    if args.fix:
        print(f"Исправлено файлов: {dirty}, замен: {total}.")
        return 0
    print(f"Файлов с запрещёнными символами: {dirty}, всего вхождений: {total}.")
    print("Починить: python scripts/check_text_style.py --fix")
    return 1


if __name__ == "__main__":
    sys.exit(main())
