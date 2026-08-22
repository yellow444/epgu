"""Разбор вложений из писем: текст, вложенные файлы, сертификаты.

Поддержка присылает ответы файлами, и это не всегда сертификат. Приходят
инструкции в PDF, документы Word, архивы, а нужное лежит внутри: ключевой
контейнер вложен в документ, сертификат в архиве, а ссылка на тестовый
удостоверяющий центр в тексте.

Открывать это руками означает потерять смысл автоматизации, поэтому здесь
разбор: определить тип, вытащить текст, перечислить вложенные файлы и достать
их на диск. Никаких обращений наружу, только чтение того, что уже сохранено.

Что понимаем:

    PDF     текст постранично, ссылки, вложенные файлы (EmbeddedFile)
    DOCX    текст документа, ссылки, вложения из word/embeddings
    ZIP     список содержимого, извлечение нужного
    CER     сертификат, дальше его показывает и ставит certsources
    KEY     каталог или архив ключевого контейнера

Отдельно предупреждаем про случай, на котором мы сами обожглись: в PDF,
полученном конвертацией из Word, значки вложенных файлов видны, а самих файлов
нет. Тогда честно говорим, что вложений в файле нет, и советуем запросить
исходный документ.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - зависит от сборки образа
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    PdfReader = None

CERT_SUFFIXES = {".cer", ".crt", ".der", ".pem", ".p7b", ".p7c"}
KEY_SUFFIXES = {".key", ".000"}
ARCHIVE_SUFFIXES = {".zip"}
MAX_TEXT = 20000
MAX_EXTRACT_BYTES = 20 * 1024 * 1024

# Файлы ключевого контейнера КриптоПро: шесть имён внутри каталога вида xxx.000.
CONTAINER_FILES = {
    "header.key",
    "masks.key",
    "masks2.key",
    "name.key",
    "primary.key",
    "primary2.key",
}

_LINK_RE = re.compile(r"https?://[^\s<>\"')]+")
_PIN_RE = re.compile(r"(?:ПИН|PIN|пин)[ -]?код[^0-9]{0,12}([0-9]{4,12})")


def guess_kind(name: str) -> str:
    """Что это за файл по одному имени, без чтения содержимого.

    Нужно для вложений в письмах: файл ещё лежит на почтовом сервере, а
    показать оператору, сертификат это или архив, нужно уже сейчас.
    """
    base = str(name).replace("\\", "/").split("/")[-1]
    lowered = base.lower()
    if lowered in CONTAINER_FILES or Path(lowered).suffix in KEY_SUFFIXES:
        return "key"
    suffix = Path(lowered).suffix
    if suffix in CERT_SUFFIXES:
        return "certificate"
    if suffix in ARCHIVE_SUFFIXES:
        return "archive"
    if suffix == ".pdf":
        return "pdf"
    if suffix in {".docx", ".doc"}:
        return "docx"
    return "unknown"


def kind_of(path: Path) -> str:
    """Что это за файл. Смотрим и на расширение, и на первые байты."""
    suffix = path.suffix.lower()
    if suffix in CERT_SUFFIXES:
        return "certificate"
    if suffix in KEY_SUFFIXES:
        return "key"
    try:
        head = path.open("rb").read(8)
    except OSError:
        return "unknown"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        # docx, xlsx и обычный архив снаружи выглядят одинаково.
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
        except zipfile.BadZipFile:
            return "archive"
        if any(name.startswith("word/") for name in names):
            return "docx"
        return "archive"
    if head.startswith(b"0\x82") or head.startswith(b"-----BEGIN"):
        return "certificate"
    return "unknown"


# ---------- PDF ----------


def _pdf_streams(data: bytes) -> List[bytes]:
    """Развернуть потоки PDF. Нам нужен только текст, без верстки."""
    streams = []
    for match in re.finditer(rb"stream\r?\n", data):
        start = match.end()
        end = data.find(b"endstream", start)
        if end == -1:
            continue
        chunk = data[start:end]
        try:
            streams.append(zlib.decompress(chunk))
        except zlib.error:
            streams.append(chunk)
    return streams


def _pdf_text(data: bytes) -> str:
    """Текст из PDF.

    Основной путь - pypdf: он читает ToUnicode и отдаёт кириллицу как есть.
    Запасной путь разбирает строковые литералы сам и годится хотя бы на
    ссылки: в PDF со шрифтами собственной кодировки он даёт мусор вместо
    русского текста, и это надо помнить.
    """
    if PdfReader is not None:
        try:
            reader = PdfReader(io.BytesIO(data))
            pages = [page.extract_text() or "" for page in reader.pages]
            text = "\n".join(pages).strip()
            if text:
                return re.sub(r"[ \t]+", " ", text)
        except Exception:  # чужой файл, причин сломаться много
            pass
    return _pdf_text_fallback(data)


def _pdf_text_fallback(data: bytes) -> str:
    pieces: List[str] = []
    for stream in _pdf_streams(data):
        for match in re.finditer(rb"\((?:\\.|[^()\\])*\)", stream, re.S):
            raw = match.group(0)[1:-1]
            raw = raw.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\", b"\\")
            try:
                text = raw.decode("utf-16-be") if b"\x00" in raw else raw.decode("cp1251")
            except (UnicodeDecodeError, LookupError):
                continue
            if text.strip():
                pieces.append(text)
        for match in re.finditer(rb"<([0-9A-Fa-f\s]+)>\s*Tj", stream):
            hex_text = re.sub(rb"\s", b"", match.group(1))
            if len(hex_text) % 4:
                continue
            try:
                pieces.append(bytes.fromhex(hex_text.decode("ascii")).decode("utf-16-be"))
            except (ValueError, UnicodeDecodeError):
                continue
    text = " ".join(pieces)
    return re.sub(r"[ \t]+", " ", text).strip()


def _pdf_embedded(data: bytes) -> List[Dict[str, Any]]:
    """Вложенные в PDF файлы. Их может не быть, даже если видны значки."""
    if PdfReader is not None:
        try:
            reader = PdfReader(io.BytesIO(data))
            named = getattr(reader, "attachments", None) or {}
            if named:
                return [
                    {"name": name, "size": sum(len(item) for item in payloads)}
                    for name, payloads in named.items()
                ]
        except Exception:
            pass
    found: List[Dict[str, Any]] = []
    for match in re.finditer(rb"/EmbeddedFile", data):
        start = data.find(b"stream", match.end())
        if start == -1:
            continue
        start = data.find(b"\n", start) + 1
        end = data.find(b"endstream", start)
        payload = data[start:end]
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            pass
        found.append({"name": "embedded-%d" % (len(found) + 1), "size": len(payload)})
    return found


def _pdf_pages(data: bytes) -> int:
    counts = [int(value) for value in re.findall(rb"/Count\s+(\d+)", data)]
    return max(counts) if counts else data.count(b"/Type/Page") or 0


# ---------- документы Word и архивы ----------


def _zip_entries(path: Path) -> List[Dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        return [
            {"name": item.filename, "size": item.file_size}
            for item in archive.infolist()
            if not item.is_dir()
        ]


def _docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        try:
            xml = archive.read("word/document.xml").decode("utf-8", "replace")
        except KeyError:
            return ""
    xml = re.sub(r"</w:p>", "\n", xml)
    text = re.sub(r"<[^>]+>", "", xml)
    return re.sub(r"[ \t]+", " ", text).strip()


def _docx_embedded(path: Path) -> List[Dict[str, Any]]:
    """Вложения документа Word.

    Именно здесь лежат ключевые контейнеры, которые пропадают при печати
    документа в PDF: word/embeddings хранит их как объекты OLE.
    """
    entries = []
    for item in _zip_entries(path):
        name = item["name"]
        if name.startswith("word/embeddings/") or name.startswith("word/media/"):
            entries.append(item)
    return entries


# ---------- разбор и извлечение ----------


def describe(path: Path) -> Dict[str, Any]:
    """Что внутри файла. Ничего не меняет на диске."""
    path = Path(path)
    if not path.is_file():
        return {"exists": False}

    kind = kind_of(path)
    result: Dict[str, Any] = {
        "exists": True,
        "name": path.name,
        "path": str(path),
        "size": path.stat().st_size,
        "kind": kind,
        "text": "",
        "links": [],
        "entries": [],
        "hints": [],
    }

    if kind == "pdf":
        data = path.read_bytes()
        result["pages"] = _pdf_pages(data)
        result["text"] = _pdf_text(data)[:MAX_TEXT]
        embedded = _pdf_embedded(data)
        result["entries"] = embedded
        if not embedded and re.search(r"\.000|контейнер", result["text"], re.I):
            result["hints"].append(
                "В тексте упоминаются ключевые контейнеры, но вложенных файлов в PDF нет. "
                "Так бывает после печати документа Word в PDF: значки видны, файлы теряются. "
                "Запросите у отправителя исходный документ."
            )
    elif kind == "docx":
        result["text"] = _docx_text(path)[:MAX_TEXT]
        result["entries"] = _docx_embedded(path)
        if result["entries"]:
            result["hints"].append(
                "В документе есть вложенные объекты, их можно извлечь на диск."
            )
    elif kind == "archive":
        result["entries"] = _zip_entries(path)
        certificates = [item for item in result["entries"]
                        if Path(item["name"]).suffix.lower() in CERT_SUFFIXES]
        containers = [item for item in result["entries"]
                      if Path(item["name"]).name.lower() in CONTAINER_FILES]
        if certificates:
            result["hints"].append(
                "В архиве есть сертификаты: %s" % ", ".join(item["name"] for item in certificates)
            )
        if containers:
            result["hints"].append(
                "В архиве есть ключевой контейнер КриптоПро, его надо распаковать "
                "в каталог ключей, а не в общую папку."
            )
    elif kind == "certificate":
        result["hints"].append("Это сертификат, его можно установить в хранилище.")
    elif kind == "key":
        result["hints"].append(
            "Похоже на часть ключевого контейнера. Контейнер это каталог из шести "
            "файлов, копируйте его целиком."
        )

    text = result["text"]
    if text:
        links = []
        for link in _LINK_RE.findall(text):
            link = link.rstrip(".,;")
            if link not in links:
                links.append(link)
        result["links"] = links[:40]
        pins = _PIN_RE.findall(text)
        if pins:
            result["hints"].append("В тексте указан ПИН: %s" % ", ".join(sorted(set(pins))))
    return result


def _pdf_attachments(data: bytes) -> List[Dict[str, Any]]:
    """Вложенные в PDF файлы вместе с содержимым, а не только именами."""
    if PdfReader is None:
        return []
    try:
        reader = PdfReader(io.BytesIO(data))
        named = getattr(reader, "attachments", None) or {}
    except Exception:
        return []
    found: List[Dict[str, Any]] = []
    for name, payloads in named.items():
        for payload in payloads:
            found.append({"name": str(name), "data": payload})
    return found


def extract(
    path: Path,
    target_dir: Path,
    *,
    only: Optional[List[str]] = None,
    keys_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Достать вложенные файлы на диск.

    Имена внутри архива приходят снаружи, поэтому каждое приводим к простому
    имени: путь из архива в файловую систему попасть не должен.

    Ключевой контейнер раскладывается отдельно. Это каталог из шести файлов, и
    рассыпать его по общей папке значит получить нерабочий закрытый ключ, о
    чём разбор сам предупреждает при осмотре архива.
    """
    path = Path(path)
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    kind = kind_of(path)
    extracted: List[Dict[str, Any]] = []
    skipped: List[str] = []

    if kind == "pdf":
        # Контейнер и сертификат присылают вложением в инструкцию, и до сих
        # пор кнопка "Извлечь" на таком файле возвращала отказ.
        found = _pdf_attachments(path.read_bytes())
        if not found:
            return {
                "extracted": [],
                "skipped": [
                    "В этом PDF вложенных файлов нет. Если значки видны, документ "
                    "напечатали из Word и вложения потерялись, запросите исходник."
                ],
            }
        for item in found:
            safe = _safe_name(item["name"])
            if not safe:
                skipped.append("%s: небезопасное имя" % item["name"])
                continue
            destination = _place(target_dir, keys_dir, safe, "")
            destination.write_bytes(item["data"])
            extracted.append(
                {"name": destination.name, "source": item["name"], "size": len(item["data"]),
                 "path": str(destination), "kind": kind_of(destination)}
            )
        return {"extracted": extracted, "skipped": skipped}

    if kind not in {"archive", "docx"}:
        return {"extracted": [], "skipped": ["Извлекать нечего: файл не архив и не документ"]}

    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            if only and item.filename not in only:
                continue
            if item.file_size > MAX_EXTRACT_BYTES:
                skipped.append("%s: больше %d байт" % (item.filename, MAX_EXTRACT_BYTES))
                continue
            safe = _safe_name(item.filename)
            if not safe:
                skipped.append("%s: небезопасное имя" % item.filename)
                continue
            payload = archive.read(item)
            # Каталог контейнера внутри архива сохраняем: по нему провайдер
            # и находит ключ.
            parent = str(item.filename).replace("\\", "/").split("/")[-2:-1]
            destination = _place(target_dir, keys_dir, safe, parent[0] if parent else "")
            destination.write_bytes(payload)
            extracted.append(
                {"name": destination.name, "source": item.filename, "size": len(payload),
                 "path": str(destination), "kind": kind_of(destination)}
            )
    return {"extracted": extracted, "skipped": skipped}


def _place(target_dir: Path, keys_dir: Optional[Path], name: str, parent: str) -> Path:
    """Куда положить извлечённый файл: к документам или к ключам."""
    if keys_dir is not None and name.lower() in CONTAINER_FILES:
        container = _safe_name(parent) or "container.000"
        if not container.endswith(".000"):
            container = container + ".000"
        folder = Path(keys_dir) / container
    else:
        folder = target_dir
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / name
    counter = 1
    while destination.exists():
        destination = folder / ("%s-%d%s" % (Path(name).stem, counter, Path(name).suffix))
        counter += 1
    return destination


def _safe_name(name: str) -> str:
    base = str(name).replace("\\", "/").split("/")[-1]
    base = re.sub(r'[\x00-\x1f<>:"|?*]', "_", base).strip().strip(". ")
    if base in ("", ".", ".."):
        return ""
    return base[:150]
