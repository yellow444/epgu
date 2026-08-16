# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Сборка ZIP-архива заявления (комплект документов + подписи).

ЕПГУ принимает комплект документов одним ZIP-архивом (``piev_epgu.zip``). Часть
документов нужно сопровождать отсоединённой ГОСТ-подписью - файлом ``<имя>.sig``
рядом с самим документом. Этот модуль избавляет от ручной возни с zip и подписями.
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Union

from .errors import ValidationError
from .signature.base import Signer

BytesLike = Union[bytes, bytearray, str]


def _as_bytes(content: BytesLike) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    return bytes(content)


@dataclass
class _Entry:
    name: str
    content: bytes
    sign: bool


@dataclass
class OrderArchive:
    """Конструктор ZIP-комплекта документов заявления.

    Args:
        signer: подписант для формирования ``.sig`` (необязателен, если ничего
            подписывать не нужно).
        sig_suffix: расширение файла подписи (по умолчанию ``.sig``).

    Example:
        >>> archive = OrderArchive(signer=signer)
        >>> archive.add_file("req.xml", req_xml_bytes)          # без подписи
        >>> archive.add_file("piev_epgu.xml", piev_bytes, sign=True)
        >>> data = archive.to_bytes()
    """

    signer: Optional[Signer] = None
    sig_suffix: str = ".sig"
    _entries: List[_Entry] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.sig_suffix or any(char in self.sig_suffix for char in ("/", "\\", "\x00")):
            raise ValidationError("sig_suffix должен быть непустым расширением без разделителей")

    @staticmethod
    def _validate_name(name: str) -> None:
        normalized = name.replace("\\", "/")
        parts = normalized.split("/")
        if (
            not name
            or "\x00" in name
            or normalized.startswith("/")
            or posixpath.isabs(normalized)
            or any(part in {"", ".", ".."} for part in parts)
            or (len(normalized) >= 2 and normalized[1] == ":")
        ):
            raise ValidationError(f"Недопустимое имя файла в архиве: {name!r}")

    def add_file(self, name: str, content: BytesLike, *, sign: bool = False) -> "OrderArchive":
        """Добавить файл в архив. При ``sign=True`` рядом кладётся ``<name>.sig``."""
        self._validate_name(name)
        if sign and self.signer is None:
            raise ValidationError(f"Для подписи файла {name!r} нужен signer, но он не задан")
        reserved_names = set(self.filenames)
        output_names = {name, name + self.sig_suffix} if sign else {name}
        if reserved_names.intersection(output_names):
            raise ValidationError(f"Файл с именем {name!r} уже добавлен в архив")
        if not sign and any(
            entry.sign and entry.name + self.sig_suffix == name for entry in self._entries
        ):
            raise ValidationError(f"Имя {name!r} уже занято файлом подписи")
        self._entries.append(_Entry(name=name, content=_as_bytes(content), sign=sign))
        return self

    def add_signed_file(self, name: str, content: BytesLike) -> "OrderArchive":
        """Сокращение для :meth:`add_file` с ``sign=True``."""
        return self.add_file(name, content, sign=True)

    @property
    def filenames(self) -> List[str]:
        """Имена файлов, которые попадут в архив (с учётом ``.sig``)."""
        names: List[str] = []
        for entry in self._entries:
            names.append(entry.name)
            if entry.sign:
                names.append(entry.name + self.sig_suffix)
        return names

    def to_bytes(self) -> bytes:
        """Собрать архив и вернуть его содержимое."""
        if not self._entries:
            raise ValidationError("Архив пуст: добавьте хотя бы один файл")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in self._entries:
                zf.writestr(entry.name, entry.content)
                if entry.sign:
                    assert self.signer is not None  # проверено в add_file
                    signature = self.signer.sign(entry.content)
                    zf.writestr(entry.name + self.sig_suffix, signature)
        return buffer.getvalue()

    def size(self) -> int:
        """Размер итогового архива в байтах (полезно для ``chunked``-загрузки)."""
        return len(self.to_bytes())
