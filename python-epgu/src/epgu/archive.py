"""Сборка ZIP-архива заявления (комплект документов + подписи).

ЕПГУ принимает комплект документов одним ZIP-архивом (``piev_epgu.zip``). Часть
документов нужно сопровождать отсоединённой ГОСТ-подписью - файлом ``<имя>.sig``
рядом с самим документом. Этот модуль избавляет от ручной возни с zip и подписями.
"""

from __future__ import annotations

import io
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

    def add_file(self, name: str, content: BytesLike, *, sign: bool = False) -> "OrderArchive":
        """Добавить файл в архив. При ``sign=True`` рядом кладётся ``<name>.sig``."""
        if sign and self.signer is None:
            raise ValidationError(
                f"Для подписи файла {name!r} нужен signer, но он не задан"
            )
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
