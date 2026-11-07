"""Чтение, поиск и проверка набора знаний (только чтение, без сети)."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import InvalidDataset, KnowledgeError, NotFound
from .limits import (
    DOMAINS, MAX_CURSOR_LEN, MAX_LIMIT, MAX_QUERY_LEN, MIN_LIMIT, OFFICIALITY, SCHEMA_VERSION,
)

_PACKAGE = "epgu_knowledge"
_DATA_RESOURCE = ("data", "knowledge.v1.json")
_SCHEMA_RESOURCE = ("schema", "knowledge.v1.schema.json")

_SNIPPET_LEN = 160

# Вес совпадения по полю.
_WEIGHTS = {"title": 10, "summary": 4, "section": 4, "body": 3, "text": 3, "checks": 2}
_TITLE_PHRASE_BONUS = 5
_SNIPPET_ORDER = ("body", "text", "summary", "section", "checks", "title")


def _norm(text: str) -> str:
    """Регистронезависимая форма с ё == е (длина строки сохраняется)."""
    out = []
    for ch in text:
        if ch in "ёЁ":
            ch = "е"
        low = ch.casefold()
        out.append(low if len(low) == 1 else ch)
    return "".join(out)


def _read_resource(parts: tuple) -> bytes:
    res = resources.files(_PACKAGE)
    for part in parts:
        res = res.joinpath(part)
    return res.read_bytes()


def _canonical_hash(data: Any) -> str:
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _str_or_none(value: Any) -> "str | None":
    """Идентификатор для проверки ссылок: нестроковые значения отмечает схема."""
    return value if isinstance(value, str) else None


class KnowledgeBase:
    """Неизменяемое представление набора знаний. Все ответы - копии."""

    def __init__(self, data: dict) -> None:
        if not isinstance(data, dict):
            raise KnowledgeError("invalid_dataset", "корень набора знаний должен быть объектом")
        self._data = copy.deepcopy(data)
        self._hash = _canonical_hash(self._data)
        self._sources: dict = {}
        self._routes: dict = {}
        self._notes: dict = {}
        for src in _as_list(self._data.get("sources")):
            if isinstance(src, dict) and isinstance(src.get("id"), str):
                self._sources.setdefault(src["id"], src)
        for route in _as_list(self._data.get("routes")):
            if isinstance(route, dict) and isinstance(route.get("id"), str):
                self._routes.setdefault(route["id"], route)
        for note in _as_list(self._data.get("notes")):
            if isinstance(note, dict) and isinstance(note.get("id"), str):
                self._notes.setdefault(note["id"], note)

    # ------------------------------------------------------------------ чтение

    @property
    def content_sha256(self) -> str:
        """Хэш канонического JSON набора: меняется при любом изменении данных."""
        return self._hash

    def dataset(self) -> dict:
        """Весь набор знаний (копия) в формате схемы knowledge.v1."""
        return copy.deepcopy(self._data)

    def meta(self) -> dict:
        nodes = sum(len(_as_list(r.get("nodes"))) for r in self._routes.values())
        return {
            "schema_version": self._data.get("schema_version"),
            "content_sha256": self._hash,
            "dataset": copy.deepcopy(self._data.get("dataset")),
            "counts": {
                "routes": len(self._routes),
                "nodes": nodes,
                "sources": len(self._sources),
                "notes": len(self._notes),
            },
        }

    def list_routes(self) -> list:
        return [
            {
                "id": r.get("id"),
                "title": r.get("title"),
                "summary": r.get("summary"),
                "domain": r.get("domain"),
                "coverage": copy.deepcopy(r.get("coverage")),
                "entry_node": r.get("entry_node"),
                "node_count": len(_as_list(r.get("nodes"))),
            }
            for r in self._routes.values()
        ]

    def get_route(self, route_id: str) -> dict:
        route = self._routes.get(route_id) if isinstance(route_id, str) else None
        if route is None:
            raise NotFound(f"маршрут не найден: {route_id!r}")
        return copy.deepcopy(route)

    def get_node(self, route_id: str, node_id: str) -> dict:
        route = self._routes.get(route_id) if isinstance(route_id, str) else None
        if route is None:
            raise NotFound(f"маршрут не найден: {route_id!r}")
        nodes = [n for n in _as_list(route.get("nodes")) if isinstance(n, dict)]
        node = next((n for n in nodes if n.get("id") == node_id), None)
        if node is None:
            raise NotFound(f"узел не найден: {route_id!r}/{node_id!r}")
        result = copy.deepcopy(node)
        result["incoming"] = [
            {"from": n.get("id"), "label": e.get("label")}
            for n in nodes
            for e in _as_list(n.get("next"))
            if isinstance(e, dict) and e.get("to") == node_id
        ]
        result["sources_resolved"] = [
            copy.deepcopy(self._sources[s])
            for s in _as_list(node.get("sources"))
            if isinstance(s, str) and s in self._sources
        ]
        return result

    def list_sources(self, officiality: "str | None" = None) -> list:
        if officiality is not None and officiality not in OFFICIALITY:
            raise ValueError(f"неизвестное значение officiality: {officiality!r}")
        return [
            copy.deepcopy(s)
            for s in self._sources.values()
            if officiality is None or s.get("officiality") == officiality
        ]

    def get_source(self, source_id: str) -> dict:
        src = self._sources.get(source_id) if isinstance(source_id, str) else None
        if src is None:
            raise NotFound(f"источник не найден: {source_id!r}")
        result = copy.deepcopy(src)
        result["used_by"] = [
            {"route": r.get("id"), "node": n.get("id")}
            for r in self._routes.values()
            for n in _as_list(r.get("nodes"))
            if isinstance(n, dict) and source_id in _as_list(n.get("sources"))
        ]
        return result

    def list_notes(self) -> list:
        return [copy.deepcopy(n) for n in self._notes.values()]

    # ------------------------------------------------------------------ поиск

    def _encode_cursor(self, offset: int, qkey: str) -> str:
        payload = f"{offset}:{self._hash[:16]}:{qkey}"
        check = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]
        return base64.urlsafe_b64encode(f"{payload}:{check}".encode()).rstrip(b"=").decode()

    def _decode_cursor(self, cursor: str, qkey: str) -> int:
        bad = ValueError("недействительный cursor")
        if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_LEN:
            raise bad
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise bad from None
        parts = raw.split(":")
        if len(parts) != 4:
            raise bad
        offset_s, ds, qk, check = parts
        payload = f"{offset_s}:{ds}:{qk}"
        if hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8] != check:
            raise bad
        if ds != self._hash[:16] or qk != qkey:
            raise bad
        if not offset_s.isascii() or not offset_s.isdigit():
            raise bad
        return int(offset_s)

    @staticmethod
    def _snippet(text: str, norm_text: str, tokens: list) -> str:
        pos = min((p for p in (norm_text.find(t) for t in tokens) if p >= 0), default=0)
        start = max(0, pos - _SNIPPET_LEN // 4)
        piece = " ".join(text[start:start + _SNIPPET_LEN].split())
        head = "..." if start > 0 else ""
        tail = "..." if start + _SNIPPET_LEN < len(text) else ""
        return head + piece + tail

    def _match(self, fields: dict, tokens: list, phrase: str):
        """Вернуть (score, snippet) или None. Все токены должны найтись (AND)."""
        normed = {k: [_norm(v) for v in vs] for k, vs in fields.items()}
        score = 0
        for tok in tokens:
            found = False
            for fname, vals in normed.items():
                if any(tok in v for v in vals):
                    found = True
                    score += _WEIGHTS[fname]
            if not found:
                return None
        if any(phrase in v for v in normed.get("title", [])):
            score += _TITLE_PHRASE_BONUS
        snippet = None
        for fname in _SNIPPET_ORDER:
            for orig, nv in zip(fields.get(fname, []), normed.get(fname, [])):
                if any(t in nv for t in tokens):
                    snippet = self._snippet(orig, nv, tokens)
                    break
            if snippet is not None:
                break
        return score, snippet or ""

    def _source_refs(self, refs: Any) -> list:
        """Явные ссылки элемента в порядке набора, без повторов и только известные источники."""
        out: list = []
        for s in _as_list(refs):
            if isinstance(s, str) and s in self._sources and s not in out:
                out.append(s)
        return out

    def search(
        self,
        query: str,
        limit: int = 10,
        cursor: "str | None" = None,
        domain: "str | None" = None,
    ) -> dict:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query не должен быть пустым")
        if len(query) > MAX_QUERY_LEN:
            raise ValueError(f"query длиннее {MAX_QUERY_LEN} символов")
        if isinstance(limit, bool) or not isinstance(limit, int) or not MIN_LIMIT <= limit <= MAX_LIMIT:
            raise ValueError(f"limit должен быть целым от {MIN_LIMIT} до {MAX_LIMIT}")
        if domain is not None and domain not in DOMAINS:
            raise ValueError(f"неизвестный domain: {domain!r}")

        phrase = " ".join(_norm(query).split())
        tokens = phrase.split(" ")
        qkey = hashlib.sha256(f"{phrase}|{domain or ''}".encode()).hexdigest()[:8]
        offset = self._decode_cursor(cursor, qkey) if cursor is not None else 0

        hits: list = []

        def add(kind, route_id, node_id, item_id, title, fields, refs):
            m = self._match(fields, tokens, phrase)
            if m:
                hits.append({
                    "type": kind, "route_id": route_id, "node_id": node_id, "id": item_id,
                    "title": title, "snippet": m[1], "score": m[0],
                    "source_ids": self._source_refs(refs),
                })

        for route in self._routes.values():
            if domain is not None and route.get("domain") != domain:
                continue
            rid = route.get("id")
            # У маршрута в knowledge.v1 нет собственных ссылок на источники.
            add("route", rid, None, rid, route.get("title"),
                {"title": [route.get("title") or ""], "summary": [route.get("summary") or ""]}, [])
            for node in _as_list(route.get("nodes")):
                if not isinstance(node, dict):
                    continue
                add("node", rid, node.get("id"), node.get("id"), node.get("title"), {
                    "title": [node.get("title") or ""],
                    "body": [node.get("body") or ""],
                    "checks": [c for c in _as_list(node.get("checks")) if isinstance(c, str)],
                }, node.get("sources"))
        if domain is None:
            for note in self._notes.values():
                add("note", None, None, note.get("id"), note.get("title"), {
                    "title": [note.get("title") or ""], "text": [note.get("text") or ""],
                }, note.get("sources"))
            for src in self._sources.values():
                add("source", None, None, src.get("id"), src.get("title"), {
                    "title": [src.get("title") or ""], "section": [src.get("section") or ""],
                }, [src.get("id")])

        hits.sort(key=lambda h: (-h["score"], h["type"], h["route_id"] or "", h["id"] or ""))
        if offset > len(hits):
            raise ValueError("недействительный cursor")
        page = hits[offset:offset + limit]
        nxt = self._encode_cursor(offset + limit, qkey) if offset + limit < len(hits) else None
        return {"items": page, "next_cursor": nxt}

    # ------------------------------------------------------------------ проверка

    def validate(self) -> list:
        from jsonschema import Draft202012Validator

        errors: list = []
        schema = json.loads(_read_resource(_SCHEMA_RESOURCE).decode("utf-8"))
        validator = Draft202012Validator(schema)
        for err in sorted(validator.iter_errors(self._data), key=lambda e: list(map(str, e.path))):
            path = "/" + "/".join(str(p) for p in err.path)
            errors.append(f"schema: {path}: {err.message}")

        data = self._data
        # Нестроковые id и ссылки уже попали в ошибки схемы; здесь они пропускаются.
        source_ids: set = set()
        for i, src in enumerate(_as_list(data.get("sources"))):
            sid = _str_or_none(_as_dict(src).get("id"))
            if sid is None:
                continue
            if sid in source_ids:
                errors.append(f"integrity: /sources/{i}: повторный id источника {sid!r}")
            source_ids.add(sid)

        def check_refs(where: str, refs: Any) -> None:
            for s in _as_list(refs):
                s = _str_or_none(s)
                if s is not None and s not in source_ids:
                    errors.append(f"integrity: {where}: неизвестный источник {s!r}")

        seen_routes: set = set()
        for ri, route in enumerate(_as_list(data.get("routes"))):
            route = _as_dict(route)
            rid = _str_or_none(route.get("id"))
            if rid is not None:
                if rid in seen_routes:
                    errors.append(f"integrity: /routes/{ri}: повторный id маршрута {rid!r}")
                seen_routes.add(rid)
            nodes = [_as_dict(n) for n in _as_list(route.get("nodes"))]
            node_ids: set = set()
            for ni, node in enumerate(nodes):
                nid = _str_or_none(node.get("id"))
                if nid is None:
                    continue
                if nid in node_ids:
                    errors.append(f"integrity: /routes/{ri}/nodes/{ni}: повторный id узла {nid!r}")
                node_ids.add(nid)
            entry = _str_or_none(route.get("entry_node"))
            if entry is not None and entry not in node_ids:
                errors.append(
                    f"integrity: /routes/{ri}: entry_node {entry!r} "
                    f"не найден среди узлов маршрута {rid!r}"
                )
            for ni, node in enumerate(nodes):
                for ei, edge in enumerate(_as_list(node.get("next"))):
                    to = _str_or_none(_as_dict(edge).get("to"))
                    if to is not None and to not in node_ids:
                        errors.append(
                            f"integrity: /routes/{ri}/nodes/{ni}/next/{ei}: "
                            f"переход к несуществующему узлу {to!r}"
                        )
                check_refs(f"/routes/{ri}/nodes/{ni}", node.get("sources"))

        seen_notes: set = set()
        for ni, note in enumerate(_as_list(data.get("notes"))):
            note = _as_dict(note)
            nid = _str_or_none(note.get("id"))
            if nid is not None:
                if nid in seen_notes:
                    errors.append(f"integrity: /notes/{ni}: повторный id заметки {nid!r}")
                seen_notes.add(nid)
            check_refs(f"/notes/{ni}", note.get("sources"))
        return errors


_CACHE: dict = {}
_MAX_REPORTED = 20


def load(path: "str | Path | None" = None, *, validate: bool = True) -> KnowledgeBase:
    """Загрузить набор знаний (по умолчанию из данных пакета). Результат кэшируется.

    По умолчанию набор проверяется схемой и ссылочной целостностью; при ошибках
    поднимается ``InvalidDataset`` и повреждённые данные не индексируются.
    ``validate=False`` нужен только для диагностики (например, чтобы получить
    полный список ошибок через ``KnowledgeBase.validate()``).
    Сообщения ошибок не содержат локальных путей.
    """
    if path is None:
        key: tuple = ("package",)

        def raw_loader() -> bytes:
            return _read_resource(_DATA_RESOURCE)
    else:
        p = Path(path).resolve()
        try:
            st = p.stat()
        except OSError as exc:
            raise KnowledgeError("unreadable_dataset", "файл набора знаний недоступен") from exc
        key = (str(p), st.st_mtime_ns, st.st_size)
        raw_loader = p.read_bytes
    entry = _CACHE.get(key)
    if entry is None:
        try:
            data = json.loads(raw_loader().decode("utf-8"))
        except OSError as exc:
            raise KnowledgeError("unreadable_dataset", "файл набора знаний недоступен") from exc
        except (UnicodeDecodeError, ValueError) as exc:
            raise KnowledgeError("invalid_dataset", "набор знаний не является JSON в UTF-8") from exc
        kb = KnowledgeBase(data)
        entry = _CACHE[key] = {"kb": kb, "errors": None}
    kb = entry["kb"]
    if validate:
        if entry["errors"] is None:
            entry["errors"] = _check(kb)
        if entry["errors"]:
            errs = entry["errors"]
            version = kb._data.get("schema_version")
            code = "unsupported_version" if version != SCHEMA_VERSION else "invalid_dataset"
            raise InvalidDataset(code, errs[:_MAX_REPORTED], total=len(errs))
    return kb


def _check(kb: KnowledgeBase) -> list:
    try:
        return kb.validate()
    except Exception as exc:  # проверка не должна пропускать данные из-за собственного сбоя
        return [f"validator: {type(exc).__name__}"]
