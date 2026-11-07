"""HTTP-адаптер tools операций к backend установки (mock-only срез).

Tools ``plan_prepare``, ``plan_get`` и ``plan_execute`` из ``targets.py``
ходят в backend только через ``epgu.integration.IntegrationClient`` (клиент
4a). Штатные профили и CLI их не выдают: спецификации ставит
``ToolRegistry.install_operations`` в явно собранный реестр operate, например
``build_operate_registry`` в тестах на mock backend.

Конфигурация процесса задаёт адрес backend и путь к файлу с ключом
интеграции, но не сам ключ. Файл читается на каждом вызове tool, не при
импорте, сборке сервера или list_tools. Ключ не бывает аргументом tool, частью
URL, repr, журнала или результата; ошибки чтения не показывают содержимое.
Адрес backend проверяется уже при создании конфигурации по правилам клиента
4a: userinfo, query и fragment отклоняются, текст ошибки адрес не повторяет,
repr показывает только схему, хост и порт.

Ответ backend не выдаётся как есть. Проекция явно копирует поля плана,
предпросмотра и журнала шагов. Свободный результат исполнителя проходит только
в описанных для возможности плоских полях (``ResultProjection``); остальное
отмечается в ``withheld``. Ссылки шагов по умолчанию тоже не выдаются: их
несекретность обеспечивает исполнитель, проверка формата не DLP.

Повторов нет. Неизвестный исход execute определяется по типу исключения
``OutcomeUnknown`` и уходит как ошибка ``outcome_unknown`` с исходным plan_id;
списки вызовов остаются null, если частичный результат неизвестен. Скрытого
plan_get и одобрения нет: одобряет человек по сессии в интерфейсе.
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from epgu.integration import (
    ExecuteResult,
    IntegrationClient,
    IntegrationConfigError,
    OutcomeUnknown,
    Plan,
    ProblemError,
    TransportError,
    UnexpectedResponse,
    _check_base_url,
)
from jsonschema import Draft202012Validator

from .registry import ToolError, ToolSpec
from .targets import TARGET_TOOLS

BACKEND_URL_ENV = "EPGU_MCP_BACKEND_URL"
CREDENTIAL_FILE_ENV = "EPGU_MCP_CREDENTIAL_FILE"
LOOPBACK_HTTP_ENV = "EPGU_MCP_ALLOW_LOOPBACK_HTTP"
TIMEOUT_ENV = "EPGU_MCP_BACKEND_TIMEOUT"

_CREDENTIAL_RE = re.compile(r"[\x21-\x7e]{16,4096}")
_CREDENTIAL_FILE_MAX = 8192
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_REFERENCE_RE = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
_RESULT_STR_MAX = 256
_REDACTED = "***"


class OperationsConfigError(Exception):
    """Конфигурация адаптера неверна. Текст не содержит значения ключа."""


@dataclass(frozen=True)
class ResultProjection:
    """Какие поля результата исполнителя возможности выдаются через MCP.

    ``fields``: имя поля и тип значения (str, bool или int). Поле другого типа,
    вложенный объект и неописанное поле не выдаются. ``step_references``:
    выдавать ли ссылки шагов журнала (номер, идентификатор сообщения).
    """

    fields: Mapping[str, type]
    step_references: bool = False

    def __post_init__(self) -> None:
        for name, kind in self.fields.items():
            if not _NAME_RE.fullmatch(name) or kind not in (str, bool, int):
                raise OperationsConfigError(f"проекция: поле {name[:64]!r} не описано как str, bool или int")


@dataclass(frozen=True)
class OperationsConfig:
    """Адрес backend и путь к файлу ключа интеграции. Самого ключа здесь нет."""

    base_url: str
    credential_file: Path
    allow_loopback_http: bool = False
    timeout: float = 30.0
    projections: Mapping[str, ResultProjection] = field(default_factory=dict)
    # Транспорт httpx для тестов на in-process backend.
    transport: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url:
            raise OperationsConfigError(f"нужен адрес backend ({BACKEND_URL_ENV})")
        # Те же правила, что у клиента 4a, но до любой диагностики. Тексты его
        # ошибок адрес не содержат; разбор порта и прочие сбои urlsplit глушатся.
        try:
            _check_base_url(self.base_url, self.allow_loopback_http is True)
            parts = urlsplit(self.base_url)
            host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
            origin = f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port is not None else "")
        except IntegrationConfigError as exc:
            raise OperationsConfigError(f"{BACKEND_URL_ENV}: {exc}") from None
        except ValueError:
            raise OperationsConfigError(f"{BACKEND_URL_ENV}: адрес не разбирается") from None
        object.__setattr__(self, "_origin", origin)
        if not isinstance(self.credential_file, Path) or not self.credential_file.is_absolute():
            raise OperationsConfigError(f"нужен абсолютный путь к файлу ключа ({CREDENTIAL_FILE_ENV})")
        if not 0 < float(self.timeout) <= 300:
            raise OperationsConfigError("timeout: от 0 до 300 секунд")

    @property
    def origin(self) -> str:
        """Схема, хост и порт backend: без пути, его можно показывать в диагностике."""
        return self._origin  # type: ignore[attr-defined]

    def __repr__(self) -> str:
        # Сырой base_url не показывается: в пути могло оказаться что угодно.
        return (f"OperationsConfig(origin={self.origin!r}, credential_file={str(self.credential_file)!r}, "
                f"allow_loopback_http={self.allow_loopback_http!r}, timeout={self.timeout!r})")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, **extra: Any) -> OperationsConfig:
        """Из переменных окружения: адрес, путь к файлу ключа, loopback http и timeout."""
        env = os.environ if environ is None else environ
        raw_timeout = env.get(TIMEOUT_ENV, "30")
        try:
            timeout = float(raw_timeout)
        except ValueError:
            raise OperationsConfigError(f"{TIMEOUT_ENV}: нужно число секунд") from None
        path = env.get(CREDENTIAL_FILE_ENV, "")
        return cls(
            base_url=env.get(BACKEND_URL_ENV, ""),
            credential_file=Path(path) if path else Path(),
            allow_loopback_http=env.get(LOOPBACK_HTTP_ENV, "") == "1",
            timeout=timeout,
            **extra,
        )


def _inside_git(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in path.parents)


def read_credential(path: Path) -> str:
    """Ключ из файла. Ошибка называет причину, но не содержимое файла."""
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise OperationsConfigError("файл ключа: не обычный файл")
        if _inside_git(resolved):
            raise OperationsConfigError("файл ключа: лежит в рабочем каталоге Git")
        if os.name == "posix" and info.st_mode & 0o077:
            raise OperationsConfigError("файл ключа: доступ шире владельца (нужно 0600)")
        if info.st_size > _CREDENTIAL_FILE_MAX:
            raise OperationsConfigError("файл ключа: слишком большой")
        data = resolved.read_bytes()
    except OSError as exc:
        raise OperationsConfigError(f"файл ключа не прочитан ({type(exc).__name__})") from None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise OperationsConfigError("файл ключа: не ASCII") from None
    text = text.rstrip("\r\n")
    if not _CREDENTIAL_RE.fullmatch(text):
        raise OperationsConfigError("файл ключа: содержимое не похоже на ключ интеграции")
    return text


class _Bad(Exception):
    """Ответ backend не укладывается в проекцию."""


def _str(value: Any) -> str:
    if not isinstance(value, str):
        raise _Bad
    return value


def _nstr(value: Any) -> str | None:
    return None if value is None else _str(value)


def _int(value: Any) -> int:
    if type(value) is not int:
        raise _Bad
    return value


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise _Bad
    return value


def _strs(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise _Bad
    return [_str(v) for v in value]


def _name(value: Any) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise _Bad
    return value


def _obj(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Bad
    return value


def _decode(value: str, where: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ToolError("invalid_parameter", f"{where}: не base64") from None


class OperationsAdapter:
    """Handlers tools операций. Сеть и файл ключа только внутри вызова."""

    def __init__(self, config: OperationsConfig) -> None:
        if not isinstance(config, OperationsConfig):
            raise TypeError("ожидается OperationsConfig")
        self.config = config
        self._tools = {t.name: t for t in TARGET_TOOLS}
        self._outputs = {t.name: Draft202012Validator(t.output_schema) for t in TARGET_TOOLS}

    def __repr__(self) -> str:
        return f"OperationsAdapter(origin={self.config.origin!r})"

    # --- handlers -------------------------------------------------------

    def prepare(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = _decode(args["payload_b64"], "payload_b64")
        attachments = [
            (item["name"], _decode(item["content_b64"], f"attachments.{i}.content_b64"))
            for i, item in enumerate(args.get("attachments", []))
        ]

        def call(api: IntegrationClient) -> dict[str, Any]:
            plan = api.prepare_plan(args["capability_id"], args["target"], payload,
                                    idempotency_key=args["idempotency_key"], attachments=attachments)
            return {**self._plan(plan), "created": _bool(plan.created)}

        return self._run("plan_prepare", call)

    def get(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._run("plan_get", lambda api: self._plan(api.get_plan(args["plan_id"])))

    def execute(self, args: dict[str, Any]) -> dict[str, Any]:
        def call(api: IntegrationClient) -> dict[str, Any]:
            done: ExecuteResult = api.execute_plan(args["plan_id"], args["plan_hash"])
            if done.plan_id != args["plan_id"] or done.status != "succeeded":
                raise _Bad
            return {"plan_id": done.plan_id, "status": "succeeded",
                    "withheld": ["result"] if done.result is not None else []}

        return self._run("plan_execute", call)

    # --- вызов ----------------------------------------------------------

    def _run(self, tool: str, call: Callable[[IntegrationClient], dict[str, Any]]) -> dict[str, Any]:
        try:
            credential = read_credential(self.config.credential_file)
        except OperationsConfigError as exc:
            raise ToolError("configuration_error", str(exc)) from None
        try:
            api = IntegrationClient(self.config.base_url, credential, timeout=self.config.timeout,
                                    allow_insecure_http=self.config.allow_loopback_http,
                                    transport=self.config.transport)
        except IntegrationConfigError as exc:
            raise ToolError("configuration_error", self._safe(str(exc), credential)) from None
        try:
            try:
                data = call(api)
            # OutcomeUnknown наследует ProblemError: проверяется первым и по типу,
            # а не по code (у транспортного сбоя code равен transport_error).
            except OutcomeUnknown as exc:
                raise self._unknown(exc, credential) from None
            except ProblemError as exc:
                code = exc.code if exc.code in self._tools[tool].error_codes else "unexpected_response"
                raise ToolError(code, self._safe(str(exc), credential)) from None
            except TransportError as exc:
                raise ToolError("transport_error", self._safe(str(exc), credential),
                                {"may_have_reached_server": exc.may_have_reached_server}) from None
            except UnexpectedResponse as exc:
                raise ToolError("unexpected_response", self._safe(str(exc), credential)) from None
            except IntegrationConfigError as exc:
                raise ToolError("invalid_parameter", self._safe(str(exc), credential)) from None
            except _Bad:
                raise ToolError("unexpected_response", "ответ backend не укладывается в проекцию") from None
        finally:
            api.close()
        # Неполный или неожиданный ответ не выдаётся за успех.
        if not self._outputs[tool].is_valid(data):
            raise ToolError("unexpected_response", "ответ backend не укладывается в проекцию")
        if credential in json.dumps(data, ensure_ascii=False):
            raise ToolError("unexpected_response", "ответ backend содержит ключ интеграции")
        return data

    @staticmethod
    def _safe(text: str, credential: str) -> str:
        return text.replace(credential, _REDACTED)[:300]

    def _unknown(self, exc: OutcomeUnknown, credential: str) -> ToolError:
        completed = uncertain = None
        if exc.partial_known:
            calls = (*(exc.completed_calls or ()), *(exc.uncertain_calls or ()))
            if all(isinstance(c, str) and _NAME_RE.fullmatch(c) for c in calls):
                completed, uncertain = list(exc.completed_calls or ()), list(exc.uncertain_calls or ())
        reason = exc.code if isinstance(exc.code, str) and _NAME_RE.fullmatch(exc.code) else "unrecognized_code"
        return ToolError(
            "outcome_unknown",
            "исход исполнения неизвестен: внешняя операция могла выполниться. Повтора нет; "
            "сверить состояние через plan_get, execute снова не вызывать",
            {"plan_id": exc.plan_id, "reason": reason, "http_status": exc.status,
             "detail": self._safe(exc.detail or "", credential),
             "completed_calls": completed, "uncertain_calls": uncertain},
        )

    # --- проекция -------------------------------------------------------

    def _plan(self, plan: Plan) -> dict[str, Any]:
        preview = _obj(plan.preview)
        calls = [{"name": _name(c.get("name")), "side_effects": _strs(c.get("side_effects"))}
                 for c in map(_obj, _strs_list(preview.get("external_calls")))]
        names = {c["name"] for c in calls}
        context = _obj(preview.get("context"))
        policy = _obj(preview.get("target_policy"))
        capability_id = _str(preview.get("capability_id"))
        projection = self.config.projections.get(capability_id)
        withheld: list[str] = []

        steps = []
        for raw in map(_obj, _strs_list(plan.steps)):
            name = _name(raw.get("name"))
            if name not in names:
                raise _Bad
            reference = _nstr(raw.get("reference"))
            if reference is not None and not (projection and projection.step_references
                                              and _REFERENCE_RE.fullmatch(reference)):
                reference = None
                if "step_references" not in withheld:
                    withheld.append("step_references")
            steps.append({"name": name, "state": _str(raw.get("state")), "reference": reference,
                          "started_at": _str(raw.get("started_at")),
                          "finished_at": _nstr(raw.get("finished_at"))})

        result, hidden = self._result(plan, projection, names)
        if hidden:
            withheld.insert(0, "result")
        return {
            "plan_id": _str(plan.plan_id),
            "plan_hash": _str(plan.plan_hash),
            "status": _str(plan.status),
            "expires_at": _str(plan.expires_at),
            "preview": {
                "capability_id": capability_id,
                "target": _str(preview.get("target")),
                "payload_sha256": _str(preview.get("payload_sha256")),
                "payload_size": _int(preview.get("payload_size")),
                "attachments": [
                    {"name": _str(a.get("name")), "sha256": _str(a.get("sha256")), "size": _int(a.get("size"))}
                    for a in map(_obj, _strs_list(preview.get("attachments")))
                ],
                "context": {
                    "contour": _str(context.get("contour")),
                    "organization_ref": _str(context.get("organization_ref")),
                    "is_ref": _nstr(context.get("is_ref")),
                    "certificate_thumbprint": _str(context.get("certificate_thumbprint")),
                    "generation": _int(context.get("generation")),
                    "binding_epoch": _int(context.get("binding_epoch")),
                },
                "external_calls": calls,
                "target_policy": {
                    "capability_id": _str(policy.get("capability_id")),
                    "effect": _str(policy.get("effect")),
                    "implemented": _bool(policy.get("implemented")),
                    "machine": _str(policy.get("machine")),
                    "mcp_profile": _str(policy.get("mcp_profile")),
                    "scopes": _strs(policy.get("scopes")),
                    "gates": _strs(policy.get("gates")),
                    "side_effects": _strs(policy.get("side_effects")),
                },
            },
            "result": result,
            "error_code": _nstr(plan.error_code),
            "steps": steps,
            "withheld": withheld,
        }

    @staticmethod
    def _result(plan: Plan, projection: ResultProjection | None,
                names: set[str]) -> tuple[dict[str, Any] | None, bool]:
        """(результат для MCP, скрыто ли что-то из результата backend)."""
        raw = plan.result
        if raw is None:
            return None, False
        raw = _obj(raw)
        if plan.status in ("failed", "unknown"):
            # Журнал вызовов, который backend собирает сам из шагов плана.
            journal: dict[str, Any] = {}
            for key in ("completed_calls", "uncertain_calls"):
                if key in raw:
                    items = _strs(raw[key])
                    if not all(i in names for i in items):
                        return None, True
                    journal[key] = items
            return journal, bool(set(raw) - set(journal))
        if plan.status != "succeeded" or projection is None:
            return None, True
        out: dict[str, Any] = {}
        for key, value in raw.items():
            kind = projection.fields.get(key)
            if kind is not None and type(value) is kind and not (
                    kind is str and len(value) > _RESULT_STR_MAX):
                out[key] = value
        return out, len(out) != len(raw)


def _strs_list(value: Any) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise _Bad
    return list(value)


def operation_specs(adapter: OperationsAdapter) -> list[ToolSpec]:
    """ToolSpec операций: схемы, профиль и аннотации из каталога, handler из адаптера."""
    handlers = {"plan_prepare": adapter.prepare, "plan_get": adapter.get, "plan_execute": adapter.execute}
    return [
        ToolSpec(
            name=t.name, title=t.title, description=t.description,
            input_schema=copy.deepcopy(t.input_schema), output_schema=copy.deepcopy(t.output_schema),
            handler=handlers[t.name], profile=t.profile, read_only=t.read_only,
            destructive=t.destructive, idempotent=t.idempotent, open_world=t.open_world,
            blocking=True,
        )
        for t in TARGET_TOOLS
    ]


def build_operate_registry(kb: Any, adapter: OperationsAdapter) -> Any:
    """Явно собранный реестр operate: справочные tools и операции на этом адаптере.

    Не используется CLI и штатным ``build_registry``. В этом срезе только для
    тестового сервера на mock backend.
    """
    from .server import build_registry

    registry = build_registry("operate", kb)
    registry.install_operations(adapter)
    return registry
