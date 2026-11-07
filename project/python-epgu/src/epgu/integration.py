# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Клиент планов операций НАШЕГО backend по ключу интеграции.

Это не клиент Госуслуг. :class:`~epgu.client.EpguClient` ходит в upstream
gusmev с маркером ЕСИА; :class:`IntegrationClient` ходит только на явно
заданный ``base_url`` установки backend и передаёт ключ интеграции в
``Authorization: Bearer``. Модель ошибок и авторизации своя.

Методы только машинные: ``prepare_plan``, ``get_plan``, ``execute_plan``.
Одобрения здесь нет и не будет: одобряет человек по сессии в интерфейсе
установки.

Правила транспорта:

- свой ``httpx.Client``: без cookie, без переменных окружения и ``.netrc``
  (``trust_env=False``), без перехода по редиректам. Ответ 3xx это ошибка
  :class:`UnexpectedResponse`, ключ на другой адрес не уходит;
- ключ не попадает в URL, ``repr``, текст исключений и журнал;
- ``http://`` допускается только явно, ``allow_insecure_http=True``, и только
  для loopback: ``localhost``, ``*.localhost``, ``127.0.0.0/8``, ``[::1]``.
  Удалённый адрес по ``http://`` не принимается ни с каким флагом;
- ``timeout`` это таймауты httpx на connect, read, write и pool. Read
  действует на каждое ожидание данных из сети, а не на весь ответ, поэтому
  общего срока на запрос нет, в отличие от JS-клиента. Дополнительно, если
  от начала запроса прошло больше ``timeout``, чтение прерывается на
  ближайшей РАСКОДИРОВАННОЙ порции тела. Сжатое тело может долго не давать
  ни одной такой порции, и тогда это ограничение срабатывает позже.
  Любая из этих ошибок у execute даёт :class:`OutcomeUnknown` без повтора;
- ответ проверяется по контракту: ``plan_id`` совпадает с запрошенным,
  поля нужных типов, статус из известного набора. Ответ execute 200 без
  ``status="succeeded"`` нашего плана это :class:`OutcomeUnknown`;
- известный ключ вырезается из всех полей ошибки: ``code``, ``title``,
  ``detail``, ``errors`` и списков ``outcome``. Сырое тело сервера к ошибке
  не прикрепляется;
- повторов нет ни по таймауту, ни по 5xx. После обрыва ``execute_plan``
  нельзя считать, что сервер план не принял: это :class:`OutcomeUnknown`
  без списков вызовов.

Пример::

    with IntegrationClient("https://epgu.example/api", key) as api:
        plan = api.prepare_plan("svc.send", "target-1", payload,
                                idempotency_key="order-42-v1")
        # ... человек проверяет и одобряет план в интерфейсе установки ...
        done = api.execute_plan(plan.plan_id, plan.plan_hash)
"""

from __future__ import annotations

import base64
import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple, Type
from urllib.parse import urlsplit

import httpx

from .const import USER_AGENT
from .errors import EpguError

PLANS_PATH = "/v1/operations/plans"
PROBLEM_MEDIA_TYPE = "application/problem+json"

_PLAN_ID_RE = re.compile(r"plan_[0-9a-f]{32}")
_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PLAN_STATUSES = frozenset(("planned", "approved", "inflight", "succeeded", "failed",
                            "unknown"))
_SUCCEEDED = "succeeded"
_CREDENTIAL_RE = re.compile(r"[\x21-\x7e]{16,4096}")
_REDACTED = "***"


# ---------- ошибки ----------


class IntegrationError(EpguError):
    """Базовая ошибка клиента backend. Текст безопасно показывать и писать в журнал."""


class IntegrationConfigError(IntegrationError):
    """Неверный ``base_url``, ключ или аргумент; запрос не отправлялся."""


class TransportError(IntegrationError):
    """Ответа нет: сеть, таймаут, TLS.

    ``may_have_reached_server`` честно говорит, мог ли запрос дойти. Для
    prepare повтор с тем же ``idempotency_key`` безопасен и решается
    вызывающим; для execute вместо этой ошибки поднимается
    :class:`OutcomeUnknown`.
    """

    def __init__(self, message: str, *, may_have_reached_server: bool) -> None:
        super().__init__(message)
        self.may_have_reached_server = may_have_reached_server


class UnexpectedResponse(IntegrationError):
    """Ответ не по контракту: редирект, не JSON, не problem+json у ошибки."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class ProblemError(IntegrationError):
    """Ответ backend в формате problem+json (RFC 9457).

    Attributes:
        status: код HTTP.
        code: машинный код ошибки (``plan_expired``, ``policy_changed``...).
        title, detail: тексты сервера.
        errors: подробности проверки тела (422), если есть.
    """

    def __init__(self, status: int, code: str, title: str, detail: str,
                 errors: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        super().__init__("%s %s: %s" % (status, code, detail or title))
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.errors = tuple(errors or ())


class InvalidRequest(ProblemError):
    """400 и 422: тело или параметр не того вида."""


class Unauthenticated(ProblemError):
    """401: ключ неверный, отозван или истёк."""


class Forbidden(ProblemError):
    """403: у ключа нет нужного права (``insufficient_scope``)."""


class PlanNotFound(ProblemError):
    """404: плана нет или он чужой."""


class Conflict(ProblemError):
    """409: контекст, хеш, состояние плана, политика или идемпотентность."""


class PlanExpired(ProblemError):
    """410: срок плана истёк."""


class ServiceUnavailable(ProblemError):
    """503: исполнитель не настроен или операция не допускается к исполнению."""


class OutcomeUnknown(ProblemError):
    """Исход execute неизвестен. Повтор не выполняется: нужна ручная сверка.

    ``completed_calls`` и ``uncertain_calls`` берутся только из поля
    ``outcome`` ответа сервера (502). Если сервер его не прислал или ответа
    не было вовсе, оба равны ``None``: частичный результат неизвестен, и это
    не то же самое, что пустые списки. ``status`` равен ``None``, если
    ответа не было.
    """

    def __init__(self, plan_id: str, *, status: Optional[int], code: str, title: str,
                 detail: str, completed_calls: Optional[Tuple[str, ...]] = None,
                 uncertain_calls: Optional[Tuple[str, ...]] = None) -> None:
        super().__init__(status or 0, code, title, detail)
        self.status = status  # type: ignore[assignment]
        self.plan_id = plan_id
        self.completed_calls = completed_calls
        self.uncertain_calls = uncertain_calls

    @property
    def partial_known(self) -> bool:
        return self.completed_calls is not None and self.uncertain_calls is not None


_BY_STATUS: Dict[int, Type[ProblemError]] = {
    400: InvalidRequest,
    401: Unauthenticated,
    403: Forbidden,
    404: PlanNotFound,
    409: Conflict,
    410: PlanExpired,
    422: InvalidRequest,
    503: ServiceUnavailable,
}


# ---------- ответы ----------


@dataclass(frozen=True)
class Plan:
    """План операции, как его отдаёт backend (``PlanOut``)."""

    plan_id: str
    plan_hash: str
    status: str
    expires_at: str
    preview: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    steps: Tuple[Dict[str, Any], ...] = ()
    # True для нового плана (201), False для повтора по ключу идемпотентности (200),
    # None для get_plan.
    created: Optional[bool] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class ExecuteResult:
    plan_id: str
    status: str
    result: Optional[Dict[str, Any]] = None


# ---------- клиент ----------


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_base_url(base_url: Any, allow_insecure_http: bool) -> str:
    if not isinstance(base_url, str) or not base_url:
        raise IntegrationConfigError("base_url: нужен адрес backend установки")
    parts = urlsplit(base_url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise IntegrationConfigError("base_url: нужен абсолютный адрес https://")
    if parts.scheme == "http" and not allow_insecure_http:
        raise IntegrationConfigError(
            "base_url: http:// только явно, allow_insecure_http=True для разработки")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise IntegrationConfigError(
            "base_url: http:// только для loopback (localhost, 127.0.0.0/8, ::1)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise IntegrationConfigError("base_url: без учётных данных, query и fragment")
    return base_url.rstrip("/")


def _check_plan_id(plan_id: Any) -> str:
    if not isinstance(plan_id, str) or not _PLAN_ID_RE.fullmatch(plan_id):
        raise IntegrationConfigError("plan_id: ожидается plan_ и 32 hex-символа")
    return plan_id


class IntegrationClient:
    """Машинный клиент планов операций backend установки.

    Args:
        base_url: адрес backend, например ``https://epgu.example/api``.
        credential: секрет ключа интеграции. Хранится только в памяти объекта.
        timeout: таймауты httpx (connect, read, write, pool), секунды. Не общий
            срок запроса, см. описание модуля.
        allow_insecure_http: разрешить ``http://`` на loopback для локальной
            разработки. Удалённый адрес по ``http://`` не принимается.
        transport: транспорт ``httpx`` для тестов. Клиент ``httpx`` при этом
            всё равно свой: чужая cookie-сессия и чужие заголовки не наследуются.
    """

    def __init__(self, base_url: str, credential: str, *, timeout: float = 30.0,
                 allow_insecure_http: bool = False,
                 transport: Optional[httpx.BaseTransport] = None) -> None:
        self.base_url = _check_base_url(base_url, allow_insecure_http)
        if not isinstance(credential, str) or not _CREDENTIAL_RE.fullmatch(credential):
            raise IntegrationConfigError("credential: нужен секрет ключа интеграции")
        self._credential = credential
        self._timeout = float(timeout)
        self._client = httpx.Client(
            timeout=timeout, follow_redirects=False, trust_env=False, transport=transport,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    def __repr__(self) -> str:
        return "IntegrationClient(base_url=%r)" % self.base_url

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "IntegrationClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- методы ---------------------------------------------------------

    def prepare_plan(self, capability_id: str, target: str, payload: bytes, *,
                     idempotency_key: str,
                     attachments: Sequence[Tuple[str, bytes]] = ()) -> Plan:
        """Подготовить план. Исполнитель не вызывается, план ждёт одобрения человеком.

        Повтор с тем же ``idempotency_key`` и тем же телом возвращает тот же
        план (``created=False``). Ключ при повторе менять нельзя: так
        появится второй план.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise IntegrationConfigError("payload: нужны байты")
        body = {
            "capability_id": capability_id,
            "target": target,
            "payload_b64": base64.b64encode(bytes(payload)).decode("ascii"),
            "attachments": [
                {"name": name, "content_b64": base64.b64encode(bytes(content)).decode("ascii")}
                for name, content in attachments
            ],
            "idempotency_key": idempotency_key,
        }
        response = self._send("POST", PLANS_PATH, body)
        data = self._json(response, (200, 201))
        return self._plan(data, created=response.status_code == 201, plan_id=None)

    def get_plan(self, plan_id: str) -> Plan:
        """Свой план со статусом, результатом и журналом шагов."""
        path = "%s/%s" % (PLANS_PATH, _check_plan_id(plan_id))
        return self._plan(self._json(self._send("GET", path), (200,)), created=None,
                          plan_id=plan_id)

    def execute_plan(self, plan_id: str, plan_hash: str) -> ExecuteResult:
        """Исполнить одобренный план. Повтора нет ни при каком исходе.

        Raises:
            OutcomeUnknown: 502 или нет ответа. Сверьте план через
                :meth:`get_plan`; ошибка этого чтения не отменяет неизвестный исход.
        """
        path = "%s/%s/execute" % (PLANS_PATH, _check_plan_id(plan_id))
        try:
            response = self._send("POST", path, {"plan_hash": plan_hash})
        except TransportError as err:
            raise OutcomeUnknown(
                plan_id, status=None, code="transport_error",
                title="Ответ на execute не получен",
                detail="%s; сервер мог принять запрос, повтор не выполняется" % err,
            ) from None
        status = response.status_code
        if status == 200:
            # Успех только наш: тот же plan_id, status=succeeded, result объект
            # или null. Иначе исход неизвестен, ответ не доказывает исполнение.
            try:
                data = self._json(response, (200,))
            except UnexpectedResponse:
                data = {}
            result = data.get("result")
            if (data.get("plan_id") == plan_id and data.get("status") == _SUCCEEDED
                    and (result is None or isinstance(result, dict))):
                return ExecuteResult(plan_id=plan_id, status=_SUCCEEDED, result=result)
        if status == 502:
            raise self._unknown(plan_id, response)
        # Отказ до исполнения бывает только по контракту: 4xx или 503 с problem+json.
        # Всё остальное (500, 504 прокси, редирект, чужое тело) не доказывает, что
        # сервер план не исполнил.
        if 400 <= status < 500 or status == 503:
            try:
                self._problem_body(response)
            except UnexpectedResponse:
                pass
            else:
                self._json(response, (200,))
        raise OutcomeUnknown(plan_id, status=status, code="unexpected_response",
                             title="Ответ на execute не по контракту",
                             detail="ответ %s; сервер мог исполнить план, повтор не "
                                    "выполняется" % status)

    # --- транспорт ------------------------------------------------------

    def _send(self, method: str, path: str, body: Optional[Dict[str, Any]] = None
              ) -> httpx.Response:
        headers = {"Authorization": "Bearer " + self._credential}
        # httpx сохраняет Set-Cookie ответов; ключ интеграции cookie не пользуется.
        self._client.cookies.clear()
        request = self._client.build_request(method, self.base_url + path, json=body,
                                             headers=headers)
        request.headers.pop("Cookie", None)
        # Таймауты httpx действуют на каждую операцию чтения, а не на весь ответ.
        # Сверх них: проверка прошедшего времени между раскодированными порциями
        # тела. Это не общий срок: декодер может долго не выдавать ни одной порции.
        deadline = time.monotonic() + self._timeout
        try:
            streamed = self._client.send(request, stream=True)
            try:
                chunks = []
                for chunk in streamed.iter_bytes():
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise TransportError("таймаут чтения ответа",
                                             may_have_reached_server=True)
            finally:
                streamed.close()
                self._client.cookies.clear()
            # Тело уже раскодировано iter_bytes: заголовки сжатия и длины не переносятся.
            kept = [(k, v) for k, v in streamed.headers.multi_items()
                    if k.lower() not in ("content-encoding", "content-length")]
            return httpx.Response(streamed.status_code, headers=kept,
                                  content=b"".join(chunks), request=request)
        except httpx.TimeoutException as err:
            reached = not isinstance(err, (httpx.ConnectTimeout, httpx.PoolTimeout))
            raise TransportError("таймаут запроса (%s)" % type(err).__name__,
                                 may_have_reached_server=reached) from None
        except httpx.ConnectError:
            raise TransportError("нет соединения с backend",
                                 may_have_reached_server=False) from None
        except httpx.TransportError as err:
            raise TransportError("ошибка транспорта (%s)" % type(err).__name__,
                                 may_have_reached_server=True) from None

    def _clean(self, text: Any) -> str:
        value = text if isinstance(text, str) else ""
        return value.replace(self._credential, _REDACTED)

    def _code(self, code: str) -> str:
        """Машинный код сервера, только если это код, а не произвольный текст."""
        if self._credential in code or not _CODE_RE.fullmatch(code):
            return "unrecognized_code"
        return code

    def _scrub(self, value: Any, depth: int = 0) -> Any:
        """Копия подробностей 422 без ключа: только JSON-значения, строки очищены."""
        if depth > 8:
            return None
        if isinstance(value, str):
            return self._clean(value)
        if isinstance(value, dict):
            return {self._clean(str(k)): self._scrub(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub(item, depth + 1) for item in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return None

    def _errors(self, errors: Any) -> Tuple[Dict[str, Any], ...]:
        if not isinstance(errors, list):
            return ()
        return tuple(self._scrub(item) for item in errors if isinstance(item, dict))

    def _problem_body(self, response: httpx.Response) -> Dict[str, Any]:
        media = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if media != PROBLEM_MEDIA_TYPE:
            raise UnexpectedResponse(
                "ответ %s без problem+json" % response.status_code, status=response.status_code)
        try:
            data = response.json()
        except ValueError:
            raise UnexpectedResponse("problem+json не разбирается",
                                     status=response.status_code) from None
        if not isinstance(data, dict) or not isinstance(data.get("code"), str):
            raise UnexpectedResponse("problem+json без code", status=response.status_code)
        return data

    def _json(self, response: httpx.Response, ok: Tuple[int, ...]) -> Dict[str, Any]:
        status = response.status_code
        if 300 <= status < 400:
            raise UnexpectedResponse("редирект %s не выполняется" % status, status=status)
        if status not in ok:
            data = self._problem_body(response)
            kind = _BY_STATUS.get(status, ProblemError)
            raise kind(status, self._code(data["code"]), self._clean(data.get("title")),
                       self._clean(data.get("detail")), self._errors(data.get("errors")))
        try:
            data = response.json()
        except ValueError:
            raise UnexpectedResponse("ответ %s не JSON" % status, status=status) from None
        if not isinstance(data, dict):
            raise UnexpectedResponse("ответ %s не объект" % status, status=status)
        return data

    def _unknown(self, plan_id: str, response: httpx.Response) -> OutcomeUnknown:
        try:
            data = self._problem_body(response)
        except UnexpectedResponse:
            return OutcomeUnknown(plan_id, status=502, code="outcome_unknown",
                                  title="Результат внешней операции неизвестен",
                                  detail="ответ 502 не по контракту")
        completed = uncertain = None
        outcome = data.get("outcome")
        if isinstance(outcome, dict) and outcome.get("plan_id") == plan_id:
            done, open_ = outcome.get("completed_calls"), outcome.get("uncertain_calls")
            if (isinstance(done, list) and isinstance(open_, list)
                    and all(isinstance(item, str) for item in done + open_)):
                completed = tuple(self._clean(item) for item in done)
                uncertain = tuple(self._clean(item) for item in open_)
        return OutcomeUnknown(plan_id, status=502, code=self._code(data["code"]),
                              title=self._clean(data.get("title")),
                              detail=self._clean(data.get("detail")),
                              completed_calls=completed, uncertain_calls=uncertain)

    @staticmethod
    def _plan(data: Dict[str, Any], *, created: Optional[bool], plan_id: Optional[str]) -> Plan:
        """План по контракту ``PlanOut``. ``plan_id`` для get: ответ о том же плане."""

        def bad(what: str) -> UnexpectedResponse:
            return UnexpectedResponse("план не по контракту: %s" % what, status=200)

        got = data.get("plan_id")
        if not isinstance(got, str) or not _PLAN_ID_RE.fullmatch(got):
            raise bad("plan_id")
        if plan_id is not None and got != plan_id:
            raise bad("plan_id не тот, что запрошен")
        for key in ("plan_hash", "expires_at"):
            if not isinstance(data.get(key), str) or not data[key]:
                raise bad(key)
        if data.get("status") not in _PLAN_STATUSES:
            raise bad("status")
        if not isinstance(data.get("preview"), dict):
            raise bad("preview")
        result, error_code = data.get("result"), data.get("error_code")
        if result is not None and not isinstance(result, dict):
            raise bad("result")
        if error_code is not None and not isinstance(error_code, str):
            raise bad("error_code")
        steps = data.get("steps", [])
        if not isinstance(steps, list) or not all(
                isinstance(s, dict) and isinstance(s.get("name"), str)
                and isinstance(s.get("state"), str) for s in steps):
            raise bad("steps")
        return Plan(
            plan_id=got, plan_hash=data["plan_hash"], status=data["status"],
            expires_at=data["expires_at"], preview=data["preview"], result=result,
            error_code=error_code, steps=tuple(steps), created=created, raw=data,
        )
