"""Реестр возможностей (capabilities) публичного ядра.

Декларативное описание того, что умеет ядро, с эффектом каждой операции и
профилем MCP, в котором её разрешено показывать. Реестр только описывает:
он ничего не исполняет и не даёт прав. Private-модули дополняют его через
``register``; повтор идентификатора это ошибка.

На этапе 1 ``mcp_profile`` равен ``knowledge`` только у справочных
возможностей, всё внешнее имеет ``none`` (решается на этапе 2).
"""

import dataclasses
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Effect(str, Enum):
    KNOWLEDGE = "knowledge"
    READ_LOCAL = "read_local"
    WRITE_LOCAL = "write_local"
    READ_EXTERNAL = "read_external"
    WRITE_EXTERNAL = "write_external"
    ADMIN = "admin"


class McpProfile(str, Enum):
    KNOWLEDGE = "knowledge"
    READ = "read"
    OPERATE = "operate"
    NONE = "none"


# Эффекты, которые нельзя отдавать в профили knowledge и read.
_DANGEROUS_EFFECTS = frozenset({Effect.WRITE_EXTERNAL, Effect.ADMIN})
_SAFE_PROFILES = frozenset({McpProfile.KNOWLEDGE, McpProfile.READ})

# Разрешения ключей интеграций (integration_auth.SCOPES берёт набор отсюда).
# Нет ни "admin", ни "*": ключ интеграции не может стать администратором.
# Набор живёт здесь, чтобы реестр не импортировал integration_auth (он тянет
# базу учётных записей, а реестр загружается и без приложения).
SCOPES = frozenset(
    {
        "knowledge:read",
        "local:read",
        "external:read",
        "local:write",
        "external:prepare",
        "external:execute",
    }
)
# Разрешения только на чтение: побочные эффекты за ними недопустимы.
READ_SCOPES = frozenset({"knowledge:read", "local:read", "external:read"})

# Условия допуска машины (gates). Каждое известное условие либо проверяется
# кодом ядра в machine_api.require_machine, либо пока только запланировано.
# BASE_MACHINE_GATES проверяются для любого enforced-маршрута, и enforced
# обязан их объявить. is_bound добавляет требование ИС в контексте ключа.
BASE_MACHINE_GATES = (
    "integration_credential",
    "operator_binding",
    "certificate_match",
    "contour_match",
    "context_match",
)
# Условия плана внешней операции: prepare только записывает план (plan_record),
# а исполнение допускается лишь при всех условиях PLAN_GATES. Их проверяет
# operations.py: одобрение человеком, целостность плана, версия привязки и
# атомарный захват исполнения.
PLAN_GATES = ("human_approval", "plan_integrity", "binding_epoch", "execution_claim")
ENFORCED_GATES = frozenset({*BASE_MACHINE_GATES, "is_bound", "plan_record", *PLAN_GATES})
# Где условия плана действительно проверяются: возможность, её маршрут и
# допустимые на нём условия плана.
PLAN_ROUTES = {
    "operation.prepare": (("POST /v1/operations/plans",), frozenset({"plan_record"})),
    "operation.execute": (
        ("POST /v1/operations/plans/{plan_id}/execute",), frozenset(PLAN_GATES)),
}
# Известные, но не подключённые условия: допустимы только при machine none или
# target. Условия private-модулей сюда не входят: пока для них нет явно
# подключённого обработчика, их имя неизвестно и объявление отклоняется.
PLANNED_GATES = frozenset({"esia_token", "selected_certificate", "membership", "license"})
GATES = ENFORCED_GATES | PLANNED_GATES

# Побочные эффекты операции, которые надо учитывать до допуска машины.
SIDE_EFFECTS = frozenset(
    {"legal_effect", "external_write", "marks_read", "consumes_quota", "reserves_number"}
)
# Режим машинного доступа: none - нет, target - целевой (ещё не включён),
# enforced - маршрут проверяет ключ интеграции и контекст оператора.
MACHINE_MODES = ("none", "target", "enforced")


@dataclass(frozen=True)
class Capability:
    id: str
    title: str
    effect: Effect
    api: Tuple[str, ...] = ()
    ui: Optional[str] = None
    implemented: bool = True
    edition: str = "public"
    mcp_profile: McpProfile = McpProfile.NONE
    requires: Tuple[str, ...] = ("login",)
    notes: str = ""
    scopes: Tuple[str, ...] = ()
    gates: Tuple[str, ...] = ()
    side_effects: Tuple[str, ...] = ()
    machine: str = "none"

    def __post_init__(self) -> None:
        # Допускаем строки и списки на входе (удобно для private-модулей),
        # но храним неизменяемые значения.
        object.__setattr__(self, "effect", Effect(self.effect))
        object.__setattr__(self, "mcp_profile", McpProfile(self.mcp_profile))
        object.__setattr__(self, "api", tuple(self.api))
        object.__setattr__(self, "requires", tuple(self.requires))
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "gates", tuple(self.gates))
        object.__setattr__(self, "side_effects", tuple(self.side_effects))
        if not self.id or not self.title:
            raise ValueError("у возможности должны быть id и title")
        if self.effect in _DANGEROUS_EFFECTS and self.mcp_profile in _SAFE_PROFILES:
            raise ValueError(
                f"{self.id}: эффект {self.effect.value} нельзя отдавать в профиль "
                f"{self.mcp_profile.value}"
            )
        for scope in self.scopes:
            if scope not in SCOPES:
                raise ValueError(f"{self.id}: неизвестное разрешение {scope!r}")
        for effect in self.side_effects:
            if effect not in SIDE_EFFECTS:
                raise ValueError(f"{self.id}: неизвестный побочный эффект {effect!r}")
        for gate in self.gates:
            if gate not in GATES:
                raise ValueError(f"{self.id}: неизвестное условие допуска {gate!r}")
        if self.machine not in MACHINE_MODES:
            raise ValueError(f"{self.id}: неизвестный режим machine {self.machine!r}")
        if self.side_effects:
            if self.mcp_profile in _SAFE_PROFILES:
                raise ValueError(
                    f"{self.id}: операцию с побочными эффектами нельзя отдавать в профиль "
                    f"{self.mcp_profile.value}"
                )
            # Пустые scopes это операция без машинного доступа (старый UI):
            # её побочные эффекты описываются, прав ключам это не даёт.
            if self.scopes and set(self.scopes) <= READ_SCOPES:
                raise ValueError(
                    f"{self.id}: побочные эффекты несовместимы с разрешениями только на чтение"
                )
        if self.machine != "none" and not self.scopes:
            raise ValueError(f"{self.id}: для машинного доступа нужны разрешения (scopes)")
        if self.effect is Effect.ADMIN and self.machine != "none":
            raise ValueError(f"{self.id}: административная операция недоступна машине")
        if self.machine == "enforced":
            check_enforced(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "effect": self.effect.value,
            "api": list(self.api),
            "ui": self.ui,
            "implemented": self.implemented,
            "edition": self.edition,
            "mcp_profile": self.mcp_profile.value,
            "requires": list(self.requires),
            "notes": self.notes,
            "scopes": list(self.scopes),
            "gates": list(self.gates),
            "side_effects": list(self.side_effects),
            "machine": self.machine,
        }


def check_enforced(cap: Capability) -> None:
    """Правила enforced: объявление должно совпадать с тем, что проверяет ядро.

    Fail-closed: неизвестное или ещё не подключённое условие, ложный
    ``implemented`` и опасная операция дают ошибку объявления, а не допуск.
    machine_api.require_machine повторяет эту проверку при сборке маршрута.
    """
    if not cap.implemented:
        raise ValueError(f"{cap.id}: enforced требует implemented=True")
    if not cap.api:
        raise ValueError(f"{cap.id}: enforced требует маршрут API")
    missing = [gate for gate in BASE_MACHINE_GATES if gate not in cap.gates]
    if missing:
        raise ValueError(f"{cap.id}: enforced должен объявить базовые условия {missing}")
    unsupported = sorted(set(cap.gates) - ENFORCED_GATES)
    if unsupported:
        raise ValueError(f"{cap.id}: условия {unsupported} ядро ещё не проверяет")
    # Изменяющая операция допускается только вместе с доказанными условиями
    # плана. Операция с побочными эффектами или внешней записью должна объявить
    # все PLAN_GATES; локальная запись без побочных эффектов только
    # записывает план и требует plan_record.
    declared = set(cap.gates)
    # Условия плана проверяет только конвейер operations.py на своих маршрутах.
    # Объявить их на другом маршруте (в том числе из private) нельзя: такое
    # объявление ничего бы не доказывало.
    plan_declared = declared & {"plan_record", *PLAN_GATES}
    if plan_declared:
        allowed = PLAN_ROUTES.get(cap.id)
        if allowed is None or cap.api != allowed[0] or not plan_declared <= allowed[1]:
            raise ValueError(
                f"{cap.id}: условия плана {sorted(plan_declared)} проверяются только на "
                "встроенных маршрутах плана"
            )
    if cap.side_effects or cap.effect is Effect.WRITE_EXTERNAL:
        absent = [gate for gate in PLAN_GATES if gate not in declared]
        if absent:
            raise ValueError(
                f"{cap.id}: изменяющая операция должна объявить условия плана {absent}"
            )
    elif cap.effect is Effect.WRITE_LOCAL and "plan_record" not in declared:
        raise ValueError(f"{cap.id}: локальная запись допустима только с условием plan_record")


# Возможности, у которых логика есть только в UI и API нет (этап 2).
UI_ONLY = frozenset({"manual.letter.compose", "xml.fill_profile"})
_UI_ONLY_NOTE = "только в UI, API нет (этап 2)"

_K = Effect.KNOWLEDGE
_RL = Effect.READ_LOCAL
_WL = Effect.WRITE_LOCAL
_XR = Effect.READ_EXTERNAL
_XW = Effect.WRITE_EXTERNAL
_AD = Effect.ADMIN
_KN = McpProfile.KNOWLEDGE


def _c(id, title, effect, api=(), ui=None, requires=("login",), notes="",
       implemented=True, mcp_profile=McpProfile.NONE, scopes=(), gates=(),
       side_effects=(), machine="none") -> Capability:
    return Capability(
        id=id, title=title, effect=effect, api=tuple(api), ui=ui,
        implemented=implemented, mcp_profile=mcp_profile,
        requires=tuple(requires), notes=notes, scopes=tuple(scopes), gates=tuple(gates),
        side_effects=tuple(side_effects), machine=machine,
    )


_ADMIN = ("login", "installation_admin")
_TOKEN = ("login", "esia_token")
_TOKEN_CERT = ("login", "esia_token", "selected_certificate")

_BUILTIN: Tuple[Capability, ...] = (
    # Справочные данные (этап 1, профиль MCP knowledge). Открыты без входа:
    # статические публичные знания, бюджет запросов public_budget.
    _c("knowledge.overview", "Сведения о наборе знаний", _K, ["GET /v1/knowledge"],
       requires=(), mcp_profile=_KN),
    _c("knowledge.dataset", "Весь набор знаний для интерфейса", _K, ["GET /v1/knowledge/dataset"],
       ui="IntegrationGuide", requires=(), mcp_profile=McpProfile.NONE,
       notes="обновление встроенной копии UI; ETag = content_sha256"),
    _c("knowledge.routes", "Маршруты подключения", _K,
       ["GET /v1/knowledge/routes", "GET /v1/knowledge/routes/{route_id}"],
       ui="IntegrationGuide", requires=(), mcp_profile=_KN),
    _c("knowledge.nodes", "Узлы маршрута", _K,
       ["GET /v1/knowledge/routes/{route_id}/nodes/{node_id}"], ui="IntegrationGuide",
       requires=(), mcp_profile=_KN),
    _c("knowledge.sources", "Источники и официальность", _K,
       ["GET /v1/knowledge/sources", "GET /v1/knowledge/sources/{source_id}"],
       ui="IntegrationGuide, SourceLinks", requires=(), mcp_profile=_KN),
    _c("knowledge.notes", "Практические заметки", _K, ["GET /v1/knowledge/notes"],
       ui="IntegrationGuide", requires=(), mcp_profile=_KN),
    _c("knowledge.search", "Поиск по знаниям", _K, ["GET /v1/knowledge/search"],
       requires=(), mcp_profile=_KN),
    _c("knowledge.capabilities_catalog", "Каталог возможностей ядра", _K,
       ["GET /v1/knowledge/capabilities"], requires=(), mcp_profile=_KN,
       notes="статический список встроенных записей; регистрации private не входят"),
    _c("knowledge.manual_path", "Ручной маршрут: кабинеты, шаги, поля, пустой шаблон письма", _K,
       ["GET /v1/knowledge/manual-path"], ui="PublicSetup", requires=(), mcp_profile=_KN,
       notes="значения не принимает; доступность внешних кабинетов не проверена"),
    _c("knowledge.connection_card", "Карточка подключения TEST по отметкам человека", _K,
       ["GET /v1/knowledge/connection-card", "POST /v1/knowledge/connection-card/evaluate"],
       ui="ConnectionCard", requires=(), mcp_profile=_KN,
       notes="только допустимые отметки; caller_reported, не проверка кабинета, подписи, заявки или прав; действий нет"),
    _c("knowledge.official_links", "Официальные ссылки кабинетов и консолей", _K,
       ["GET /v1/knowledge/manual-path"], ui="PublicSetup", requires=(), mcp_profile=_KN,
       notes="поле links ручного маршрута; доступность внешних кабинетов не проверена"),
    _c("capabilities.list", "Реестр возможностей установки", _K,
       ["GET /v1/capabilities", "GET /v1/capabilities/{capability_id}"], mcp_profile=_KN,
       notes="эффективный реестр, включая private; только после входа"),
    _c("manual.letter.compose", "Письмо оператору (.eml, mailto)", _RL,
       ui="PublicSetup", requires=(),
       notes=_UI_ONLY_NOTE + ": значения остаются в браузере; пустой шаблон отдаёт knowledge.manual_path"),
    # Каталог услуг, XML, архивы.
    _c("services.list", "Список услуг", _RL, ["GET /services"], ui="App"),
    _c("services.get", "Описание услуги", _RL, ["GET /services/{code}"], ui="App"),
    _c("services.xml_template", "Шаблон XML услуги", _RL, ["GET /xml"], ui="App, вкладка XML"),
    _c("services.xsd_values", "Допустимые значения по XSD", _RL, ["GET /xsd"],
       ui="App, вкладка XML"),
    _c("xml.fill_profile", "Заполнение XML профилем", _RL, ui="Заполнить XML",
       notes=_UI_ONLY_NOTE + ": трансформации выполняются в браузере (serviceProfiles.js)"),
    _c("archive.size", "Размер архива", _RL, ["POST /zipsize"], ui="выбор файлов"),
    # Сертификаты и сессия ЕСИА.
    _c("cert.list", "Список сертификатов", _RL, ["POST /get_certificates"], ui="App"),
    _c("cert.current", "Текущий сертификат", _RL, ["POST /get_current_certificate"], ui="App"),
    _c("cert.select", "Выбор сертификата", _AD, ["POST /set_current_certificate"], ui="select",
       requires=_ADMIN),
    _c("cert.request", "Запрос сертификата", _AD, ["POST /certificates/request"],
       requires=_ADMIN),
    _c("cert.delete", "Удаление сертификата", _AD, ["POST /certificates/delete"],
       requires=_ADMIN),
    _c("cert.restore_keys", "Восстановление ключей", _AD, ["POST /certificates/restore-keys"],
       requires=_ADMIN),
    _c("cert.trust_test_ca", "Доверие тестовому УЦ", _AD, ["POST /certificates/trust-test-ca"],
       requires=_ADMIN, notes="меняет доверие хоста; обращается к внешнему адресу"),
    _c("esia.token.obtain", "Получение токена ЕСИА", _AD, ["POST /accessTkn_esia"],
       ui="Получить токен", requires=("login", "selected_certificate"),
       notes="внешнее чтение, но меняет токен процесса"),
    _c("session.clear", "Сброс токена и сессии подачи", _AD, ["POST /session/clear"],
       ui="Удалить токен", requires=_ADMIN),
    # Подача и заявки.
    _c("order.reserve", "Резервирование заявки", _XW, ["POST /order"], ui="Зарезервировать",
       requires=_TOKEN),
    _c("order.push", "Подача заявки", _XW, ["POST /push"], ui="Создать запрос",
       requires=_TOKEN_CERT),
    _c("order.push_chunked", "Подача заявки по частям", _XW, ["POST /push/chunked"],
       ui="Создать запрос", requires=_TOKEN_CERT),
    _c("order.details", "Статус заявки", _XR, ["POST /order/{orderId}"], ui="Проверить статус",
       requires=_TOKEN, notes="идемпотентность upstream не подтверждена"),
    _c("order.cancel", "Отмена заявки", _XW, ["POST /order/{orderId}/cancel"], ui="Отменить",
       requires=_TOKEN),
    _c("order.list_updated", "Заявки, изменённые после даты", _XR, ["GET /getUpdatedAfter"],
       ui="Получить все запросы", requires=_TOKEN),
    _c("order.status", "Статусы заявок", _XR, ["GET /getOrdersStatus"],
       ui="Получить все запросы", requires=_TOKEN),
    _c("order.download_file", "Файл ответа по заявке", _XR,
       ["POST /download_file/{objectId}/{objectType}"], ui="Скачать файл ответа",
       requires=_TOKEN),
    _c("dictionary.get", "Справочник ЕПГУ", _XR, ["POST /dictionary/{code}"], requires=_TOKEN),
    # Госключ и ФССП.
    _c("goskey.capabilities", "Возможности Госключа", _RL, ["GET /goskey/capabilities"],
       ui="GoskeyForm"),
    _c("goskey.preview", "Проверка заявки Госключа", _RL, ["POST /goskey/preview"],
       ui="GoskeyForm"),
    _c("goskey.submit", "Подача через Госключ", _XW, ["POST /goskey/submit"], ui="GoskeyForm",
       requires=_TOKEN_CERT, notes="подпись общим сертификатом установки"),
    _c("fssp.contracts", "Контракты ФССП", _RL, ["GET /fssp/contracts"],
       notes="в UI не вызывается"),
    _c("fssp.preview", "Проверка заявления ФССП", _RL, ["POST /fssp/preview"], ui="FsspForm"),
    _c("fssp.submit", "Подача заявления ФССП", _XW, ["POST /fssp/submit"], ui="FsspForm",
       requires=_TOKEN_CERT),
    # Госпочта (ГЭПС).
    _c("geps.search", "Поиск писем ГЭПС", _XW, ["POST /geps/search"], requires=_TOKEN,
       notes="квота 5 в сутки"),
    _c("geps.result", "Результат поиска ГЭПС", _XR, ["GET /geps/search/{task_uuid}"],
       requires=_TOKEN, notes="квота 15"),
    _c("geps.message", "Письмо ГЭПС", _XR, ["GET /geps/message/{thread_uuid}/{message_uuid}"],
       requires=_TOKEN),
    _c("geps.attachment", "Вложение письма ГЭПС", _XR,
       ["GET /geps/attachment/{message_uuid}/{attachment_uuid}/{file_type}"], requires=_TOKEN,
       notes="получение может иметь юридический эффект"),
    _c("geps.quota", "Квоты ГЭПС", _RL, ["GET /geps/quota"], ui="Gospochta"),
    _c("geps.scheduler.state", "Состояние планировщика ГЭПС", _RL, ["GET /geps/scheduler"],
       ui="Gospochta"),
    _c("geps.scheduler.switch", "Включение планировщика ГЭПС", _AD, ["POST /geps/scheduler"],
       ui="Gospochta", requires=_ADMIN),
    _c("geps.scheduler.run", "Запуск планировщика ГЭПС", _XW, ["POST /geps/scheduler/run"],
       ui="Gospochta", requires=_TOKEN),
    _c("geps.jobs", "Задания ГЭПС", _RL, ["GET /geps/jobs"], ui="Gospochta"),
    _c("geps.store.messages", "Сохранённые письма ГЭПС", _RL,
       ["GET /geps/messages", "GET /geps/messages/{message_uuid}"], ui="Gospochta"),
    _c("geps.store.attachment_save", "Сохранение вложения ГЭПС", _XR,
       ["POST /geps/messages/{message_uuid}/attachments/{attachment_uuid}/save"],
       ui="Gospochta", requires=_TOKEN,
       notes="читает вложение у оператора и пишет его локально"),
    # Входящие.
    _c("inbound.journal", "Журнал входящих", _RL, ["GET /inbound/messages"], ui="InboundLog"),
    _c("inbound.clear", "Очистка журнала входящих", _WL, ["POST /inbound/clear"],
       ui="InboundLog"),
    _c("inbound.check_public", "Проверка публичного адреса приёмника", _XR,
       ["POST /inbound/check-public"], ui="InboundLog", notes="обращается к заданному адресу"),
    # Вход в установку.
    _c("auth.mode", "Режим входа", _RL, ["GET /auth/mode"], ui="AuthGate", requires=()),
    _c("auth.login", "Вход", _WL, ["POST /auth/login"], ui="AuthGate", requires=()),
    _c("auth.logout", "Выход", _WL, ["POST /auth/logout"], ui="AccountMenu", requires=()),
    _c("auth.session", "Текущая сессия", _RL, ["GET /auth/session"], ui="AccountMenu"),
    _c("auth.password", "Смена своего пароля", _WL, ["POST /auth/password"], ui="AccountMenu"),
    _c("auth.accounts.list", "Список пользователей", _RL, ["GET /auth/accounts"],
       ui="AccountMenu", requires=_ADMIN),
    _c("auth.accounts.create", "Создание пользователя", _AD, ["POST /auth/accounts"],
       requires=_ADMIN),
    _c("auth.accounts.password", "Сброс пароля пользователя", _AD,
       ["POST /auth/accounts/{account_id}/password"], requires=_ADMIN),
    _c("auth.accounts.disable", "Отключение пользователя", _AD,
       ["POST /auth/accounts/{account_id}/disabled"], requires=_ADMIN),
    # Ключи интеграций. Только администратор установки по сессии человека; ключ
    # интеграции эти операции не открывает, и в MCP они не попадают.
    _c("integration.create", "Выпуск ключа интеграции", _AD,
       ["POST /v1/admin/integrations"], requires=_ADMIN,
       notes="секрет показывается один раз, ответ с Cache-Control: no-store"),
    _c("integration.list", "Список ключей интеграций", _AD,
       ["GET /v1/admin/integrations"], requires=_ADMIN),
    _c("integration.revoke", "Отзыв ключа интеграции", _AD,
       ["POST /v1/admin/integrations/{client_id}/revoke"], requires=_ADMIN),
    # Контекст оператора. Машинный маршрут: только ключ интеграции (Bearer), cookie
    # не принимается. Привязку оператора задаёт администратор установки по сессии.
    _c("operator.context", "Контекст оператора для интеграции", _RL,
       ["GET /v1/operator/context"], requires=(), scopes=("local:read",),
       gates=("integration_credential", "operator_binding", "certificate_match",
              "contour_match", "context_match"),
       machine="enforced",
       notes="ключ интеграции; контекст берётся из привязки оператора и живого состояния"),
    _c("operator.binding.get", "Привязка оператора", _AD,
       ["GET /v1/admin/operator-binding"], requires=_ADMIN),
    _c("operator.binding.set", "Установка привязки оператора", _AD,
       ["PUT /v1/admin/operator-binding"], requires=_ADMIN),
    _c("operator.binding.clear", "Снятие привязки оператора", _AD,
       ["DELETE /v1/admin/operator-binding"], requires=_ADMIN),
    # План внешней операции: prepare только записывает план, человек одобряет его
    # по обычной сессии, execute идёт через исполнитель. Встроенных исполнителей
    # нет: без зарегистрированного исполнителя prepare и execute дают 503.
    _c("operation.prepare", "Подготовка плана внешней операции", _WL,
       ["POST /v1/operations/plans"], requires=(), scopes=("external:prepare",),
       gates=(*BASE_MACHINE_GATES, "plan_record"), machine="enforced",
       notes="только записывает план; исполнитель не вызывается, номер не резервируется"),
    _c("operation.plan.get", "Просмотр плана внешней операции", _RL,
       ["GET /v1/operations/plans/{plan_id}"], requires=(), scopes=("external:prepare",),
       gates=BASE_MACHINE_GATES, machine="enforced",
       notes="только план своего ключа"),
    _c("operation.execute", "Исполнение одобренного плана", _XW,
       ["POST /v1/operations/plans/{plan_id}/execute"], requires=(),
       scopes=("external:execute",),
       side_effects=("legal_effect", "external_write", "marks_read", "consumes_quota",
                     "reserves_number"),
       gates=(*BASE_MACHINE_GATES, *PLAN_GATES), machine="enforced",
       notes="только одобренный человеком план; без исполнителя 503; при сбое после "
             "начала внешнего вызова статус unknown, без автоповтора"),
    _c("operation.review", "Предпросмотр плана для одобрения", _AD,
       ["GET /v1/admin/operations/plans/{plan_id}"], ui="PlanReviewModal", requires=_ADMIN,
       notes="точный предпросмотр, включая байты; ключ интеграции не открывает"),
    _c("operation.approve", "Одобрение плана человеком", _AD,
       ["POST /v1/admin/operations/plans/{plan_id}/approve"], ui="PlanReviewModal", requires=_ADMIN,
       notes="только обычная сессия администратора; ключ и MCP одобрить не могут"),
    # Диагностика.
    _c("diagnostics.version", "Версия API Client", _RL, ["GET /version"],
       ui="Проверить API Client"),
    _c("diagnostics.environments", "Окружения", _RL, ["GET /environments"],
       ui="Проверить API Client"),
    _c("diagnostics.status", "Состояние сервера", _RL, ["GET /status"],
       ui="Проверить API Client"),
    _c("diagnostics.health", "Проверка здоровья", _RL, ["GET /health", "GET /hc"], requires=()),
)

_lock = threading.Lock()
_private: List[Capability] = []


def register(cap: Capability) -> None:
    """Добавить возможность из private-модуля. Повтор id это ошибка."""
    if not isinstance(cap, Capability):
        raise TypeError("ожидается Capability")
    with _lock:
        if any(existing.id == cap.id for existing in (*_BUILTIN, *_private)):
            raise ValueError(f"возможность {cap.id!r} уже зарегистрирована")
        _private.append(cap)


def items() -> List[Capability]:
    """Все возможности: копии, порча результата не влияет на реестр."""
    with _lock:
        return [dataclasses.replace(c) for c in (*_BUILTIN, *_private)]


def catalog() -> List[Capability]:
    """Статический публичный каталог: только встроенные записи ядра.

    Регистрации private сюда не попадают; эффективный реестр установки
    отдаёт ``items()`` и только после входа.
    """
    return [dataclasses.replace(c) for c in _BUILTIN]


def get(capability_id: str) -> Optional[Capability]:
    for cap in items():
        if cap.id == capability_id:
            return cap
    return None
