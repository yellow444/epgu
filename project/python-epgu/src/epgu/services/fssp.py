# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Типизированные заявления ФССП в API ЕПГУ.

Поддержаны две услуги с общей схемой бизнес-запроса ФССП
(``http://www.fssprus.ru/namespace/incoming/2019/1``):

- 60010153 - информация о наличии исполнительного производства;
- 10000000352 - информация о ходе исполнительного производства.

Заявление - архив из двух файлов: служебный ``req.xml`` (``EPGURequest``) и
бизнес-запрос ``piev_epgu.xml`` (``IRequest``). Подпись не требуется.

Модуль проверяет поля до сборки и отказывает, а не подставляет что-то за
пользователя (fail closed): пустые поля, неверные контрольные цифры СНИЛС,
ИНН и ОГРН, даты в будущем и значения из примеров спецификации не проходят.
Подача от сотрудника ЮЛ по доверенности из ЕСИА (код 09) требует вложить
машиночитаемую доверенность и здесь пока не поддержана.

XML строится через ``lxml`` по квалифицированным именам, значения в разметку
не подставляются строками. Нужен extra ``xml``::

    pip install "epgu-api[xml]"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from ..errors import ConfigError, ValidationError

NS_TRANSPORT = "urn://x-artifacts-fssp-ru/mvv/smev3/epgu/1.0.1"
NS_REQUEST = "http://www.fssprus.ru/namespace/incoming/2019/1"
TRANSPORT_FILENAME = "req.xml"
REQUEST_FILENAME = "piev_epgu.xml"

MOSCOW = timezone(timedelta(hours=3))
_MIN_DATE = date(1900, 1, 1)

# Ограничения схемы ФССП (DDescriptionType, DAddrType, DDocnumberType).
_MAX_NAME = 1000
_MAX_ADDRESS = 200
_MAX_DOCNUMBER = 25

# Номер исполнительного производства: n..n/yy/dd/rr или n..n/yy/CCNNN-ИП.
_CASE_NUMBER_RE = re.compile(r"^\d{1,12}/\d{2}/(?:\d{2}/\d{2}|\d{5}-ИП)$")
_NAME_WORD_RE = re.compile(r"^[A-Za-zА-Яа-яЁё]+(?:[-'][A-Za-zА-Яа-яЁё]+)*$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Значения из примеров спецификаций ФССП. Отправить их по ошибке вместо
# настоящих данных проще всего, поэтому они отклоняются явно.
DEMO_SNILS = frozenset({"72297105196", "80044242443", "01000031322", "00036363636", "01000030825"})
DEMO_INN = frozenset({"8388055923", "2166087672"})
DEMO_OGRN = frozenset({"5226414709373", "1136193003665"})
DEMO_NAMES = frozenset(
    name.casefold()
    for name in (
        "Иванов Леонид Иванович",
        "Иванов Иван Иванович",
        "Антонов Антон Антонович",
        "Иванова Антонина Леонидовна",
        "Петрова Петра Светлановна",
        "Некрасова Марина",
        "Общество с ограниченной ответственностью «Тестовая организация»",
        "ОРГАНИЗАЦИЯ -1655096987",
    )
)


class FsspContractError(ValidationError):
    """Заявление не соответствует контракту ФССП.

    ``errors`` - пары (поле, сообщение), чтобы форма могла подсветить поля.
    """

    def __init__(self, errors: Sequence[Tuple[str, str]]):
        self.errors: Tuple[Tuple[str, str], ...] = tuple(errors)
        super().__init__("; ".join(f"{field}: {message}" for field, message in self.errors))


class Side(str, Enum):
    """Сторона исполнительного производства (ComplainerType)."""

    CLAIMANT = "1"
    DEBTOR = "2"


class Gender(str, Enum):
    MALE = "1"
    FEMALE = "2"


class Environment(str, Enum):
    """Атрибут Env в req.xml."""

    DEV = "DEV"
    SVCDEV = "SVCDEV"
    PROD = "PROD"


class PowerDocument(str, Enum):
    """Документ, подтверждающий полномочия представителя-физлица (TrusteeDoctype)."""

    GENERAL_POWER = "01"
    SPECIAL_POWER = "02"
    ONE_TIME_POWER = "03"
    BIRTH_CERTIFICATE = "04"
    GUARDIANSHIP = "06"
    BANKRUPTCY = "08"


# Подача от руководителя ЮЛ: приказ о назначении руководителя.
HEAD_OF_ORGANIZATION = "07"


@dataclass(frozen=True)
class FsspContract:
    """Неизменные значения услуги из её спецификации."""

    service_code: str
    title: str
    doc_type: str
    doc_name: str
    receiver_for_person: str
    receiver_for_organization: str
    target_code: str
    smev_service_code: str = "10001449665"
    case_number_required: bool = False
    include_closed_supported: bool = False


CONTRACTS: Mapping[str, FsspContract] = MappingProxyType(
    {
        "60010153": FsspContract(
            service_code="60010153",
            title="Информация о наличии исполнительного производства",
            doc_type="I_IP_EXIST_INTERACTIVE",
            doc_name=(
                "Заявление о предоставлении информации о наличии исполнительного "
                "производства из банка данных"
            ),
            receiver_for_person="FSSP10",
            receiver_for_organization="FSSP10",
            target_code="10001505301",
            include_closed_supported=True,
        ),
        "10000000352": FsspContract(
            service_code="10000000352",
            title="Информация о ходе исполнительного производства",
            doc_type="I_IPSIDE_FSSP_INTERACTIVE",
            doc_name=(
                "Заявление о предоставлении информации о ходе исполнительного "
                "производства из банка данных"
            ),
            receiver_for_person="FSSP07",
            receiver_for_organization="FSSP08",
            target_code="10003818851",
            case_number_required=True,
        ),
    }
)


@dataclass(frozen=True)
class Person:
    """Физическое лицо: заявитель или доверитель."""

    full_name: str
    gender: Gender
    birth_date: date
    snils: str


@dataclass(frozen=True)
class PersonRepresentation:
    """Заявитель представляет другое физлицо по документу из PowerDocument."""

    document: PowerDocument
    issued_by: str
    number: str
    issued_on: date
    principal: Person


@dataclass(frozen=True)
class OrganizationRepresentation:
    """Заявитель - руководитель ЮЛ и подаёт от имени организации (код 07)."""

    name: str
    address: str
    inn: str
    ogrn: str


Representation = Union[PersonRepresentation, OrganizationRepresentation]


@dataclass(frozen=True)
class FsspRequest:
    service_code: str
    side: Side
    applicant: Person
    representation: Optional[Representation] = None
    include_closed: bool = True
    case_number: str = ""


# ---------- проверка ----------


def contract_for(service_code: str) -> FsspContract:
    contract = CONTRACTS.get(str(service_code or "").strip())
    if contract is None:
        raise FsspContractError([("serviceCode", "Услуга не поддерживается построителем ФССП")])
    return contract


def digits_only(value: str) -> str:
    """Убрать пробелы и дефисы, которыми принято разделять СНИЛС и ИНН."""
    return re.sub(r"[\s\-]", "", str(value or ""))


def snils_is_valid(value: str) -> bool:
    if not re.fullmatch(r"\d{11}", value):
        return False
    number = value[:9]
    if int(number) <= 1001998:
        # Контрольная сумма для этого диапазона не определена, и номера
        # из него не выдаются.
        return False
    total = sum(int(digit) * weight for digit, weight in zip(number, range(9, 0, -1), strict=True))
    if total < 100:
        control = total
    elif total in (100, 101):
        control = 0
    else:
        control = total % 101
        if control == 100:
            control = 0
    return control == int(value[9:])


def _inn_checksum(digits: str, weights: Sequence[int]) -> int:
    return (
        sum(
            int(digit) * weight
            for digit, weight in zip(digits[: len(weights)], weights, strict=True)
        )
        % 11
        % 10
    )


def inn_is_valid(value: str) -> bool:
    if re.fullmatch(r"\d{10}", value):
        return _inn_checksum(value, (2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(value[9])
    if re.fullmatch(r"\d{12}", value):
        first = _inn_checksum(value, (7, 2, 4, 10, 3, 5, 9, 4, 6, 8))
        second = _inn_checksum(value, (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8))
        return first == int(value[10]) and second == int(value[11])
    return False


def ogrn_is_valid(value: str) -> bool:
    if re.fullmatch(r"\d{13}", value):
        return int(value[:12]) % 11 % 10 == int(value[12])
    if re.fullmatch(r"\d{15}", value):
        return int(value[:14]) % 13 % 10 == int(value[14])
    return False


def _clean(value: str) -> str:
    return " ".join(str(value or "").split())


class _Checker:
    def __init__(self, today: date):
        self.today = today
        self.errors: List[Tuple[str, str]] = []

    def fail(self, field: str, message: str) -> None:
        self.errors.append((field, message))

    def text(self, field: str, value: str, limit: int, label: str) -> str:
        cleaned = _clean(value)
        if not cleaned:
            self.fail(field, f"{label}: обязательное поле")
        elif len(cleaned) > limit:
            self.fail(field, f"{label}: не длиннее {limit} знаков")
        elif _CONTROL_CHARS_RE.search(str(value or "")):
            self.fail(field, f"{label}: недопустимые символы")
        elif cleaned.casefold() in DEMO_NAMES:
            self.fail(field, f"{label}: значение из примера спецификации, укажите настоящее")
        return cleaned

    def full_name(self, field: str, value: str, label: str) -> str:
        cleaned = self.text(field, value, _MAX_NAME, label)
        if cleaned and cleaned.casefold() not in DEMO_NAMES:
            words = cleaned.split(" ")
            if len(words) < 2 or not all(_NAME_WORD_RE.match(word) for word in words):
                self.fail(field, f"{label}: фамилия, имя и, если есть, отчество через пробел")
        return cleaned

    def day(self, field: str, value: Any, label: str) -> Optional[date]:
        if not isinstance(value, date) or isinstance(value, datetime):
            self.fail(field, f"{label}: нужна дата")
            return None
        if value < _MIN_DATE:
            self.fail(field, f"{label}: не раньше 1900 года")
        elif value > self.today:
            self.fail(field, f"{label}: дата в будущем")
        return value

    def snils(self, field: str, value: str, label: str) -> str:
        digits = digits_only(value)
        if not digits:
            self.fail(field, f"{label}: обязательное поле")
        elif digits in DEMO_SNILS:
            self.fail(field, f"{label}: СНИЛС из примера спецификации, укажите настоящий")
        elif not snils_is_valid(digits):
            self.fail(field, f"{label}: неверный СНИЛС, проверьте цифры")
        return digits

    def person(self, prefix: str, person: Person, label: str) -> Person:
        full_name = self.full_name(f"{prefix}.fullName", person.full_name, f"ФИО ({label})")
        if not isinstance(person.gender, Gender):
            self.fail(f"{prefix}.gender", f"Пол ({label}): мужской или женский")
        self.day(f"{prefix}.birthDate", person.birth_date, f"Дата рождения ({label})")
        snils = self.snils(f"{prefix}.snils", person.snils, f"СНИЛС ({label})")
        return replace(person, full_name=full_name, snils=snils)


def validate_request(request: FsspRequest, *, today: date) -> FsspRequest:
    """Проверить заявление и вернуть нормализованную копию.

    Все ошибки собираются разом: :class:`FsspContractError` перечисляет поля.
    """
    contract = contract_for(request.service_code)
    check = _Checker(today)
    if not isinstance(request.side, Side):
        check.fail("side", "Сторона производства: взыскатель или должник")
    applicant = check.person("applicant", request.applicant, "заявитель")

    case_number = _clean(request.case_number)
    if contract.case_number_required:
        if not case_number:
            check.fail("caseNumber", "Номер исполнительного производства: обязательное поле")
        elif len(case_number) > _MAX_DOCNUMBER or not _CASE_NUMBER_RE.match(case_number):
            check.fail(
                "caseNumber",
                "Номер исполнительного производства: в виде 12345/20/69025-ИП или 12345/20/12/34",
            )
    elif case_number:
        check.fail("caseNumber", "Номер производства для этой услуги не передаётся")
    if contract.include_closed_supported and not isinstance(request.include_closed, bool):
        check.fail("includeClosed", "Признак оконченных производств: да или нет")

    representation = request.representation
    if isinstance(representation, OrganizationRepresentation):
        inn = digits_only(representation.inn)
        ogrn = digits_only(representation.ogrn)
        if not inn:
            check.fail("organization.inn", "ИНН организации: обязательное поле")
        elif inn in DEMO_INN:
            check.fail("organization.inn", "ИНН из примера спецификации, укажите настоящий")
        elif len(inn) != 10 or not inn_is_valid(inn):
            check.fail("organization.inn", "ИНН организации: 10 цифр с верной контрольной цифрой")
        if not ogrn:
            check.fail("organization.ogrn", "ОГРН организации: обязательное поле")
        elif ogrn in DEMO_OGRN:
            check.fail("organization.ogrn", "ОГРН из примера спецификации, укажите настоящий")
        elif len(ogrn) != 13 or not ogrn_is_valid(ogrn):
            check.fail("organization.ogrn", "ОГРН организации: 13 цифр с верной контрольной цифрой")
        address = check.text(
            "organization.address", representation.address, _MAX_ADDRESS, "Адрес организации"
        )
        if address == "0":
            check.fail("organization.address", "Адрес организации: укажите настоящий адрес")
        representation = OrganizationRepresentation(
            name=check.text(
                "organization.name", representation.name, _MAX_NAME, "Наименование организации"
            ),
            address=address,
            inn=inn,
            ogrn=ogrn,
        )
    elif isinstance(representation, PersonRepresentation):
        if not isinstance(representation.document, PowerDocument):
            check.fail("representative.document", "Документ о полномочиях: выберите из списка")
        principal = check.person("principal", representation.principal, "доверитель")
        if principal.snils and principal.snils == applicant.snils:
            check.fail("principal.snils", "Доверитель и заявитель не могут быть одним лицом")
        check.day("representative.issuedOn", representation.issued_on, "Дата документа")
        representation = replace(
            representation,
            issued_by=check.text(
                "representative.issuedBy", representation.issued_by, _MAX_NAME, "Кем выдан документ"
            ),
            number=check.text(
                "representative.number", representation.number, _MAX_DOCNUMBER, "Номер документа"
            ),
            principal=principal,
        )
    elif representation is not None:
        check.fail("representation", "Неизвестный вид представительства")

    if check.errors:
        raise FsspContractError(check.errors)
    return replace(
        request, applicant=applicant, representation=representation, case_number=case_number
    )


# ---------- сборка XML ----------


def _lxml_etree() -> Any:
    try:
        from lxml import etree  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - без extra xml
        raise ConfigError(
            "Для заявлений ФССП нужен пакет с extra: pip install 'epgu-api[xml]'"
        ) from exc
    return etree


def _moscow(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValidationError("Время формирования заявления должно быть с часовым поясом")
    return moment.astimezone(MOSCOW).replace(microsecond=0)


def _add(parent: Any, namespace: str, name: str, value: str) -> Any:
    etree = _lxml_etree()
    node = etree.SubElement(parent, etree.QName(namespace, name))
    node.text = value
    return node


def _serialize(root: Any) -> bytes:
    etree = _lxml_etree()
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=True)


def _check_order_id(order_id: int) -> str:
    if isinstance(order_id, bool) or not isinstance(order_id, int) or order_id <= 0:
        raise ValidationError("Номер заявления ЕПГУ должен быть положительным целым")
    return str(order_id)


def receiver_for(request: FsspRequest) -> str:
    contract = contract_for(request.service_code)
    if isinstance(request.representation, OrganizationRepresentation):
        return contract.receiver_for_organization
    return contract.receiver_for_person


def build_transport_xml(
    request: FsspRequest,
    *,
    order_id: int,
    moment: datetime,
    environment: Environment,
) -> bytes:
    """Служебный req.xml (EPGURequest) по таблице спецификации услуги."""
    contract = contract_for(request.service_code)
    etree = _lxml_etree()
    local = _moscow(moment)
    root = etree.Element(etree.QName(NS_TRANSPORT, "EPGURequest"), nsmap={"fssp": NS_TRANSPORT})
    root.set("Env", Environment(environment).value)
    data = etree.SubElement(root, etree.QName(NS_TRANSPORT, "DataRequest"))
    _add(data, NS_TRANSPORT, "OrderId", _check_order_id(order_id))
    _add(data, NS_TRANSPORT, "Date", local.isoformat())
    _add(data, NS_TRANSPORT, "Department", "ФССП")
    _add(data, NS_TRANSPORT, "DepartmentCode", "00000")
    _add(data, NS_TRANSPORT, "ReceiverID", receiver_for(request))
    _add(data, NS_TRANSPORT, "ServiceCode", contract.smev_service_code)
    _add(data, NS_TRANSPORT, "TargetCode", contract.target_code)
    _add(data, NS_TRANSPORT, "StatementDate", local.date().isoformat())
    return _serialize(root)


def build_request_xml(request: FsspRequest, *, order_id: int, moment: datetime) -> bytes:
    """Бизнес-запрос piev_epgu.xml (IRequest) в порядке элементов схемы ФССП."""
    contract = contract_for(request.service_code)
    etree = _lxml_etree()
    local = _moscow(moment)
    applicant = request.applicant
    ns = NS_REQUEST
    root = etree.Element(etree.QName(ns, "IRequest"), nsmap={"fssp": ns})
    _add(root, ns, "ExternalKey", _check_order_id(order_id))
    _add(root, ns, "DocType", contract.doc_type)
    _add(root, ns, "DocName", contract.doc_name)
    _add(root, ns, "DocDate", local.date().isoformat())
    if contract.case_number_required:
        _add(root, ns, "DeloNum", request.case_number)
    if contract.include_closed_supported:
        _add(root, ns, "IncludeAll", "true" if request.include_closed else "false")
    _add(root, ns, "ComplainerType", Side(request.side).value)
    _add(root, ns, "AuthorName", applicant.full_name)
    _add(root, ns, "ComplainerGender", Gender(applicant.gender).value)
    _add(root, ns, "AuthorBorn", applicant.birth_date.isoformat())
    _add(root, ns, "AuthorSnils", applicant.snils)
    _add(root, ns, "AuthorBackAddrType", "ЕПГУ")
    _add(root, ns, "AuthorBackAddr", applicant.snils)
    representation = request.representation
    if isinstance(representation, OrganizationRepresentation):
        _add(root, ns, "TrusteeDoctype", HEAD_OF_ORGANIZATION)
        _add(root, ns, "TrusteeDivision", representation.name)
        _add(root, ns, "TrusteeDocnumber", "-")
        _add(root, ns, "TrusteeDocdate", local.date().isoformat())
        _add(root, ns, "TrusteeName", representation.name)
        _add(root, ns, "TrusteeAddress", representation.address)
        _add(root, ns, "TrusteeInn", representation.inn)
        _add(root, ns, "TrusteeOGRN", representation.ogrn)
    elif isinstance(representation, PersonRepresentation):
        principal = representation.principal
        _add(root, ns, "TrusteeDoctype", PowerDocument(representation.document).value)
        _add(root, ns, "TrusteeDivision", representation.issued_by)
        _add(root, ns, "TrusteeDocnumber", representation.number)
        _add(root, ns, "TrusteeDocdate", representation.issued_on.isoformat())
        _add(root, ns, "TrusteeName", principal.full_name)
        _add(root, ns, "TrusteeAddress", "0")
        _add(root, ns, "TrusteeBorndate", principal.birth_date.isoformat())
        _add(root, ns, "TrusteeGender", Gender(principal.gender).value)
        _add(root, ns, "TrusteeSnils", principal.snils)
    _add(root, ns, "SimpleDigSignature", applicant.snils)
    sendlist = etree.SubElement(root, etree.QName(ns, "Sendlist"))
    _add(sendlist, ns, "Receiver", "ФССП")
    _add(sendlist, ns, "ReceiverDivisionCode", "00000")
    _add(sendlist, ns, "ReceiverAddrType", "ВЕБ-СЕРВИС")
    _add(sendlist, ns, "ReceiverAddr", "00000")
    return _serialize(root)


def build_documents(
    request: FsspRequest,
    *,
    order_id: int,
    moment: datetime,
    environment: Environment,
) -> Dict[str, bytes]:
    """Проверить заявление и собрать оба файла архива."""
    normalized = validate_request(request, today=_moscow(moment).date())
    return {
        TRANSPORT_FILENAME: build_transport_xml(
            normalized, order_id=order_id, moment=moment, environment=environment
        ),
        REQUEST_FILENAME: build_request_xml(normalized, order_id=order_id, moment=moment),
    }


__all__ = [
    "CONTRACTS",
    "DEMO_INN",
    "DEMO_NAMES",
    "DEMO_OGRN",
    "DEMO_SNILS",
    "Environment",
    "FsspContract",
    "FsspContractError",
    "FsspRequest",
    "Gender",
    "HEAD_OF_ORGANIZATION",
    "OrganizationRepresentation",
    "Person",
    "PersonRepresentation",
    "PowerDocument",
    "REQUEST_FILENAME",
    "Side",
    "TRANSPORT_FILENAME",
    "build_documents",
    "build_request_xml",
    "build_transport_xml",
    "contract_for",
    "digits_only",
    "inn_is_valid",
    "ogrn_is_valid",
    "receiver_for",
    "snils_is_valid",
    "validate_request",
]
