from datetime import date, datetime, timedelta, timezone

import pytest
from lxml import etree

from epgu.errors import ValidationError
from epgu.services import fssp
from epgu.services.fssp import (
    Environment,
    FsspContractError,
    FsspRequest,
    Gender,
    OrganizationRepresentation,
    Person,
    PersonRepresentation,
    PowerDocument,
    Side,
    build_documents,
    inn_is_valid,
    ogrn_is_valid,
    snils_is_valid,
    validate_request,
)

MOSCOW = timezone(timedelta(hours=3))
MOMENT = datetime(2026, 10, 8, 9, 15, 30, 123456, tzinfo=timezone.utc)
TODAY = date(2026, 10, 8)

# Синтетические значения с верными контрольными цифрами.
APPLICANT = Person("Петров Пётр Петрович", Gender.MALE, date(1985, 3, 4), "112-233-445 95")
PRINCIPAL = Person("Петрова Анна Петровна", Gender.FEMALE, date(2015, 7, 1), "12345678964")
ORGANIZATION = OrganizationRepresentation(
    name="ООО «Ромашка»",
    address="101000, г. Москва, ул. Примерная, д. 1",
    inn="7700000016",
    ogrn="1027700000019",
)

# Порядок элементов из примеров спецификаций ФССП (piev_epgu.xml).
PERSONAL_ORDER = [
    "ExternalKey",
    "DocType",
    "DocName",
    "DocDate",
    "IncludeAll",
    "ComplainerType",
    "AuthorName",
    "ComplainerGender",
    "AuthorBorn",
    "AuthorSnils",
    "AuthorBackAddrType",
    "AuthorBackAddr",
    "SimpleDigSignature",
    "Sendlist",
]
ORGANIZATION_ORDER = [
    "ExternalKey",
    "DocType",
    "DocName",
    "DocDate",
    "IncludeAll",
    "ComplainerType",
    "AuthorName",
    "ComplainerGender",
    "AuthorBorn",
    "AuthorSnils",
    "AuthorBackAddrType",
    "AuthorBackAddr",
    "TrusteeDoctype",
    "TrusteeDivision",
    "TrusteeDocnumber",
    "TrusteeDocdate",
    "TrusteeName",
    "TrusteeAddress",
    "TrusteeInn",
    "TrusteeOGRN",
    "SimpleDigSignature",
    "Sendlist",
]
PERSON_TRUSTEE_ORDER = [
    "ExternalKey",
    "DocType",
    "DocName",
    "DocDate",
    "DeloNum",
    "ComplainerType",
    "AuthorName",
    "ComplainerGender",
    "AuthorBorn",
    "AuthorSnils",
    "AuthorBackAddrType",
    "AuthorBackAddr",
    "TrusteeDoctype",
    "TrusteeDivision",
    "TrusteeDocnumber",
    "TrusteeDocdate",
    "TrusteeName",
    "TrusteeAddress",
    "TrusteeBorndate",
    "TrusteeGender",
    "TrusteeSnils",
    "SimpleDigSignature",
    "Sendlist",
]


def children(xml: bytes):
    root = etree.fromstring(xml)
    return root, [etree.QName(child).localname for child in root]


def text(root, name, namespace=fssp.NS_REQUEST):
    return root.find(".//{%s}%s" % (namespace, name)).text


def test_existence_from_organization_head_matches_the_specification():
    request = FsspRequest("60010153", Side.CLAIMANT, APPLICANT, ORGANIZATION, include_closed=False)
    documents = build_documents(
        request, order_id=1234567890, moment=MOMENT, environment=Environment.SVCDEV
    )
    assert set(documents) == {"req.xml", "piev_epgu.xml"}

    transport = etree.fromstring(documents["req.xml"])
    assert etree.QName(transport).localname == "EPGURequest"
    assert transport.get("Env") == "SVCDEV"
    data = [(etree.QName(node).localname, node.text) for node in transport[0]]
    assert data == [
        ("OrderId", "1234567890"),
        ("Date", "2026-10-08T12:15:30+03:00"),
        ("Department", "ФССП"),
        ("DepartmentCode", "00000"),
        ("ReceiverID", "FSSP10"),
        ("ServiceCode", "10001449665"),
        ("TargetCode", "10001505301"),
        ("StatementDate", "2026-10-08"),
    ]

    root, order = children(documents["piev_epgu.xml"])
    assert order == ORGANIZATION_ORDER
    assert text(root, "DocType") == "I_IP_EXIST_INTERACTIVE"
    assert text(root, "IncludeAll") == "false"
    assert text(root, "ComplainerType") == "1"
    assert text(root, "AuthorSnils") == "11223344595"  # без пробелов и дефисов
    assert text(root, "AuthorBackAddr") == text(root, "SimpleDigSignature") == "11223344595"
    assert text(root, "TrusteeDoctype") == "07"
    assert text(root, "TrusteeDocnumber") == "-"
    assert text(root, "TrusteeDocdate") == "2026-10-08"
    assert text(root, "TrusteeName") == text(root, "TrusteeDivision") == "ООО «Ромашка»"
    assert text(root, "TrusteeInn") == "7700000016"
    assert [
        (etree.QName(n).localname, n.text) for n in root.find("{%s}Sendlist" % fssp.NS_REQUEST)
    ] == [
        ("Receiver", "ФССП"),
        ("ReceiverDivisionCode", "00000"),
        ("ReceiverAddrType", "ВЕБ-СЕРВИС"),
        ("ReceiverAddr", "00000"),
    ]


def test_personal_existence_request_has_no_trustee():
    request = FsspRequest("60010153", Side.DEBTOR, APPLICANT)
    root, order = children(
        build_documents(request, order_id=1, moment=MOMENT, environment=Environment.PROD)[
            "piev_epgu.xml"
        ]
    )
    assert order == PERSONAL_ORDER
    assert text(root, "IncludeAll") == "true"


def test_course_request_carries_the_case_number_and_receiver_depends_on_applicant():
    by_person = FsspRequest(
        "10000000352",
        Side.DEBTOR,
        APPLICANT,
        PersonRepresentation(
            PowerDocument.BIRTH_CERTIFICATE,
            "Отдел ЗАГС",
            "III-МЮ 123456",
            date(2015, 7, 10),
            PRINCIPAL,
        ),
        case_number="23545/20/69025-ИП",
    )
    documents = build_documents(
        by_person, order_id=7, moment=MOMENT, environment=Environment.SVCDEV
    )
    root, order = children(documents["piev_epgu.xml"])
    assert order == PERSON_TRUSTEE_ORDER
    assert text(root, "DocType") == "I_IPSIDE_FSSP_INTERACTIVE"
    assert text(root, "DeloNum") == "23545/20/69025-ИП"
    assert text(root, "TrusteeDoctype") == "04"
    assert text(root, "TrusteeAddress") == "0"
    assert text(root, "TrusteeSnils") == "12345678964"
    assert text(etree.fromstring(documents["req.xml"]), "ReceiverID", fssp.NS_TRANSPORT) == "FSSP07"
    assert (
        text(etree.fromstring(documents["req.xml"]), "TargetCode", fssp.NS_TRANSPORT)
        == "10003818851"
    )

    by_organization = FsspRequest(
        "10000000352", Side.CLAIMANT, APPLICANT, ORGANIZATION, case_number="5013/20/12/34"
    )
    transport = build_documents(
        by_organization, order_id=7, moment=MOMENT, environment=Environment.SVCDEV
    )["req.xml"]
    assert text(etree.fromstring(transport), "ReceiverID", fssp.NS_TRANSPORT) == "FSSP08"


def test_values_from_the_specification_examples_are_rejected():
    demo = FsspRequest(
        "60010153",
        Side.DEBTOR,
        Person("Иванов Леонид Иванович", Gender.MALE, date(1989, 6, 21), "72297105196"),
        OrganizationRepresentation(
            "ОРГАНИЗАЦИЯ -1655096987", "127434, г. Москва, ул. Дубки", "8388055923", "5226414709373"
        ),
    )
    with pytest.raises(FsspContractError) as caught:
        validate_request(demo, today=TODAY)
    fields = {field for field, _ in caught.value.errors}
    assert fields == {
        "applicant.fullName",
        "applicant.snils",
        "organization.inn",
        "organization.ogrn",
        "organization.name",
    }


@pytest.mark.parametrize(
    "change, field",
    [
        (
            dict(applicant=Person("Петров", Gender.MALE, date(1985, 3, 4), "11223344595")),
            "applicant.fullName",
        ),
        (
            dict(applicant=Person("Петров Пётр", Gender.MALE, date(1985, 3, 4), "11223344596")),
            "applicant.snils",
        ),
        (
            dict(applicant=Person("Петров Пётр", Gender.MALE, date(2030, 1, 1), "11223344595")),
            "applicant.birthDate",
        ),
        (
            dict(applicant=Person("Петров Пётр", "M", date(1985, 3, 4), "11223344595")),
            "applicant.gender",
        ),
        (
            dict(applicant=Person("Петров 2 Пётр", Gender.MALE, date(1985, 3, 4), "11223344595")),
            "applicant.fullName",
        ),
        (dict(side="claimant"), "side"),
        (dict(case_number="12345"), "caseNumber"),
        (
            dict(
                representation=OrganizationRepresentation(
                    "ООО «Ромашка»", "0", "7700000016", "1027700000019"
                )
            ),
            "organization.address",
        ),
        (
            dict(
                representation=OrganizationRepresentation(
                    "ООО «Ромашка»", "Москва", "7700000017", "1027700000019"
                )
            ),
            "organization.inn",
        ),
        (
            dict(
                representation=OrganizationRepresentation(
                    "ООО «Ромашка»", "Москва", "7700000016", "1027700000018"
                )
            ),
            "organization.ogrn",
        ),
        (
            dict(
                representation=OrganizationRepresentation(
                    "", "Москва", "7700000016", "1027700000019"
                )
            ),
            "organization.name",
        ),
        (dict(representation="кто-то"), "representation"),
    ],
)
def test_invalid_fields_fail_closed(change, field):
    base = dict(
        service_code="60010153",
        side=Side.CLAIMANT,
        applicant=APPLICANT,
        representation=ORGANIZATION,
    )
    base.update(change)
    with pytest.raises(FsspContractError) as caught:
        validate_request(FsspRequest(**base), today=TODAY)
    assert field in {name for name, _ in caught.value.errors}


def test_course_requires_a_valid_case_number_and_existence_has_none():
    with pytest.raises(FsspContractError, match="caseNumber"):
        validate_request(FsspRequest("10000000352", Side.DEBTOR, APPLICANT), today=TODAY)
    with pytest.raises(FsspContractError, match="caseNumber"):
        validate_request(
            FsspRequest("10000000352", Side.DEBTOR, APPLICANT, case_number="23545-ИП"), today=TODAY
        )
    with pytest.raises(FsspContractError, match="caseNumber"):
        validate_request(
            FsspRequest("60010153", Side.DEBTOR, APPLICANT, case_number="23545/20/69025-ИП"),
            today=TODAY,
        )


def test_representative_cannot_be_the_principal():
    same = PersonRepresentation(
        PowerDocument.GENERAL_POWER, "Нотариус", "77 АА 1234567", date(2025, 1, 10), APPLICANT
    )
    with pytest.raises(FsspContractError, match="principal.snils"):
        validate_request(FsspRequest("60010153", Side.CLAIMANT, APPLICANT, same), today=TODAY)


def test_unknown_service_order_number_and_naive_time_are_refused():
    with pytest.raises(FsspContractError, match="serviceCode"):
        validate_request(FsspRequest("10000000396", Side.DEBTOR, APPLICANT), today=TODAY)
    request = FsspRequest("60010153", Side.DEBTOR, APPLICANT)
    with pytest.raises(ValidationError, match="положительным"):
        build_documents(request, order_id=0, moment=MOMENT, environment=Environment.SVCDEV)
    with pytest.raises(ValidationError, match="часовым поясом"):
        build_documents(
            request, order_id=1, moment=datetime(2026, 10, 8, 12, 0), environment=Environment.SVCDEV
        )


def test_identifier_checksums():
    assert snils_is_valid("11223344595") and not snils_is_valid("11223344596")
    assert not snils_is_valid("00100199800")  # диапазон без контрольной суммы
    assert inn_is_valid("7700000016") and not inn_is_valid("7700000017")
    assert inn_is_valid("500100732259") and not inn_is_valid("500100732258")
    assert ogrn_is_valid("1027700000019") and not ogrn_is_valid("1027700000018")
    assert ogrn_is_valid("317392600035973")


def test_values_are_escaped_not_interpolated():
    organization = OrganizationRepresentation(
        name="ООО «Рога & Копыта» <test>", address="Москва", inn="7700000016", ogrn="1027700000019"
    )
    request = FsspRequest("60010153", Side.CLAIMANT, APPLICANT, organization)
    xml = build_documents(request, order_id=5, moment=MOMENT, environment=Environment.DEV)[
        "piev_epgu.xml"
    ]
    root = etree.fromstring(xml)
    assert text(root, "TrusteeName") == "ООО «Рога & Копыта» <test>"
    assert b"<test>" not in xml
