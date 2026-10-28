import hashlib
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest
from lxml import etree

from epgu import validate_xml
from epgu.services import goskey
from epgu.services.goskey import (
    CapabilityState,
    DecipherDocument,
    DecipherRequest,
    ForeignDecipherRecipient,
    ForeignLegalRecipient,
    GoskeyAttribute,
    GoskeyContractError,
    GoskeyOperation,
    IndividualRecipient,
    IndividualSignRequest,
    LegalEntitySignRequest,
    RussianDecipherRecipient,
    RussianLegalRecipient,
    SigningVariant,
    TransportMode,
    TreasurySignRequest,
    UnsupportedGoskeyContractError,
    build_signed_archive,
    capability_for,
    capability_for_service,
    select_transport,
    validate_detached_signature_manifest,
    validate_submission_window,
)

MOSCOW = timezone(timedelta(hours=3))
EXPIRES = datetime(2026, 8, 13, 12, 30, 15, 159000, tzinfo=MOSCOW)
ATTRIBUTES = (
    GoskeyAttribute("orgName", "ООО Ромашка"),
    GoskeyAttribute("orgINN", "6950199530"),
)


def _schema(service_code: str) -> bytes:
    """Return a project-authored request-only conformance schema.

    The full official XSD copies are intentionally not redistributed. Their
    hashes remain in the capability registry and the local documentation
    snapshot can be fetched independently for a full comparison.
    """

    namespaces = {
        "10000000374": "urn://mpkey.gosuslugi.ru/sign_document/1.0.0",
        "60025907": "urn://mpkey.gosuslugi.ru/sign_document_ukep_legalperson/1.0.0",
        "60080470": "urn://mpkey.gosuslugi.ru/sign_document_ukep_roskazna/1.0.0",
    }
    namespace = namespaces[service_code]
    individual = """
      <xs:choice>
        <xs:element name="Snils" type="tns:Snils"/>
        <xs:element name="OID" type="tns:Identifier"/>
      </xs:choice>"""
    legal = """
      <xs:choice>
        <xs:element name="RFOrg">
          <xs:complexType><xs:sequence>
            <xs:choice>
              <xs:element name="Snils" type="tns:Snils"/>
              <xs:element name="OID" type="tns:Identifier"/>
            </xs:choice>
            <xs:element name="OGRN"><xs:simpleType><xs:restriction base="xs:string">
              <xs:pattern value="[0-9]{11}|[0-9]{13}|[0-9]{15}"/>
            </xs:restriction></xs:simpleType></xs:element>
          </xs:sequence></xs:complexType>
        </xs:element>
        <xs:element name="ForeignOrg">
          <xs:complexType><xs:sequence>
            <xs:element name="RAFP"><xs:simpleType><xs:restriction base="xs:string">
              <xs:pattern value="[0-9]{11}"/>
            </xs:restriction></xs:simpleType></xs:element>
            <xs:element name="INN_user"><xs:simpleType><xs:restriction base="xs:string">
              <xs:pattern value="[0-9]{12}"/>
            </xs:restriction></xs:simpleType></xs:element>
          </xs:sequence></xs:complexType>
        </xs:element>
      </xs:choice>"""
    recipient = legal if service_code == "60025907" else individual
    schema = """<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:tns="{namespace}" targetNamespace="{namespace}"
  elementFormDefault="qualified">
  <xs:simpleType name="Identifier"><xs:restriction base="xs:normalizedString">
    <xs:minLength value="1"/><xs:maxLength value="20"/>
  </xs:restriction></xs:simpleType>
  <xs:simpleType name="Snils"><xs:restriction base="xs:string">
    <xs:pattern value="[0-9]{{3}}-[0-9]{{3}}-[0-9]{{3}} [0-9]{{2}}"/>
  </xs:restriction></xs:simpleType>
  <xs:simpleType name="Text50"><xs:restriction base="xs:string">
    <xs:maxLength value="50"/>
  </xs:restriction></xs:simpleType>
  <xs:simpleType name="Text250"><xs:restriction base="xs:string">
    <xs:maxLength value="250"/>
  </xs:restriction></xs:simpleType>
  <xs:complexType name="Attribute"><xs:sequence>
    <xs:element name="AttributeName" type="tns:Text50"/>
    <xs:element name="AttributeValue" type="xs:normalizedString"/>
  </xs:sequence></xs:complexType>
  <xs:element name="SignRequest"><xs:complexType><xs:sequence>
    {recipient}
    <xs:element name="Backlink" type="tns:Text250" minOccurs="0"/>
    <xs:element name="SignExpiration" type="xs:dateTime"/>
    <xs:element name="Description" type="tns:Text250"/>
    <xs:element name="Attribute" type="tns:Attribute" minOccurs="0" maxOccurs="10"/>
  </xs:sequence></xs:complexType></xs:element>
</xs:schema>
""".format(namespace=namespace, recipient=recipient)
    return schema.encode("utf-8")


def _unep_request(**changes) -> IndividualSignRequest:
    values = {
        "variant": SigningVariant.UNEP,
        "recipient": IndividualRecipient(snils="000-729-729 38"),
        "sign_expiration": EXPIRES,
        "description": "Заявление на отпуск",
        "attributes": ATTRIBUTES,
        "backlink": "https://www.gosuslugi.ru/",
    }
    values.update(changes)
    return IndividualSignRequest(**values)


def _manifest(xml: bytes, name: str = "document.pdf"):
    return {
        "req.xml": xml,
        "req.xml.sig": b"REQ-SIGNATURE",
        name: b"DOCUMENT",
        name + ".sig": b"DOCUMENT-SIGNATURE",
    }


def _qnames(xml: bytes):
    root = etree.fromstring(xml)
    return etree.QName(root), [etree.QName(child).localname for child in root]


def test_capability_registry_is_explicit_about_verified_and_reference_contracts():
    unep = capability_for(GoskeyOperation.SIGN_INDIVIDUAL, SigningVariant.UNEP)
    ukep = capability_for_service("10000000374", SigningVariant.UKEP)
    legal = capability_for_service("60025907")
    decipher = capability_for_service("60079416")
    treasury = capability_for_service("60080470")

    assert unep.state is CapabilityState.VERIFIED
    assert ukep.state is CapabilityState.REFERENCE
    assert ukep.schema_sha256 is None
    assert legal.state is CapabilityState.VERIFIED
    assert legal.contradictions and "Description" in legal.contradictions[0]
    assert decipher.state is CapabilityState.REFERENCE
    assert "FileName" in decipher.contradictions[0]
    assert "Description" in decipher.contradictions[0]
    assert treasury.state is CapabilityState.VERIFIED
    assert treasury.target_code == "-60080470"


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: capability_for("missing"), "Unknown"),
        (lambda: capability_for(GoskeyOperation.SIGN_INDIVIDUAL), "requires variant"),
        (
            lambda: capability_for(GoskeyOperation.SIGN_TREASURY, SigningVariant.UKEP),
            "does not accept",
        ),
        (lambda: capability_for_service("missing"), "Unknown"),
        (lambda: capability_for_service("10000000374"), "requires variant"),
        (
            lambda: capability_for_service("60080470", SigningVariant.UKEP),
            "does not accept",
        ),
        (lambda: capability_for_service("10000000374", "bad"), "Unknown"),
    ],
)
def test_capability_lookup_rejects_invalid_pairs(call, message):
    with pytest.raises(GoskeyContractError, match=message):
        call()


def test_unep_req_xml_is_deterministic_golden_and_validates_against_contract_schema():
    xml = _unep_request().to_xml()

    expected = """<?xml version='1.0' encoding='UTF-8'?>
<SignRequest xmlns="urn://mpkey.gosuslugi.ru/sign_document/1.0.0"><Snils>000-729-729 38</Snils><Backlink>https://www.gosuslugi.ru/</Backlink><SignExpiration>2026-08-13T12:30:15.159+03:00</SignExpiration><Description>Заявление на отпуск</Description><Attribute><AttributeName>orgName</AttributeName><AttributeValue>ООО Ромашка</AttributeValue></Attribute><Attribute><AttributeName>orgINN</AttributeName><AttributeValue>6950199530</AttributeValue></Attribute></SignRequest>"""  # noqa: E501 - golden wire representation
    assert xml == expected.encode("utf-8")
    validate_xml(xml, _schema("10000000374"))


def test_xml_values_are_escaped_not_interpolated():
    value = 'ООО <Ромашка> & "Ко"'
    request = _unep_request(
        description="Договор <№1> & приложение",
        attributes=(GoskeyAttribute("orgName", value), ATTRIBUTES[1]),
    )
    xml = request.to_xml()

    assert b"&lt;" in xml and b"&amp;" in xml
    root = etree.fromstring(xml)
    namespace = {"g": request.capability.namespace}
    assert root.findtext("g:Description", namespaces=namespace) == "Договор <№1> & приложение"
    assert root.xpath("string(g:Attribute[1]/g:AttributeValue)", namespaces=namespace) == value


@pytest.mark.parametrize(
    "recipient",
    [
        RussianLegalRecipient(ogrn="12345678901", oid="123456789"),
        ForeignLegalRecipient(rafp="12345678901", inn_user="123456789012"),
    ],
)
def test_legal_entity_variants_validate_against_contract_schema(recipient):
    request = LegalEntitySignRequest(
        recipient=recipient,
        sign_expiration=EXPIRES,
        description="Договор на оказание услуг",
        attributes=ATTRIBUTES,
    )
    xml = request.to_xml()
    root_name, children = _qnames(xml)

    assert root_name.localname == "SignRequest"
    assert root_name.namespace == request.capability.namespace
    expected_recipient = "RFOrg" if isinstance(recipient, RussianLegalRecipient) else "ForeignOrg"
    assert children[0] == expected_recipient
    assert children[1:] == [
        "SignExpiration",
        "Description",
        "Attribute",
        "Attribute",
    ]
    validate_xml(xml, _schema("60025907"))


def test_treasury_oid_request_matches_root_order_and_contract_schema():
    request = TreasurySignRequest(
        recipient=IndividualRecipient(oid="123456789"),
        sign_expiration=EXPIRES.replace(microsecond=0),
        description="Договор",
        attributes=ATTRIBUTES,
        backlink=None,
    )
    xml = request.to_xml()
    root_name, children = _qnames(xml)

    assert root_name.namespace.endswith("sign_document_ukep_roskazna/1.0.0")
    assert children == ["OID", "SignExpiration", "Description", "Attribute", "Attribute"]
    assert b"2026-08-13T12:30:15+03:00" in xml
    validate_xml(xml, _schema("60080470"))


def test_reference_only_variants_fail_closed_with_source_conflict():
    ukep = _unep_request(variant=SigningVariant.UKEP)
    with pytest.raises(UnsupportedGoskeyContractError, match="publishes only the UNEP"):
        ukep.to_xml()

    decipher = DecipherRequest(
        recipient=RussianDecipherRecipient(ogrn="1234567890123"),
        expiration=EXPIRES,
        description="Налоговый отчет",
        attributes=ATTRIBUTES,
        documents=(DecipherDocument("document.pdf.enc", ("/Document/Data",)),),
    )
    with pytest.raises(UnsupportedGoskeyContractError, match="FileName"):
        decipher.to_xml()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: IndividualRecipient(),
        lambda: IndividualRecipient(snils="000-729-729 38", oid="1"),
        lambda: IndividualRecipient(snils="00072972938"),
        lambda: IndividualRecipient(oid=""),
        lambda: RussianLegalRecipient(ogrn="1", oid="1"),
        lambda: RussianLegalRecipient(ogrn="12345678901"),
        lambda: ForeignLegalRecipient(rafp="1", inn_user="123456789012"),
        lambda: ForeignLegalRecipient(rafp="12345678901", inn_user="1"),
        lambda: RussianDecipherRecipient(ogrn="12345678901", user_id="1", snils="000-729-729 38"),
        lambda: RussianDecipherRecipient(ogrn="12345678901", user_id="abc"),
        lambda: ForeignDecipherRecipient(rafp="12345678901", inn_user="abc"),
    ],
)
def test_recipient_models_reject_values_outside_embedded_xsd(factory):
    with pytest.raises(GoskeyContractError):
        factory()


def test_request_models_validate_timezone_attributes_and_limits():
    with pytest.raises(GoskeyContractError, match="timezone-aware"):
        _unep_request(sign_expiration=EXPIRES.replace(tzinfo=None))
    with pytest.raises(GoskeyContractError, match="Moscow"):
        _unep_request(sign_expiration=EXPIRES.astimezone(timezone.utc))
    with pytest.raises(GoskeyContractError, match="missing"):
        _unep_request(attributes=(ATTRIBUTES[0],))
    with pytest.raises(GoskeyContractError, match="unique"):
        _unep_request(attributes=(ATTRIBUTES[0], ATTRIBUTES[0], ATTRIBUTES[1]))
    with pytest.raises(GoskeyContractError, match="250"):
        _unep_request(description="x" * 251)
    with pytest.raises(GoskeyContractError, match="control"):
        GoskeyAttribute("bad\x01name", "value")
    with pytest.raises(GoskeyContractError, match="at most 10"):
        _unep_request(
            attributes=ATTRIBUTES
            + tuple(GoskeyAttribute("extra{0}".format(index), "x") for index in range(9))
        )


def test_decipher_typed_fields_validate_even_though_generation_is_reference_only():
    assert RussianDecipherRecipient(ogrn="12345678901")
    assert ForeignDecipherRecipient(rafp="12345678901", inn_user="123456789012")
    with pytest.raises(GoskeyContractError, match="1..10"):
        DecipherDocument("document.pdf.enc", ())
    with pytest.raises(GoskeyContractError, match="50"):
        DecipherRequest(
            recipient=RussianDecipherRecipient(ogrn="12345678901"),
            expiration=EXPIRES,
            description="Документы",
            attributes=ATTRIBUTES,
            documents=tuple(
                DecipherDocument("{0}.enc".format(index), ("/x",)) for index in range(51)
            ),
        )


def test_manifest_requires_detached_signature_for_every_payload_including_req_xml():
    xml = _unep_request().to_xml()
    report = validate_detached_signature_manifest(
        _manifest(xml),
        service_code="10000000374",
        variant=SigningVariant.UNEP,
    )

    assert report.payload_names == ("req.xml", "document.pdf")
    assert report.signature_names == ("req.xml.sig", "document.pdf.sig")
    assert report.document_count == 1
    assert report.document_bytes == len(b"DOCUMENT")
    assert report.cryptographic_signatures_verified is False

    for missing in ("req.xml.sig", "document.pdf.sig"):
        members = _manifest(xml)
        del members[missing]
        with pytest.raises(GoskeyContractError, match="missing detached signature"):
            validate_detached_signature_manifest(
                members,
                service_code="10000000374",
                variant=SigningVariant.UNEP,
            )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda values: values.pop("req.xml"), "req.xml"),
        (lambda values: values.update({"orphan.pdf.sig": b"sig"}), "orphan"),
        (lambda values: values.update({"req.xml.sig.sig": b"sig"}), "orphan"),
        (
            lambda values: values.update({"folder/evil.pdf": b"x", "folder/evil.pdf.sig": b"s"}),
            "flat",
        ),
        (lambda values: values.update({"DOCUMENT.PDF": b"x", "DOCUMENT.PDF.sig": b"s"}), "case"),
        (lambda values: values.update({"bad.exe": b"x", "bad.exe.sig": b"s"}), "extension"),
        (
            lambda values: values.update({"bad-name.pdf": b"x", "bad-name.pdf.sig": b"s"}),
            "characters",
        ),
        (lambda values: values.update({"empty.pdf": b"", "empty.pdf.sig": b"s"}), "empty"),
    ],
)
def test_manifest_rejects_unsafe_or_incomplete_members(mutate, message):
    values = _manifest(_unep_request().to_xml())
    mutate(values)
    with pytest.raises(GoskeyContractError, match=message):
        validate_detached_signature_manifest(
            values,
            service_code="10000000374",
            variant=SigningVariant.UNEP,
        )


def test_manifest_rejects_wrong_xml_root_dtd_count_and_size(monkeypatch):
    base = _manifest(_unep_request().to_xml())
    base["req.xml"] = b'<SignRequest xmlns="urn:wrong"/>'
    with pytest.raises(GoskeyContractError, match="root"):
        validate_detached_signature_manifest(
            base, service_code="10000000374", variant=SigningVariant.UNEP
        )

    dtd = dict(_manifest(_unep_request().to_xml()))
    dtd["req.xml"] = (
        b'<!DOCTYPE SignRequest [<!ENTITY x "x">]>'
        b'<SignRequest xmlns="urn://mpkey.gosuslugi.ru/sign_document/1.0.0">&x;</SignRequest>'
    )
    with pytest.raises(GoskeyContractError, match="DTD"):
        validate_detached_signature_manifest(
            dtd, service_code="10000000374", variant=SigningVariant.UNEP
        )

    too_many = {
        "req.xml": _unep_request().to_xml(),
        "req.xml.sig": b"sig",
    }
    for index in range(21):
        name = "d{0}.pdf".format(index)
        too_many[name] = b"x"
        too_many[name + ".sig"] = b"s"
    with pytest.raises(GoskeyContractError, match="count"):
        validate_detached_signature_manifest(
            too_many, service_code="10000000374", variant=SigningVariant.UNEP
        )

    monkeypatch.setattr(goskey, "MAX_DOCUMENT_BYTES", 2)
    with pytest.raises(GoskeyContractError, match="100,000,000"):
        validate_detached_signature_manifest(
            _manifest(_unep_request().to_xml()),
            service_code="10000000374",
            variant=SigningVariant.UNEP,
        )


def test_build_signed_archive_reuses_signer_for_req_and_every_document():
    signed_hashes = []

    class HashSigner:
        def sign(self, data: bytes) -> bytes:
            digest = hashlib.sha256(data).digest()
            signed_hashes.append(digest)
            return b"CMS" + digest

    content = build_signed_archive(
        _unep_request(),
        {"offer.pdf": b"PDF", "terms.txt": b"TEXT"},
        HashSigner(),
    )
    with zipfile.ZipFile(BytesIO(content)) as archive:
        assert archive.namelist() == [
            "req.xml",
            "req.xml.sig",
            "offer.pdf",
            "offer.pdf.sig",
            "terms.txt",
            "terms.txt.sig",
        ]
        for name in ("req.xml", "offer.pdf", "terms.txt"):
            assert (
                archive.read(name + ".sig") == b"CMS" + hashlib.sha256(archive.read(name)).digest()
            )
    assert len(signed_hashes) == 3


@pytest.mark.parametrize(
    ("documents", "message"),
    [
        ({}, "at least one"),
        ({"req.xml": b"bad"}, "unsigned"),
        ({"doc.pdf.sig": b"bad"}, "unsigned"),
        ({"doc.pdf": "not bytes"}, "bytes"),
    ],
)
def test_build_signed_archive_rejects_invalid_document_input(documents, message):
    class Signer:
        def sign(self, data: bytes) -> bytes:
            return b"signature"

    with pytest.raises(GoskeyContractError, match=message):
        build_signed_archive(_unep_request(), documents, Signer())


def test_adaptive_transport_boundary_and_existing_order():
    direct = select_transport(50_000_000)
    oversized = select_transport(50_000_001)
    reserved = select_transport(1, order_id=42)

    assert direct.mode is TransportMode.PUSH
    assert direct.endpoint == "/api/gusmev/push"
    assert direct.reserve_order is False
    assert oversized.mode is TransportMode.ORDER_CHUNKED
    assert oversized.reserve_order is True
    assert reserved.mode is TransportMode.ORDER_CHUNKED
    assert reserved.reserve_order is False
    assert reserved.order_id == 42


@pytest.mark.parametrize(
    "args",
    [(0,), (-1,), (True,), (1, 0), (1, -1), (1, True)],
)
def test_adaptive_transport_rejects_non_positive_or_boolean_values(args):
    with pytest.raises(GoskeyContractError):
        select_transport(*args)


def test_submission_window_is_future_moscow_and_at_most_24_hours():
    now = datetime(2026, 8, 12, 12, 0, tzinfo=MOSCOW)
    validate_submission_window(now + timedelta(seconds=1), now=now)
    validate_submission_window(now + timedelta(hours=24), now=now)

    with pytest.raises(GoskeyContractError, match="future"):
        validate_submission_window(now, now=now)
    with pytest.raises(GoskeyContractError, match="24 hours"):
        validate_submission_window(now + timedelta(hours=24, seconds=1), now=now)
    with pytest.raises(GoskeyContractError, match="Moscow"):
        validate_submission_window(now.astimezone(timezone.utc), now=now)
    with pytest.raises(GoskeyContractError, match="now"):
        validate_submission_window(now + timedelta(hours=1), now=now.replace(tzinfo=None))
