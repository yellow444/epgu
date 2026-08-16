import pytest

from epgu import validate_xml
from epgu.errors import ValidationError

XSD = b"""\
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="request">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="orderId" type="xs:positiveInteger"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
"""


def test_validate_xml_accepts_document_matching_schema():
    validate_xml(b"<request><orderId>42</orderId></request>", XSD)


def test_validate_xml_rejects_schema_mismatch():
    with pytest.raises(ValidationError, match="не соответствует"):
        validate_xml(b"<request><orderId>zero</orderId></request>", XSD)


def test_validate_xml_rejects_malformed_document_and_schema():
    with pytest.raises(ValidationError, match="Некорректный XML"):
        validate_xml(b"<request>", XSD)
    with pytest.raises(ValidationError, match="XSD"):
        validate_xml(b"<request/>", b"<schema>")


def test_validate_xml_does_not_resolve_external_entities(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    payload = f"""\
<!DOCTYPE request [<!ENTITY xxe SYSTEM "{secret.as_uri()}">]>
<request><orderId>&xxe;</orderId></request>
"""
    with pytest.raises(ValidationError):
        validate_xml(payload, XSD)
