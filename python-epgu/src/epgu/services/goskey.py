# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Typed contracts for the four Goskey services published in API EPGU.

The module deliberately separates *documented* contracts from contracts that
are safe to generate.  Official specifications sometimes disagree with their
embedded XSD.  Such variants remain discoverable through :data:`CAPABILITIES`,
but :meth:`to_xml` fails closed until an unambiguous schema is published.

XML is built with ``lxml`` qualified names; values are never interpolated into
markup.  Install the ``xml`` extra to use XML and manifest helpers::

    pip install "epgu-api[xml]"
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from ..archive import OrderArchive
from ..errors import ConfigError, ValidationError
from ..signature.base import Signer

MAX_DIRECT_ARCHIVE_BYTES = 50_000_000
MAX_DOCUMENT_BYTES = 100_000_000
REQUEST_FILENAME = "req.xml"
SIGNATURE_SUFFIX = ".sig"

_SNILS_RE = re.compile(r"^[0-9]{3}-[0-9]{3}-[0-9]{3} [0-9]{2}$")
_OID_RE = re.compile(r"^[^\x00-\x1f]{1,20}$")
_OGRN_RE = re.compile(r"^(?:[0-9]{11}|[0-9]{13}|[0-9]{15})$")
_RAFP_RE = re.compile(r"^[0-9]{11}$")
_INN_USER_RE = re.compile(r"^[0-9]{12}$")
_USER_ID_RE = re.compile(r"^[0-9]{1,20}$")
_DOCUMENT_NAME_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9_ .,\u2019']+$")
_MOSCOW_OFFSET = timedelta(hours=3)


class GoskeyOperation(str, Enum):
    """Business operation exposed by a Goskey EPGU service."""

    SIGN_INDIVIDUAL = "sign-individual"
    SIGN_LEGAL_ENTITY = "sign-legal-entity"
    DECIPHER = "decipher"
    SIGN_TREASURY = "sign-treasury"


class SigningVariant(str, Enum):
    """Recipient signature type for service ``10000000374``."""

    UNEP = "unep"
    UKEP = "ukep"


class DecipherSignOption(str, Enum):
    """Allowed ``signOption`` value from service ``60079416`` XSD."""

    GOSKEY_CHIEF = "DECIPHER_GOSKEY_CHIEF"


class CapabilityState(str, Enum):
    """Confidence level of a locally implemented official contract."""

    VERIFIED = "verified"
    REFERENCE = "reference"
    UNSUPPORTED = "unsupported"


class TransportMode(str, Enum):
    """Submission sequence selected for a prepared ZIP archive."""

    PUSH = "push"
    ORDER_CHUNKED = "order+chunked"


class GoskeyContractError(ValidationError):
    """Base error for invalid or contradictory Goskey contracts."""


class UnsupportedGoskeyContractError(GoskeyContractError):
    """Raised before generation when official sources are contradictory."""


@dataclass(frozen=True)
class GoskeyCapability:
    """Machine-readable status of one service/variant contract."""

    operation: GoskeyOperation
    service_code: str
    target_code: str
    root_name: str
    namespace: str
    state: CapabilityState
    spec_version: str
    spec_date: str
    source_sha256: str
    schema_sha256: Optional[str]
    max_documents: int
    allowed_extensions: Tuple[str, ...]
    variant: Optional[SigningVariant] = None
    contradictions: Tuple[str, ...] = ()

    def require_verified(self) -> None:
        """Fail closed unless this exact contract has verified schema coverage."""

        if self.state is CapabilityState.VERIFIED:
            return
        detail = "; ".join(self.contradictions) or "contract is not verified"
        raise UnsupportedGoskeyContractError(
            "Goskey contract {0}/{1} is {2}: {3}".format(
                self.service_code,
                self.variant.value if self.variant else self.operation.value,
                self.state.value,
                detail,
            )
        )


_SIGN_EXTENSIONS = (".pdf", ".tif", ".tiff", ".jpg", ".jpeg", ".xml", ".txt")

_CAPABILITY_ITEMS = (
    GoskeyCapability(
        operation=GoskeyOperation.SIGN_INDIVIDUAL,
        variant=SigningVariant.UNEP,
        service_code="10000000374",
        target_code="-10000000374",
        root_name="SignRequest",
        namespace="urn://mpkey.gosuslugi.ru/sign_document/1.0.0",
        state=CapabilityState.VERIFIED,
        spec_version="1.9",
        spec_date="2025-08-28",
        source_sha256="ad78aacb591ef37989e6fdd1dd715bfb1b8ec486b13e16e4bca5a9b00a9eab1d",
        schema_sha256="f46480dbe996a62bb7a1fd9201fc47115bd3616befb27eff03377351523a206b",
        max_documents=20,
        allowed_extensions=_SIGN_EXTENSIONS,
        contradictions=(
            "The copied DOCX XML example contains non-breaking spaces in markup; "
            "the embedded XSD is used as the normative source.",
        ),
    ),
    GoskeyCapability(
        operation=GoskeyOperation.SIGN_INDIVIDUAL,
        variant=SigningVariant.UKEP,
        service_code="10000000374",
        target_code="-10000000374",
        root_name="SignRequest",
        namespace="urn://mpkey.gosuslugi.ru/sign_document_ukep/1.0.0",
        state=CapabilityState.REFERENCE,
        spec_version="1.9",
        spec_date="2025-08-28",
        source_sha256="ad78aacb591ef37989e6fdd1dd715bfb1b8ec486b13e16e4bca5a9b00a9eab1d",
        schema_sha256=None,
        max_documents=20,
        allowed_extensions=_SIGN_EXTENSIONS,
        contradictions=(
            "The specification names the UKEP namespace and says both variants have the same "
            "structure, but publishes only the UNEP targetNamespace XSD.",
        ),
    ),
    GoskeyCapability(
        operation=GoskeyOperation.SIGN_LEGAL_ENTITY,
        service_code="60025907",
        target_code="-60025907",
        root_name="SignRequest",
        namespace="urn://mpkey.gosuslugi.ru/sign_document_ukep_legalperson/1.0.0",
        state=CapabilityState.VERIFIED,
        spec_version="1.1",
        spec_date="2025-08-28",
        source_sha256="383ecf11f75bcee0221c57990b0a4be6943e0e56d1e76effebfa815f44dc3343",
        schema_sha256="3b3fa3ca3e0cecb384dbb0169f421e62ea953a66080208d7f00fb1d1e13cd4ef",
        max_documents=20,
        allowed_extensions=_SIGN_EXTENSIONS,
        contradictions=(
            "Table 4 marks Description as 0..1 while the embedded XSD requires it; generation "
            "follows the XSD.",
        ),
    ),
    GoskeyCapability(
        operation=GoskeyOperation.DECIPHER,
        service_code="60079416",
        target_code="-60079416",
        root_name="DecipheringRequest",
        namespace="urn://mpkey.gosuslugi.ru/deciphering_document/1.0.0",
        state=CapabilityState.REFERENCE,
        spec_version="1.0",
        spec_date="2025-11-01",
        source_sha256="91348129c8cd19557d40600c8c6c647fe0458a564d8869978c9746a2d85aa826",
        schema_sha256="84310f7f2a753790f4f1427ba9c00e3ae1ad1f698a4d355fcdc062495714bd0f",
        max_documents=50,
        allowed_extensions=(".enc",),
        contradictions=(
            "Table 4 calls the Document child FileName, but the embedded XSD calls it Description.",
            "The archive table allows 50 documents, while the XSD allows at most 20 "
            "Document nodes.",
            "The only request example omits Document, so it does not resolve either conflict.",
        ),
    ),
    GoskeyCapability(
        operation=GoskeyOperation.SIGN_TREASURY,
        service_code="60080470",
        target_code="-60080470",
        root_name="SignRequest",
        namespace="urn://mpkey.gosuslugi.ru/sign_document_ukep_roskazna/1.0.0",
        state=CapabilityState.VERIFIED,
        spec_version="1.0",
        spec_date="2026-02-25",
        source_sha256="a153bc7f383d5ed1774b405829626686f2704634c03ba2cd2153d57bf2e95a02",
        schema_sha256="af4831fac4ad63e47da96c020833ba730022903d1bbd4dd4c39029860ee8715a",
        max_documents=50,
        allowed_extensions=_SIGN_EXTENSIONS,
        contradictions=(
            "The result-download prose mistakenly names eServiceCode 60025907; its request meta "
            "and download example use 60080470.",
        ),
    ),
)

CAPABILITIES = MappingProxyType(
    {(item.operation, item.variant): item for item in _CAPABILITY_ITEMS}
)
"""Immutable registry of all currently documented Goskey contracts."""


def capability_for(
    operation: GoskeyOperation,
    variant: Optional[SigningVariant] = None,
) -> GoskeyCapability:
    """Return the exact capability, rejecting invalid operation/variant pairs."""

    try:
        operation = GoskeyOperation(operation)
    except (TypeError, ValueError) as exc:
        raise GoskeyContractError("Unknown Goskey operation: {0!r}".format(operation)) from exc
    if variant is not None:
        try:
            variant = SigningVariant(variant)
        except (TypeError, ValueError) as exc:
            raise GoskeyContractError("Unknown signing variant: {0!r}".format(variant)) from exc
    try:
        return CAPABILITIES[(operation, variant)]
    except KeyError as exc:
        if operation is GoskeyOperation.SIGN_INDIVIDUAL:
            message = "SIGN_INDIVIDUAL requires variant UNEP or UKEP"
        else:
            message = "{0} does not accept a signing variant".format(operation.value)
        raise GoskeyContractError(message) from exc


def capability_for_service(
    service_code: str,
    variant: Optional[SigningVariant] = None,
) -> GoskeyCapability:
    """Look up a capability by EPGU service code."""

    candidates = [item for item in _CAPABILITY_ITEMS if item.service_code == str(service_code)]
    if not candidates:
        raise GoskeyContractError("Unknown Goskey serviceCode: {0!r}".format(service_code))
    if len(candidates) == 1:
        if variant is not None:
            raise GoskeyContractError(
                "serviceCode {0} does not accept a signing variant".format(service_code)
            )
        return candidates[0]
    if variant is None:
        raise GoskeyContractError(
            "serviceCode {0} requires variant UNEP or UKEP".format(service_code)
        )
    try:
        normalized = SigningVariant(variant)
    except (TypeError, ValueError) as exc:
        raise GoskeyContractError("Unknown signing variant: {0!r}".format(variant)) from exc
    for candidate in candidates:
        if candidate.variant is normalized:
            return candidate
    raise GoskeyContractError("Unsupported service/variant pair")


@dataclass(frozen=True)
class GoskeyAttribute:
    """One official ``AttributeName``/``AttributeValue`` pair."""

    name: str
    value: str

    def __post_init__(self) -> None:
        _validate_text(self.name, "AttributeName", 50)
        _validate_text(self.value, "AttributeValue", 250)


@dataclass(frozen=True)
class IndividualRecipient:
    """Exactly one physical-person identifier: SNILS or ESIA OID."""

    snils: Optional[str] = None
    oid: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_exactly_one(self.snils, self.oid, "snils", "oid")
        if self.snils is not None and not _SNILS_RE.fullmatch(self.snils):
            raise GoskeyContractError("snils must match XXX-XXX-XXX XX")
        if self.oid is not None and not _OID_RE.fullmatch(self.oid):
            raise GoskeyContractError("oid must contain 1..20 characters without controls")


@dataclass(frozen=True)
class RussianLegalRecipient:
    """Russian company or sole proprietor recipient for service ``60025907``."""

    ogrn: str
    snils: Optional[str] = None
    oid: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_exactly_one(self.snils, self.oid, "snils", "oid")
        _validate_ogrn(self.ogrn)
        if self.snils is not None and not _SNILS_RE.fullmatch(self.snils):
            raise GoskeyContractError("snils must match XXX-XXX-XXX XX")
        if self.oid is not None and not _OID_RE.fullmatch(self.oid):
            raise GoskeyContractError("oid must contain 1..20 characters without controls")


@dataclass(frozen=True)
class ForeignLegalRecipient:
    """Foreign company/accredited branch recipient for service ``60025907``."""

    rafp: str
    inn_user: str

    def __post_init__(self) -> None:
        if not _RAFP_RE.fullmatch(self.rafp):
            raise GoskeyContractError("rafp must contain exactly 11 digits")
        if not _INN_USER_RE.fullmatch(self.inn_user):
            raise GoskeyContractError("inn_user must contain exactly 12 digits")


@dataclass(frozen=True)
class RussianDecipherRecipient:
    """Russian recipient shape from the ``60079416`` XSD."""

    ogrn: str
    user_id: Optional[str] = None
    snils: Optional[str] = None

    def __post_init__(self) -> None:
        if self.user_id is not None and self.snils is not None:
            raise GoskeyContractError("Only one of user_id and snils may be supplied")
        _validate_ogrn(self.ogrn)
        if self.user_id is not None and not _USER_ID_RE.fullmatch(self.user_id):
            raise GoskeyContractError("user_id must contain 1..20 digits")
        if self.snils is not None and not _SNILS_RE.fullmatch(self.snils):
            raise GoskeyContractError("snils must match XXX-XXX-XXX XX")


@dataclass(frozen=True)
class ForeignDecipherRecipient:
    """Foreign recipient shape from the ``60079416`` XSD."""

    rafp: str
    inn_user: str

    def __post_init__(self) -> None:
        if not _RAFP_RE.fullmatch(self.rafp):
            raise GoskeyContractError("rafp must contain exactly 11 digits")
        if not _INN_USER_RE.fullmatch(self.inn_user):
            raise GoskeyContractError("inn_user must contain exactly 12 digits")


@dataclass(frozen=True)
class IndividualSignRequest:
    """Request for physical-person signing (service ``10000000374``)."""

    variant: SigningVariant
    recipient: IndividualRecipient
    sign_expiration: datetime
    description: str
    attributes: Tuple[GoskeyAttribute, ...]
    backlink: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_request_common(
            self.sign_expiration, self.description, self.backlink, self.attributes
        )

    @property
    def capability(self) -> GoskeyCapability:
        return capability_for(GoskeyOperation.SIGN_INDIVIDUAL, self.variant)

    def to_xml(self) -> bytes:
        """Build XSD-oriented ``req.xml`` or fail for the reference-only UKEP variant."""

        capability = self.capability
        capability.require_verified()
        root = _root(capability)
        _append_individual(root, capability.namespace, self.recipient)
        _append_common_sign_fields(root, capability.namespace, self)
        return _serialize(root)


@dataclass(frozen=True)
class LegalEntitySignRequest:
    """UKEP signing request for a legal entity/IP (service ``60025907``)."""

    recipient: Union[RussianLegalRecipient, ForeignLegalRecipient]
    sign_expiration: datetime
    description: str
    attributes: Tuple[GoskeyAttribute, ...]
    backlink: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.recipient, (RussianLegalRecipient, ForeignLegalRecipient)):
            raise GoskeyContractError("recipient has an invalid type for service 60025907")
        _validate_request_common(
            self.sign_expiration, self.description, self.backlink, self.attributes
        )

    @property
    def capability(self) -> GoskeyCapability:
        return capability_for(GoskeyOperation.SIGN_LEGAL_ENTITY)

    def to_xml(self) -> bytes:
        """Build a deterministic ``SignRequest`` matching the embedded official XSD."""

        capability = self.capability
        capability.require_verified()
        root = _root(capability)
        namespace = capability.namespace
        if isinstance(self.recipient, RussianLegalRecipient):
            section = _subelement(root, namespace, "RFOrg")
            _append_identifier(section, namespace, self.recipient.snils, self.recipient.oid)
            _text_element(section, namespace, "OGRN", self.recipient.ogrn)
        else:
            section = _subelement(root, namespace, "ForeignOrg")
            _text_element(section, namespace, "RAFP", self.recipient.rafp)
            _text_element(section, namespace, "INN_user", self.recipient.inn_user)
        _append_common_sign_fields(root, namespace, self)
        return _serialize(root)


@dataclass(frozen=True)
class TreasurySignRequest:
    """Treasury-certificate UKEP signing request (service ``60080470``)."""

    recipient: IndividualRecipient
    sign_expiration: datetime
    description: str
    attributes: Tuple[GoskeyAttribute, ...]
    backlink: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_request_common(
            self.sign_expiration, self.description, self.backlink, self.attributes
        )

    @property
    def capability(self) -> GoskeyCapability:
        return capability_for(GoskeyOperation.SIGN_TREASURY)

    def to_xml(self) -> bytes:
        """Build a deterministic ``SignRequest`` matching the embedded official XSD."""

        capability = self.capability
        capability.require_verified()
        root = _root(capability)
        _append_individual(root, capability.namespace, self.recipient)
        _append_common_sign_fields(root, capability.namespace, self)
        return _serialize(root)


@dataclass(frozen=True)
class DecipherDocument:
    """Document metadata recorded by the contradictory ``60079416`` sources."""

    file_name: str
    full_path_elements: Tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_text(self.file_name, "file_name", 250)
        paths = tuple(self.full_path_elements)
        if not 1 <= len(paths) <= 10:
            raise GoskeyContractError("full_path_elements must contain 1..10 values")
        for path in paths:
            _validate_text(path, "FullPathElement", 10_000)
        object.__setattr__(self, "full_path_elements", paths)


@dataclass(frozen=True)
class DecipherRequest:
    """Reference-only request for service ``60079416``.

    The type exposes the published fields, but XML generation is blocked because
    the field name and multiplicity for ``Document`` disagree between Table 4
    and the embedded XSD.
    """

    recipient: Union[RussianDecipherRecipient, ForeignDecipherRecipient]
    expiration: datetime
    description: str
    attributes: Tuple[GoskeyAttribute, ...]
    documents: Tuple[DecipherDocument, ...] = ()
    backlink: Optional[str] = None
    sign_option: DecipherSignOption = DecipherSignOption.GOSKEY_CHIEF

    def __post_init__(self) -> None:
        if not isinstance(self.recipient, (RussianDecipherRecipient, ForeignDecipherRecipient)):
            raise GoskeyContractError("recipient has an invalid type for service 60079416")
        _validate_request_common(self.expiration, self.description, self.backlink, self.attributes)
        documents = tuple(self.documents)
        if len(documents) > 50:
            raise GoskeyContractError("documents exceeds the archive-table limit of 50")
        if any(not isinstance(item, DecipherDocument) for item in documents):
            raise GoskeyContractError("documents must contain DecipherDocument values")
        object.__setattr__(self, "documents", documents)
        try:
            object.__setattr__(self, "sign_option", DecipherSignOption(self.sign_option))
        except (TypeError, ValueError) as exc:
            raise GoskeyContractError("Unknown decipher sign_option") from exc

    @property
    def capability(self) -> GoskeyCapability:
        return capability_for(GoskeyOperation.DECIPHER)

    def to_xml(self) -> bytes:
        """Always fail closed until the official ``Document`` conflict is resolved."""

        self.capability.require_verified()
        raise AssertionError(  # pragma: no cover
            "reference capability unexpectedly became verified"
        )


@dataclass(frozen=True)
class ManifestReport:
    """Result of structural detached-signature manifest validation."""

    service_code: str
    payload_names: Tuple[str, ...]
    signature_names: Tuple[str, ...]
    document_count: int
    document_bytes: int
    cryptographic_signatures_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class TransportDecision:
    """Selected API sequence for an already built archive."""

    mode: TransportMode
    endpoint: str
    reserve_order: bool
    order_id: Optional[int]


def select_transport(archive_size: int, order_id: Optional[int] = None) -> TransportDecision:
    """Apply the Goskey threshold exactly.

    ``push`` is selected only when the ZIP is at most 50,000,000 bytes and no
    order has been reserved.  Every other case uses ``order`` + ``push/chunked``.
    """

    if isinstance(archive_size, bool) or not isinstance(archive_size, int) or archive_size <= 0:
        raise GoskeyContractError("archive_size must be a positive integer")
    if order_id is not None and (
        isinstance(order_id, bool) or not isinstance(order_id, int) or order_id <= 0
    ):
        raise GoskeyContractError("order_id must be a positive integer")
    if archive_size <= MAX_DIRECT_ARCHIVE_BYTES and order_id is None:
        return TransportDecision(TransportMode.PUSH, "/api/gusmev/push", False, None)
    return TransportDecision(
        TransportMode.ORDER_CHUNKED,
        "/api/gusmev/push/chunked",
        order_id is None,
        order_id,
    )


def validate_submission_window(
    expiration: datetime,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Validate the official Goskey signing window at submission time.

    Request objects validate the wire format only, so they remain deterministic
    and may be prepared in advance.  Call this immediately before submission:
    the deadline must be in the future, use Moscow UTC+03:00 and be no more
    than 24 hours from ``now``.
    """

    if not isinstance(expiration, datetime) or expiration.tzinfo is None:
        raise GoskeyContractError("expiration must be a timezone-aware datetime")
    if expiration.utcoffset() != _MOSCOW_OFFSET:
        raise GoskeyContractError("expiration must use Moscow UTC+03:00")
    current = now or datetime.now(expiration.tzinfo)
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise GoskeyContractError("now must be a timezone-aware datetime")
    current_moscow = current.astimezone(expiration.tzinfo)
    remaining = expiration - current_moscow
    if remaining <= timedelta(0):
        raise GoskeyContractError("expiration must be in the future")
    if remaining > timedelta(hours=24):
        raise GoskeyContractError("expiration must be no more than 24 hours from submission")


BytesValue = Union[bytes, bytearray, memoryview]


def validate_detached_signature_manifest(
    members: Mapping[str, BytesValue],
    *,
    service_code: str,
    variant: Optional[SigningVariant] = None,
) -> ManifestReport:
    """Validate archive members without pretending to verify CAdES cryptography.

    Every payload, including ``req.xml``, must have a non-empty adjacent
    ``<payload>.sig`` member.  Names must be flat and unambiguous.  The request
    root/namespace, document extension/count and documented 100 MB payload limit
    are also checked.  Actual certificate-chain and signature verification is a
    separate cryptographic responsibility, reflected by the report flag.
    """

    capability = capability_for_service(service_code, variant)
    if not isinstance(members, Mapping) or not members:
        raise GoskeyContractError("manifest must be a non-empty mapping")
    normalized: Dict[str, bytes] = {}
    casefold_names: Dict[str, str] = {}
    for name, content in members.items():
        _validate_archive_name(name)
        folded = name.casefold()
        if folded in casefold_names:
            raise GoskeyContractError(
                "archive names differ only by case: {0!r} and {1!r}".format(
                    casefold_names[folded], name
                )
            )
        casefold_names[folded] = name
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise GoskeyContractError("archive member content must be bytes")
        value = bytes(content)
        if not value:
            raise GoskeyContractError("archive member {0!r} is empty".format(name))
        normalized[name] = value

    payload_names = tuple(name for name in normalized if not name.endswith(SIGNATURE_SUFFIX))
    signature_names = tuple(name for name in normalized if name.endswith(SIGNATURE_SUFFIX))
    if REQUEST_FILENAME not in payload_names:
        raise GoskeyContractError("manifest must contain req.xml")
    for payload_name in payload_names:
        signature_name = payload_name + SIGNATURE_SUFFIX
        if signature_name not in normalized:
            raise GoskeyContractError("missing detached signature {0!r}".format(signature_name))
    for signature_name in signature_names:
        payload_name = signature_name[: -len(SIGNATURE_SUFFIX)]
        if payload_name not in payload_names:
            raise GoskeyContractError("orphan detached signature {0!r}".format(signature_name))

    _validate_request_root(normalized[REQUEST_FILENAME], capability)
    document_names = tuple(name for name in payload_names if name != REQUEST_FILENAME)
    if not document_names:
        raise GoskeyContractError("manifest must contain at least one business document")
    if len(document_names) > capability.max_documents:
        raise GoskeyContractError(
            "document count exceeds the official limit of {0}".format(capability.max_documents)
        )
    for name in document_names:
        _validate_document_name(name, capability.allowed_extensions)
    document_bytes = sum(len(normalized[name]) for name in document_names)
    if document_bytes > MAX_DOCUMENT_BYTES:
        raise GoskeyContractError("business documents exceed the 100,000,000-byte limit")
    return ManifestReport(
        service_code=capability.service_code,
        payload_names=payload_names,
        signature_names=signature_names,
        document_count=len(document_names),
        document_bytes=document_bytes,
    )


RequestType = Union[
    IndividualSignRequest,
    LegalEntitySignRequest,
    TreasurySignRequest,
    DecipherRequest,
]


def build_signed_archive(
    request: RequestType,
    documents: Mapping[str, BytesValue],
    signer: Signer,
) -> bytes:
    """Generate ``req.xml`` and reuse :class:`OrderArchive` to sign every payload."""

    if not isinstance(
        request,
        (IndividualSignRequest, LegalEntitySignRequest, TreasurySignRequest, DecipherRequest),
    ):
        raise GoskeyContractError("request has an unsupported Goskey type")
    if not isinstance(documents, Mapping):
        raise GoskeyContractError("documents must be a mapping")
    request_xml = request.to_xml()
    capability = request.capability
    preflight: Dict[str, bytes] = {
        REQUEST_FILENAME: request_xml,
        REQUEST_FILENAME + SIGNATURE_SUFFIX: b"preflight",
    }
    for name, content in documents.items():
        if name in {REQUEST_FILENAME, REQUEST_FILENAME + SIGNATURE_SUFFIX} or name.endswith(
            SIGNATURE_SUFFIX
        ):
            raise GoskeyContractError("documents must contain unsigned business payloads only")
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise GoskeyContractError("document content must be bytes")
        preflight[name] = bytes(content)
        preflight[name + SIGNATURE_SUFFIX] = b"preflight"
    validate_detached_signature_manifest(
        preflight,
        service_code=capability.service_code,
        variant=capability.variant,
    )

    archive = OrderArchive(signer=signer)
    archive.add_signed_file(REQUEST_FILENAME, request_xml)
    for name, content in documents.items():
        archive.add_signed_file(name, bytes(content))
    result = archive.to_bytes()
    validate_detached_signature_manifest(
        _read_zip_members(result),
        service_code=capability.service_code,
        variant=capability.variant,
    )
    return result


def _validate_text(value: str, field_name: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise GoskeyContractError(
            "{0} must be a non-empty string up to {1} characters".format(field_name, maximum)
        )
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise GoskeyContractError("{0} contains control characters".format(field_name))


def _validate_exactly_one(
    first: Optional[str],
    second: Optional[str],
    first_name: str,
    second_name: str,
) -> None:
    if (first is None) == (second is None):
        raise GoskeyContractError(
            "Exactly one of {0} and {1} must be supplied".format(first_name, second_name)
        )


def _validate_ogrn(value: str) -> None:
    if not _OGRN_RE.fullmatch(value):
        raise GoskeyContractError("ogrn must contain 11, 13 or 15 digits")


def _normalize_attributes(
    attributes: Iterable[GoskeyAttribute],
) -> Tuple[GoskeyAttribute, ...]:
    items = tuple(attributes)
    if len(items) > 10:
        raise GoskeyContractError("attributes must contain at most 10 values")
    if any(not isinstance(item, GoskeyAttribute) for item in items):
        raise GoskeyContractError("attributes must contain GoskeyAttribute values")
    names = [item.name for item in items]
    if len(names) != len(set(names)):
        raise GoskeyContractError("AttributeName values must be unique")
    missing = {"orgName", "orgINN"}.difference(names)
    if missing:
        raise GoskeyContractError(
            "required Goskey attributes are missing: {0}".format(", ".join(sorted(missing)))
        )
    return items


def _validate_request_common(
    expiration: datetime,
    description: str,
    backlink: Optional[str],
    attributes: Sequence[GoskeyAttribute],
) -> None:
    if not isinstance(expiration, datetime) or expiration.tzinfo is None:
        raise GoskeyContractError("expiration must be a timezone-aware datetime")
    if expiration.utcoffset() != _MOSCOW_OFFSET:
        raise GoskeyContractError("expiration must use Moscow UTC+03:00")
    _validate_text(description, "Description", 250)
    if backlink is not None:
        _validate_text(backlink, "Backlink", 250)
    normalized = _normalize_attributes(attributes)
    if isinstance(attributes, tuple) and attributes == normalized:
        return
    # Frozen request dataclasses call this helper only for validation.  Keeping
    # coercion out avoids mutating caller-provided list objects unexpectedly.


def _lxml_etree() -> Any:
    try:
        from lxml import etree  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - exercised without the xml extra
        raise ConfigError("Goskey XML support requires: pip install 'epgu-api[xml]'") from exc
    return etree


def _root(capability: GoskeyCapability) -> Any:
    etree = _lxml_etree()
    return etree.Element(
        etree.QName(capability.namespace, capability.root_name),
        nsmap={None: capability.namespace},
    )


def _subelement(parent: Any, namespace: str, name: str) -> Any:
    etree = _lxml_etree()
    return etree.SubElement(parent, etree.QName(namespace, name))


def _text_element(parent: Any, namespace: str, name: str, value: str) -> Any:
    node = _subelement(parent, namespace, name)
    node.text = value
    return node


def _append_identifier(
    parent: Any,
    namespace: str,
    snils: Optional[str],
    oid: Optional[str],
) -> None:
    if snils is not None:
        _text_element(parent, namespace, "Snils", snils)
    else:
        assert oid is not None
        _text_element(parent, namespace, "OID", oid)


def _append_individual(
    parent: Any,
    namespace: str,
    recipient: IndividualRecipient,
) -> None:
    _append_identifier(parent, namespace, recipient.snils, recipient.oid)


def _format_datetime(value: datetime) -> str:
    if value.microsecond == 0:
        timespec = "seconds"
    elif value.microsecond % 1000 == 0:
        timespec = "milliseconds"
    else:
        timespec = "microseconds"
    return value.isoformat(timespec=timespec)


def _append_common_sign_fields(parent: Any, namespace: str, request: Any) -> None:
    if request.backlink is not None:
        _text_element(parent, namespace, "Backlink", request.backlink)
    _text_element(parent, namespace, "SignExpiration", _format_datetime(request.sign_expiration))
    _text_element(parent, namespace, "Description", request.description)
    _append_attributes(parent, namespace, request.attributes)


def _append_attributes(
    parent: Any,
    namespace: str,
    attributes: Iterable[GoskeyAttribute],
) -> None:
    for attribute in attributes:
        node = _subelement(parent, namespace, "Attribute")
        _text_element(node, namespace, "AttributeName", attribute.name)
        _text_element(node, namespace, "AttributeValue", attribute.value)


def _serialize(root: Any) -> bytes:
    etree = _lxml_etree()
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=False)


def _validate_archive_name(name: str) -> None:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise GoskeyContractError("archive member has an invalid name")
    if "/" in name or posixpath.isabs(name) or name in {".", ".."}:
        raise GoskeyContractError("Goskey archives must be flat and cannot contain paths")
    if len(name) >= 2 and name[1] == ":":
        raise GoskeyContractError("archive member has an absolute Windows path")


def _validate_document_name(name: str, extensions: Tuple[str, ...]) -> None:
    if len(name) > 50:
        raise GoskeyContractError("business document name exceeds 50 characters")
    if not _DOCUMENT_NAME_RE.fullmatch(name):
        raise GoskeyContractError("business document name contains undocumented characters")
    if not any(name.lower().endswith(extension) for extension in extensions):
        raise GoskeyContractError(
            "business document extension must be one of: {0}".format(", ".join(extensions))
        )


def _validate_request_root(xml_content: bytes, capability: GoskeyCapability) -> None:
    etree = _lxml_etree()
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        remove_comments=False,
    )
    try:
        root = etree.fromstring(xml_content, parser)
    except etree.XMLSyntaxError as exc:
        raise GoskeyContractError("req.xml is not well-formed XML: {0}".format(exc)) from exc
    if root.getroottree().docinfo.doctype:
        raise GoskeyContractError("req.xml must not contain a DTD")
    qname = etree.QName(root)
    if qname.localname != capability.root_name or qname.namespace != capability.namespace:
        raise GoskeyContractError(
            "req.xml root must be {{{0}}}{1}".format(capability.namespace, capability.root_name)
        )


def _read_zip_members(content: bytes) -> Mapping[str, bytes]:
    members: Dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
        for info in archive.infolist():
            if info.is_dir() or info.filename in members:
                raise GoskeyContractError("generated archive contains invalid or duplicate members")
            members[info.filename] = archive.read(info)
    return members


__all__ = [
    "CAPABILITIES",
    "MAX_DIRECT_ARCHIVE_BYTES",
    "MAX_DOCUMENT_BYTES",
    "REQUEST_FILENAME",
    "SIGNATURE_SUFFIX",
    "CapabilityState",
    "DecipherDocument",
    "DecipherRequest",
    "DecipherSignOption",
    "ForeignDecipherRecipient",
    "ForeignLegalRecipient",
    "GoskeyAttribute",
    "GoskeyCapability",
    "GoskeyContractError",
    "GoskeyOperation",
    "IndividualRecipient",
    "IndividualSignRequest",
    "LegalEntitySignRequest",
    "ManifestReport",
    "RussianDecipherRecipient",
    "RussianLegalRecipient",
    "SigningVariant",
    "TransportDecision",
    "TransportMode",
    "TreasurySignRequest",
    "UnsupportedGoskeyContractError",
    "build_signed_archive",
    "capability_for",
    "capability_for_service",
    "select_transport",
    "validate_detached_signature_manifest",
    "validate_submission_window",
]
