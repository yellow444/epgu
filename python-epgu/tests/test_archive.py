import io
import zipfile

import pytest

from epgu import OrderArchive
from epgu.errors import SignatureError, ValidationError
from epgu.signature import CallableSigner


def test_archive_builds_zip_with_signatures():
    signer = CallableSigner(lambda data: b"SIG:" + data)
    archive = OrderArchive(signer=signer)
    archive.add_file("req.xml", "<req/>")
    archive.add_signed_file("piev_epgu.xml", b"<piev/>")

    assert archive.filenames == ["req.xml", "piev_epgu.xml", "piev_epgu.xml.sig"]

    zf = zipfile.ZipFile(io.BytesIO(archive.to_bytes()))
    assert set(zf.namelist()) == {"req.xml", "piev_epgu.xml", "piev_epgu.xml.sig"}
    assert zf.read("piev_epgu.xml.sig") == b"SIG:<piev/>"
    assert zf.read("req.xml") == b"<req/>"


def test_archive_requires_signer_for_signed_file():
    archive = OrderArchive()
    with pytest.raises(ValidationError):
        archive.add_file("a.xml", b"x", sign=True)


def test_empty_archive_raises():
    with pytest.raises(ValidationError):
        OrderArchive().to_bytes()


@pytest.mark.parametrize("name", ["", "../secret", "/absolute", "C:\\secret", "a//b", "a\\..\\b"])
def test_archive_rejects_unsafe_names(name):
    with pytest.raises(ValidationError, match="имя"):
        OrderArchive().add_file(name, b"x")


def test_archive_rejects_duplicate_and_signature_name_collisions():
    signer = CallableSigner(lambda data: b"signature")
    archive = OrderArchive(signer=signer).add_signed_file("request.xml", b"x")
    with pytest.raises(ValidationError, match="уже"):
        archive.add_file("request.xml", b"y")
    with pytest.raises(ValidationError, match="уже"):
        archive.add_file("request.xml.sig", b"y")


def test_archive_rejects_unsafe_signature_suffix():
    with pytest.raises(ValidationError, match="sig_suffix"):
        OrderArchive(sig_suffix="../sig")


def test_callable_signer_validates_return_type():
    bad = CallableSigner(lambda data: "not-bytes")
    with pytest.raises(SignatureError):
        bad.sign(b"x")


def test_callable_signer_wraps_external_error():
    def fail(data):
        raise RuntimeError("offline")

    with pytest.raises(SignatureError) as caught:
        CallableSigner(fail).sign(b"x")
    assert "offline" not in str(caught.value)


def test_signature_module_lazy_attribute():
    import epgu.signature as signature

    assert signature.CryptoProSigner.__name__ == "CryptoProSigner"
    with pytest.raises(AttributeError):
        signature.__getattr__("MissingSigner")


def test_cryptopro_signer_requires_explicit_certificate_thumbprint():
    from epgu.signature import CryptoProSigner

    with pytest.raises(SignatureError, match="отпечаток"):
        CryptoProSigner("   ")
