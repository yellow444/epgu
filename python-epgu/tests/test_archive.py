import io
import zipfile

import pytest

from epgu import OrderArchive
from epgu.errors import ValidationError
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


def test_callable_signer_validates_return_type():
    from epgu.errors import SignatureError

    bad = CallableSigner(lambda data: "not-bytes")
    with pytest.raises(SignatureError):
        bad.sign(b"x")
