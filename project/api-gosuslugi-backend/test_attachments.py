"""Разбор вложений: PDF, документы Word, архивы, сертификаты."""

from __future__ import annotations

import io
import zipfile
import zlib

import pytest

import attachments


def make_pdf(text: str, *, with_embedded: bool = False) -> bytes:
    """Маленький PDF со сжатым потоком текста, как их отдают конвертеры."""
    literal = text.replace("(", r"\(").replace(")", r"\)")
    stream = zlib.compress(("BT (" + literal + ") Tj ET").encode("cp1251"))
    body = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Count 3>>endobj\n"
    body += b"2 0 obj<</Length " + str(len(stream)).encode() + b"/Filter/FlateDecode>>stream\n"
    body += stream + b"\nendstream endobj\n"
    if with_embedded:
        payload = zlib.compress(b"CONTAINER-BYTES")
        body += b"3 0 obj<</Type/EmbeddedFile/Length " + str(len(payload)).encode() + b">>stream\n"
        body += payload + b"\nendstream endobj\n"
    body += b"trailer<</Root 1 0 R>>\n%%EOF"
    return body


def make_docx(text: str, *, embedded=()) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "word/document.xml",
            "<w:document><w:body><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:body></w:document>" % text,
        )
        for name, payload in embedded:
            archive.writestr("word/embeddings/" + name, payload)
    return buffer.getvalue()


def make_zip(entries) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return buffer.getvalue()


# --- определение типа ----------------------------------------------------


@pytest.mark.parametrize(
    "name, payload, expected",
    [
        ("instr.pdf", b"%PDF-1.4 ...", "pdf"),
        ("cert.cer", b"0\x82\x03\x00", "certificate"),
        ("chain.p7b", b"anything", "certificate"),
        ("primary.key", b"\x00\x01", "key"),
        ("readme.txt", "просто текст".encode("utf-8"), "unknown"),
    ],
)
def test_kind_is_detected(tmp_path, name, payload, expected):
    path = tmp_path / name
    path.write_bytes(payload)
    assert attachments.kind_of(path) == expected


def test_docx_and_zip_are_told_apart(tmp_path):
    docx = tmp_path / "instruction.docx"
    docx.write_bytes(make_docx("текст"))
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(make_zip([("cert.cer", b"0\x82")]))

    assert attachments.kind_of(docx) == "docx"
    assert attachments.kind_of(archive) == "archive"


# --- PDF ------------------------------------------------------------------


def test_pdf_text_and_links_are_extracted(tmp_path):
    path = tmp_path / "instruction.pdf"
    path.write_bytes(make_pdf(
        "Тестовый УЦ доступен по адресу https://testca2012.cryptopro.ru/ui/ "
        "ПИН-код контейнера 1234567890"
    ))

    result = attachments.describe(path)

    assert result["kind"] == "pdf"
    assert "Тестовый УЦ" in result["text"]
    assert "https://testca2012.cryptopro.ru/ui/" in result["links"]
    assert any("1234567890" in hint for hint in result["hints"])


def test_pdf_without_embedded_files_says_so(tmp_path):
    """Случай из жизни: значки контейнеров видны, а файлов в PDF нет."""
    path = tmp_path / "instruction.pdf"
    path.write_bytes(make_pdf("Используйте тестовые контейнеры e22c7385.000 и e7d05a2b.000"))

    result = attachments.describe(path)

    assert result["entries"] == []
    assert any("исходный документ" in hint for hint in result["hints"])


def test_pdf_with_embedded_file_is_reported(tmp_path):
    path = tmp_path / "with-file.pdf"
    path.write_bytes(make_pdf("контейнер внутри", with_embedded=True))

    result = attachments.describe(path)

    assert len(result["entries"]) == 1
    assert result["entries"][0]["size"] > 0


# --- документы и архивы ---------------------------------------------------


def test_docx_text_and_embedded_objects(tmp_path):
    path = tmp_path / "instruction.docx"
    path.write_bytes(make_docx("Инструкция по работе", embedded=[("oleObject1.bin", b"OLE")]))

    result = attachments.describe(path)

    assert result["kind"] == "docx"
    assert "Инструкция по работе" in result["text"]
    assert result["entries"][0]["name"] == "word/embeddings/oleObject1.bin"
    assert any("извлечь" in hint for hint in result["hints"])


def test_archive_points_at_certificates_and_containers(tmp_path):
    path = tmp_path / "bundle.zip"
    path.write_bytes(make_zip([
        ("org.cer", b"0\x82"),
        ("xxx.000/primary.key", b"\x00"),
        ("xxx.000/header.key", b"\x00"),
    ]))

    result = attachments.describe(path)

    assert any("org.cer" in hint for hint in result["hints"])
    assert any("контейнер" in hint.lower() for hint in result["hints"])


def test_extract_puts_files_next_to_the_archive(tmp_path):
    path = tmp_path / "bundle.zip"
    path.write_bytes(make_zip([("org.cer", b"0\x82\x03"), ("readme.txt", "текст".encode("utf-8"))]))
    target = tmp_path / "out"

    result = attachments.extract(path, target)

    names = sorted(item["name"] for item in result["extracted"])
    assert names == ["org.cer", "readme.txt"]
    assert (target / "org.cer").read_bytes() == b"0\x82\x03"
    assert result["extracted"][0]["kind"] in {"certificate", "unknown"}


def test_extract_can_take_one_entry(tmp_path):
    path = tmp_path / "bundle.zip"
    path.write_bytes(make_zip([("org.cer", b"0\x82"), ("junk.bin", b"x")]))
    target = tmp_path / "out"

    result = attachments.extract(path, target, only=["org.cer"])

    assert [item["name"] for item in result["extracted"]] == ["org.cer"]
    assert not (target / "junk.bin").exists()


def test_paths_from_the_archive_never_escape(tmp_path):
    """Имена внутри архива приходят снаружи и попадают в путь на диске."""
    path = tmp_path / "evil.zip"
    path.write_bytes(make_zip([("../../etc/passwd", b"root"), ("dir/sub/ok.cer", b"0\x82")]))
    target = tmp_path / "out"

    result = attachments.extract(path, target)

    names = sorted(item["name"] for item in result["extracted"])
    assert names == ["ok.cer", "passwd"]
    assert not (tmp_path / "etc").exists()


def test_extract_refuses_plain_files(tmp_path):
    path = tmp_path / "cert.cer"
    path.write_bytes(b"0\x82")

    result = attachments.extract(path, tmp_path / "out")

    assert result["extracted"] == []
    assert result["skipped"]


def test_missing_file_is_reported(tmp_path):
    assert attachments.describe(tmp_path / "нет.pdf") == {"exists": False}
