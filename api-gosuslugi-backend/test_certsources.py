"""Удаление сертификата: проверки, копия ключей, аккуратность с ключевым контейнером."""

from __future__ import annotations

import importlib
import subprocess

import pytest


@pytest.fixture()
def sources(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_INBOX_DIR", str(tmp_path / "inbox"))
    monkeypatch.setenv("KEYS_DIR", str(tmp_path / "keys"))

    import certsources

    importlib.reload(certsources)
    (tmp_path / "inbox").mkdir()
    container = tmp_path / "keys" / "xxx.000"
    container.mkdir(parents=True)
    for name in ("primary.key", "header.key"):
        (container / name).write_bytes(b"key")
    monkeypatch.setattr(certsources, "cryptopro_available", lambda: True)
    return certsources


def fake_run(results):
    """Подменяем certmgr: тесты не должны зависеть от установленного КриптоПро."""
    calls = []

    def runner(args, timeout=20):
        calls.append(args)
        code = results.pop(0) if results else 0
        return subprocess.CompletedProcess(args, code, stdout="вывод certmgr", stderr="")

    runner.calls = calls
    return runner


THUMB = "f1c9f89a7f2544dfea66437867bff4155a0b4c97"


def test_thumbprint_is_checked(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([]))
    for bad in ("", "не отпечаток", "f1c9", THUMB + "00"):
        with pytest.raises(ValueError):
            sources.delete_certificate(bad)


def test_store_is_checked(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([]))
    with pytest.raises(ValueError):
        sources.delete_certificate(THUMB, store="uSomething")


def test_without_cryptopro_it_refuses(sources, monkeypatch):
    monkeypatch.setattr(sources, "cryptopro_available", lambda: False)
    with pytest.raises(RuntimeError):
        sources.delete_certificate(THUMB)


def test_keys_are_copied_before_deleting(sources, monkeypatch):
    """certmgr уносит ключевой контейнер вместе с сертификатом."""
    monkeypatch.setattr(sources, "_run", fake_run([0]))

    result = sources.delete_certificate(THUMB)

    assert result["deleted"] is True
    backup = sources.cert_dir().glob("keys-backup-*")
    copied = sorted(path.name for path in next(backup).glob("xxx.000/*"))
    assert copied == ["header.key", "primary.key"]
    assert result["keys_backup"]


def test_both_places_are_cleaned(sources, monkeypatch):
    runner = fake_run([0, 0])
    monkeypatch.setattr(sources, "_run", runner)

    result = sources.delete_certificate(THUMB, containers=["\\\\.\\HDIMAGE\\biokey"])

    assert result["removed_from"] == ["uMy", "\\\\.\\HDIMAGE\\biokey"]
    assert any("-container" in " ".join(call) for call in runner.calls)
    assert all("-silent" in call for call in runner.calls)


def test_failure_is_reported_without_pretending(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([44]))

    result = sources.delete_certificate(THUMB)

    assert result["deleted"] is False
    assert result["removed_from"] == []


def test_remaining_containers_are_listed(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([0]))

    result = sources.delete_certificate(THUMB)

    # Контейнер на месте: подменённый certmgr ничего не удалял.
    assert result["keys_left"] == ["xxx.000"]


def test_backup_is_skipped_when_there_are_no_keys(sources, monkeypatch, tmp_path):
    for path in (tmp_path / "keys" / "xxx.000").iterdir():
        path.unlink()
    (tmp_path / "keys" / "xxx.000").rmdir()
    monkeypatch.setattr(sources, "_run", fake_run([0]))

    result = sources.delete_certificate(THUMB)

    assert result["keys_backup"] == ""
