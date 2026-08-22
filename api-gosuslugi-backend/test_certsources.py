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


# ---------- Копии ключей ----------


def test_backups_are_listed_newest_first(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([0, 0]))
    sources.delete_certificate(THUMB)
    # Вторая копия делается из того, что осталось: контейнер на месте.
    sources.delete_certificate(THUMB)

    listed = sources.list_key_backups()

    assert len(listed) == 2
    assert listed[0]["name"] > listed[1]["name"]
    assert listed[0]["containers"][0]["name"] == "xxx.000"
    assert "UTC" in listed[0]["made_at"]


def test_restore_puts_the_container_back(sources, monkeypatch, tmp_path):
    monkeypatch.setattr(sources, "_run", fake_run([0]))
    sources.delete_certificate(THUMB)
    backup = sources.list_key_backups()[0]["name"]
    # Повторяем то, что делает certmgr: контейнер исчез вместе с сертификатом.
    container = tmp_path / "keys" / "xxx.000"
    for path in container.iterdir():
        path.unlink()

    result = sources.restore_key_backup(backup)

    assert sorted(path.name for path in container.iterdir()) == ["header.key", "primary.key"]
    assert len(result["restored"]) == 2


def test_restore_does_not_overwrite_a_working_key(sources, monkeypatch, tmp_path):
    monkeypatch.setattr(sources, "_run", fake_run([0]))
    sources.delete_certificate(THUMB)
    backup = sources.list_key_backups()[0]["name"]
    (tmp_path / "keys" / "xxx.000" / "primary.key").write_bytes("новый ключ".encode())

    result = sources.restore_key_backup(backup)

    assert (tmp_path / "keys" / "xxx.000" / "primary.key").read_bytes() == "новый ключ".encode()
    assert any("уже на месте" in line for line in result["skipped"])


def test_backup_name_is_checked(sources):
    for bad in ("", "../etc", "keys-backup-x", "keys-backup-20260821"):
        with pytest.raises(ValueError):
            sources.restore_key_backup(bad)
