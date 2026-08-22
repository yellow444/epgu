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


# ---------- Запрос на сертификат для удостоверяющего центра ----------


PROFILE = {
    "ORG_FULL_NAME": "ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ КВИК РЕСТО",
    "ORG_INN": "7726734798",
    "ORG_OGRN": "5137746099046",
    "CONTACT_NAME": "Ситников Максим Валериевич",
    "CONTACT_ROLE": "Генеральный директор",
    "CONTACT_EMAIL": "smev@mirasnowfox.ru",
    "CONTACT_SNILS": "127-439-029 61",
}


def test_request_name_is_built_from_the_profile(sources):
    rdn = sources.request_rdn(PROFILE)

    assert rdn.startswith("CN=ОБЩЕСТВО С ОГРАНИЧЕННОЙ")
    assert "INN=7726734798" in rdn
    assert "OGRN=5137746099046" in rdn
    assert "SNILS=127-439-029 61" in rdn
    # Фамилия и имя идут отдельными полями, как в сертификате от УЦ РТК.
    assert "SN=Ситников" in rdn
    assert "G=Максим Валериевич" in rdn
    assert rdn.endswith("C=RU")


def test_empty_profile_fields_are_skipped(sources):
    rdn = sources.request_rdn({"ORG_FULL_NAME": "ООО Ромашка", "CONTACT_NAME": ""})

    assert rdn == "CN=ООО Ромашка,O=ООО Ромашка,C=RU"


def test_missing_fields_are_named(sources):
    missing = sources.missing_for_request({"ORG_FULL_NAME": "ООО Ромашка"})

    assert "ИНН" in missing
    assert "ОГРН" in missing
    assert "ФИО владельца" in missing
    assert sources.missing_for_request(PROFILE) == []


def test_container_name_is_checked(sources, monkeypatch):
    monkeypatch.setattr(sources, "_run", fake_run([]))
    for bad in ("", "ab", "имя", "name; rm -rf /", "a" * 41):
        with pytest.raises(ValueError):
            sources.create_request(container=bad, rdn="CN=X")


def test_dangerous_name_is_refused(sources):
    for bad in ('CN="X"', "CN=X\nO=Y", "CN=$(whoami)", "CN=X; rm -rf /"):
        with pytest.raises(ValueError):
            sources.create_request(container="epgu-test", rdn=bad)


def test_existing_request_is_not_overwritten(sources):
    (sources.cert_dir() / "epgu-test.req").write_text("уже есть", encoding="utf-8")

    with pytest.raises(ValueError):
        sources.create_request(container="epgu-test", rdn="CN=X")


def test_without_cryptopro_the_request_is_refused(sources, monkeypatch):
    monkeypatch.setattr(sources, "cryptopro_available", lambda: False)

    with pytest.raises(RuntimeError):
        sources.create_request(container="epgu-test", rdn="CN=X")


def test_error_text_explains_entropy_failure(sources):
    assert "энтропия" in sources._request_error("ErrorCode: 0x80090020").lower()
    assert "уже есть" in sources._request_error("Error: Object already exists 0x8009000F")


# ---------- Доверие тестовому удостоверяющему центру ----------


def test_ca_roots_are_installed_into_their_stores(sources, monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def read(self, limit=None):
            return self.payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    import urllib.request

    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout=30: FakeResponse(b"cert-" + url.encode()[-9:])
    )

    def runner(args, timeout=20):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="Subject: Тестовый УЦ", stderr="")

    monkeypatch.setattr(sources, "_run", runner)

    result = sources.trust_test_ca()

    stores = [item["store"] for item in result["installed"]]
    assert stores == ["mroot", "uCA"]
    assert result["failed"] == []
    # Корневой идёт в доверенные корни, промежуточный в промежуточные.
    assert any("-store" in call and "mroot" in call for call in calls)
    assert any("-store" in call and "uCA" in call for call in calls)


def test_root_waits_for_restart_when_store_is_locked(sources, monkeypatch):
    """Доверенные корни машины пишет только root, приложение работает не им."""

    class FakeResponse:
        def read(self, limit=None):
            return b"cert"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout=30: FakeResponse())
    # certmgr отказывает и на установке, и на чтении: прав нет ни там, ни там.
    monkeypatch.setattr(
        sources,
        "_run",
        lambda args, timeout=20: subprocess.CompletedProcess(args, 1, stdout="", stderr=""),
    )

    result = sources.trust_test_ca()

    assert result["installed"] == []
    assert len(result["pending"]) == 2
    # Файл лежит там, откуда entrypoint ставит корни при старте.
    assert result["pending"][0]["file"].endswith("test-root.cer")
    assert (sources.keys_dir() / "ca-trust" / "test-root.cer").exists()


def test_unreachable_ca_is_reported_not_hidden(sources, monkeypatch):
    import urllib.request

    def boom(url, timeout=30):
        raise OSError("нет сети")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(sources, "_run", fake_run([]))

    result = sources.trust_test_ca()

    assert result["installed"] == []
    assert len(result["failed"]) == 2
