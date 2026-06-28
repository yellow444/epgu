"""Подписант на КриптоПро CSP через модуль ``pycades``.

``pycades`` распространяется вместе с КриптоПро и не ставится из PyPI, поэтому
импорт выполняется лениво - пакет ``epgu-api`` можно установить и использовать
без КриптоПро (например, с :class:`~epgu.signature.callable.CallableSigner`).
"""

from __future__ import annotations

import base64
from typing import List, Optional

from ..errors import SignatureError


class CryptoProSigner:
    """Формирует отсоединённую подпись CAdES-BES с помощью КриптоПро CSP.

    Args:
        thumbprint: отпечаток (Thumbprint) сертификата в личном хранилище.
            Если ``None`` - берётся первый доступный сертификат.
        pin: PIN контейнера закрытого ключа.
        tsa_address: адрес службы меток времени (для CAdES-T можно указать TSA;
            для CAdES-BES не используется при подписи api-key, но оставлен для
            совместимости с подписью файлов).
        check_certificate: проверять ли цепочку сертификата при подписи.
        add_timestamp: формировать ли CAdES-T (со штампом времени) вместо BES.

    Note:
        Требует установленного КриптоПро CSP и доступного модуля ``pycades``.
    """

    def __init__(
        self,
        thumbprint: Optional[str] = None,
        *,
        pin: Optional[str] = None,
        tsa_address: Optional[str] = None,
        check_certificate: bool = True,
        add_timestamp: bool = False,
    ) -> None:
        try:
            import pycades  # noqa: F401
        except ImportError as exc:  # pragma: no cover - зависит от окружения
            raise SignatureError(
                "Модуль 'pycades' не найден. Установите КриптоПро CSP и pycades "
                "(идут в дистрибутиве КриптоПро) или используйте CallableSigner."
            ) from exc

        self._pycades = pycades
        self.thumbprint = thumbprint
        self.pin = pin
        self.tsa_address = tsa_address
        self.check_certificate = check_certificate
        self.add_timestamp = add_timestamp

    # --- работа с хранилищем сертификатов -------------------------------

    def _open_store(self):
        store = self._pycades.Store()
        store.Open(
            self._pycades.CADESCOM_CONTAINER_STORE,
            self._pycades.CAPICOM_MY_STORE,
            self._pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
        )
        return store

    def list_certificates(self) -> List[dict]:
        """Возвращает список сертификатов личного хранилища (thumbprint + subject)."""
        store = self._open_store()
        try:
            certs = store.Certificates
            result = []
            for i in range(1, certs.Count + 1):
                cert = certs.Item(i)
                result.append({"thumbprint": cert.Thumbprint, "subject": cert.SubjectName})
            return result
        finally:
            store.Close()

    def _find_certificate(self, store):
        certs = store.Certificates
        if certs.Count == 0:
            raise SignatureError("В личном хранилище нет сертификатов")
        if self.thumbprint:
            for i in range(1, certs.Count + 1):
                cert = certs.Item(i)
                if cert.Thumbprint == self.thumbprint:
                    return cert
            raise SignatureError(f"Сертификат с отпечатком {self.thumbprint} не найден")
        return certs.Item(1)

    # --- подпись --------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Подписать ``data``, вернуть DER-байты отсоединённой подписи."""
        pycades = self._pycades
        store = self._open_store()
        try:
            cert = self._find_certificate(store)
            signer = pycades.Signer()
            signer.Certificate = cert
            signer.CheckCertificate = self.check_certificate
            if self.pin is not None:
                signer.KeyPin = self.pin
            if self.tsa_address:
                signer.TSAAddress = self.tsa_address

            signed_data = pycades.SignedData()
            signed_data.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
            signed_data.Content = base64.b64encode(data).decode("ascii")

            cades_type = (
                pycades.CADESCOM_CADES_T if self.add_timestamp else pycades.CADESCOM_CADES_BES
            )
            detached = 1
            signature_b64 = signed_data.SignCades(signer, cades_type, detached)
        except SignatureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SignatureError(f"Ошибка подписи КриптоПро: {exc}") from exc
        finally:
            store.Close()

        # pycades возвращает PEM-подобный base64 с переносами строк.
        cleaned = signature_b64.replace("\r\n", "").replace("\n", "")
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        return base64.b64decode(cleaned)
