"""Определение почтовых серверов по адресу ящика.

Адрес сервера у хостингов почти никогда не совпадает с доменом почты: у
mirasnowfox.ru на reg.ru это mail.hosting.reg.ru, и угадать это невозможно.
Поэтому модуль спрашивает DNS, а не выдумывает имена:

1. SRV-записи по RFC 6186 (_imaps._tcp, _submission._tcp и соседние). Это
   штатный способ published autoconfiguration, если хостинг его настроил.
2. MX-записи домена. Почтовый узел провайдера обычно живёт рядом с ними:
   mx1.hosting.reg.ru подсказывает hosting.reg.ru.
3. Привычные имена вида imap.<домен> и mail.<домен>.

Кандидаты не просто перечисляются: каждый проверяется живым подключением, и
наружу уходит только то, что реально ответило на своём порту.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:  # dnspython нужен для SRV и MX: в стандартной библиотеке их нет.
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - образ без dnspython
    DNS_AVAILABLE = False

PROBE_TIMEOUT = 5

IMAP_PORTS = (993, 143)
SMTP_PORTS = (465, 587)


@dataclass
class Candidate:
    host: str
    port: int
    protocol: str
    source: str
    reachable: bool = False
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "source": self.source,
            "reachable": self.reachable,
            "detail": self.detail,
        }


def domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" in address:
        address = address.rsplit("@", 1)[1]
    return address.strip().strip(".")


def _srv(domain: str, service: str) -> List[Tuple[str, int]]:
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(f"{service}.{domain}", "SRV", lifetime=PROBE_TIMEOUT)
    except Exception:
        return []
    records = []
    for record in sorted(answers, key=lambda item: (item.priority, -item.weight)):
        host = str(record.target).rstrip(".")
        if host and host != ".":
            records.append((host, int(record.port)))
    return records


def _mx(domain: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=PROBE_TIMEOUT)
    except Exception:
        return []
    return [
        str(record.exchange).rstrip(".")
        for record in sorted(answers, key=lambda item: item.preference)
    ]


def _parent(host: str) -> str:
    """mx1.hosting.reg.ru -> hosting.reg.ru: узел провайдера обычно рядом."""
    parts = host.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else host


def _probe(host: str, port: int) -> Tuple[bool, str]:
    """Проверить, что на хосте и порту действительно кто-то есть."""
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, "имя не разрешается"
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT) as raw:
            if port in (993, 465):
                context = ssl.create_default_context()
                try:
                    with context.wrap_socket(raw, server_hostname=host):
                        return True, "отвечает, TLS в порядке"
                except ssl.SSLError as err:
                    return True, f"порт открыт, но TLS ругается ({type(err).__name__})"
            return True, "порт открыт"
    except (socket.timeout, TimeoutError):
        return False, "не ответил"
    except ConnectionRefusedError:
        return False, "соединение отклонено"
    except OSError as err:
        return False, f"недоступен ({type(err).__name__})"


def _collect(domain: str) -> List[Candidate]:
    seen: set[Tuple[str, int, str]] = set()
    candidates: List[Candidate] = []

    def add(host: str, port: int, protocol: str, source: str) -> None:
        host = host.strip().rstrip(".").lower()
        if not host:
            return
        key = (host, port, protocol)
        if key in seen:
            return
        seen.add(key)
        candidates.append(Candidate(host=host, port=port, protocol=protocol, source=source))

    # 1. SRV: штатная автонастройка.
    for service, protocol in (
        ("_imaps._tcp", "imap"),
        ("_imap._tcp", "imap"),
        ("_submissions._tcp", "smtp"),
        ("_submission._tcp", "smtp"),
    ):
        for host, port in _srv(domain, service):
            add(host, port, protocol, "SRV-запись")

    # 2. MX и узел провайдера рядом с ними.
    for exchange in _mx(domain):
        parent = _parent(exchange)
        for prefix in ("mail", "imap"):
            add(f"{prefix}.{parent}", IMAP_PORTS[0], "imap", f"MX {exchange}")
        for prefix in ("mail", "smtp"):
            add(f"{prefix}.{parent}", SMTP_PORTS[0], "smtp", f"MX {exchange}")

    # 3. Привычные имена самого домена.
    for prefix in ("imap", "mail"):
        add(f"{prefix}.{domain}", IMAP_PORTS[0], "imap", "имя по домену")
    for prefix in ("smtp", "mail"):
        add(f"{prefix}.{domain}", SMTP_PORTS[0], "smtp", "имя по домену")

    return candidates


def discover(address: str) -> Dict[str, Any]:
    """Найти рабочие IMAP и SMTP для адреса ящика."""
    domain = domain_of(address)
    if not domain or "." not in domain:
        raise ValueError("Укажите адрес ящика или домен")

    candidates = _collect(domain)
    for candidate in candidates:
        candidate.reachable, candidate.detail = _probe(candidate.host, candidate.port)

    working = [item for item in candidates if item.reachable]
    imap = next((item for item in working if item.protocol == "imap"), None)
    smtp = next((item for item in working if item.protocol == "smtp"), None)

    logger.info(
        "Автоопределение почты для домена %s: проверено %s, ответили %s",
        domain,
        len(candidates),
        len(working),
    )
    return {
        "domain": domain,
        "dns_available": DNS_AVAILABLE,
        "candidates": [item.as_dict() for item in candidates],
        "suggested": {
            "imap_host": imap.host if imap else "",
            "imap_port": imap.port if imap else 993,
            "smtp_host": smtp.host if smtp else "",
            "smtp_port": smtp.port if smtp else 465,
            "use_ssl": True,
        },
        "found": bool(imap and smtp),
    }
