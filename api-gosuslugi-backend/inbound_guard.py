"""Защита публичного приёмника: кого пускаем и как часто.

Приёмник (``inbound.py``) стоит на единственном порту, который смотрит в
интернет, и по замыслу принимает всё подряд: контракт входящего push в
опубликованных спецификациях API ЕПГУ не описан, и отказывать отправителю
из-за незнакомого формата нельзя. Но «принимаем всё» не значит «принимаем от
всех и сколько угодно».

Проверено на стенде: 70 запросов по мегабайту за 5 секунд вытесняют журнал
целиком, вместе с настоящими сообщениями. Поэтому здесь три рубежа, каждый
включается своей переменной окружения:

    INBOUND_ALLOW_NETS   сети, с которых принимаем (CIDR через запятую)
    INBOUND_TOKEN        общий секрет в заголовке X-Inbound-Token
    INBOUND_RATE_*       ограничение частоты, работает всегда

Пока адрес не опубликован, можно жить без первых двух: ограничение частоты
включено по умолчанию. Перед публикацией адреса в техпортале задайте хотя бы
одну из проверок, иначе журнал сможет забить кто угодно.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("inbound.guard")

TOKEN_HEADER = "x-inbound-token"
# Тот же набор проверок нужен и отдаче наружу, только переменные у неё свои.
# Поэтому имя переменной складывается из префикса: INBOUND_TOKEN, OUTBOUND_TOKEN.
DEFAULT_PREFIX = "INBOUND"

_lock = threading.Lock()
_buckets: "OrderedDict[str, Tuple[float, float]]" = OrderedDict()
_global_bucket: Tuple[float, float] = (0.0, 0.0)
_rejected: Dict[str, int] = {}
_max_tracked_clients = 10000


def _nets(name: str) -> List[ipaddress._BaseNetwork]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    result = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            result.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning("Не разобрал сеть в %s: %s", name, part)
    return result


def allow_nets(prefix: str = DEFAULT_PREFIX) -> List[ipaddress._BaseNetwork]:
    return _nets(f"{prefix}_ALLOW_NETS")


def trusted_proxies(prefix: str = DEFAULT_PREFIX) -> List[ipaddress._BaseNetwork]:
    return _nets(f"{prefix}_TRUSTED_PROXIES")


def token(prefix: str = DEFAULT_PREFIX) -> str:
    return os.getenv(f"{prefix}_TOKEN", "").strip()


def token_is_transferable(prefix: str = DEFAULT_PREFIX) -> bool:
    """Секрет должен быть латиницей: кириллицу заголовок HTTP не перенесёт."""
    return token(prefix).isascii()


def rate_per_minute(prefix: str = DEFAULT_PREFIX) -> float:
    return float(os.getenv(f"{prefix}_RATE_PER_MINUTE", "60"))


def rate_burst(prefix: str = DEFAULT_PREFIX) -> float:
    return float(os.getenv(f"{prefix}_RATE_BURST", "20"))


def rate_global_per_minute(prefix: str = DEFAULT_PREFIX) -> float:
    return float(os.getenv(f"{prefix}_RATE_GLOBAL_PER_MINUTE", "600"))


def _parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def client_ip(peer: Optional[str], forwarded: str, prefix: str = DEFAULT_PREFIX) -> str:
    """Адрес отправителя.

    ``X-Forwarded-For`` подставляет кто угодно, поэтому верим ему только
    тогда, когда запрос действительно пришёл от нашего обратного прокси,
    перечисленного в ``INBOUND_TRUSTED_PROXIES``. Иначе берём адрес сокета:
    его подделать нельзя.
    """
    peer_ip = _parse_ip(peer or "")
    proxies = trusted_proxies(prefix)
    if forwarded and peer_ip is not None and any(peer_ip in net for net in proxies):
        first = forwarded.split(",")[0].strip()
        if _parse_ip(first) is not None:
            return first
    return str(peer_ip) if peer_ip is not None else "неизвестен"


def net_allowed(ip: str, prefix: str = DEFAULT_PREFIX) -> bool:
    nets = allow_nets(prefix)
    if not nets:
        return True
    address = _parse_ip(ip)
    if address is None:
        return False
    return any(address in net for net in nets)


def token_matches(provided: str, prefix: str = DEFAULT_PREFIX) -> bool:
    expected = token(prefix)
    if not expected:
        return True
    # Сравниваем байты: compare_digest не работает со строками, где есть
    # символы вне ASCII, а секрет вполне может быть написан по-русски.
    return secrets.compare_digest(provided.strip().encode("utf-8"), expected.encode("utf-8"))


def _take(bucket: Tuple[float, float], per_minute: float, burst: float, now: float):
    """Ведро с протечкой: сколько токенов осталось после этого запроса."""
    tokens, last = bucket
    if last == 0.0:
        tokens = burst
    else:
        tokens = min(burst, tokens + (now - last) * per_minute / 60.0)
    if tokens < 1.0:
        return (tokens, now), False
    return (tokens - 1.0, now), True


def rate_ok(ip: str, prefix: str = DEFAULT_PREFIX) -> bool:
    """Не слишком ли часто. Считаем и по отправителю, и по приёмнику в целом."""
    global _global_bucket
    now = time.monotonic()
    per_minute = rate_per_minute(prefix)
    burst = rate_burst(prefix)
    with _lock:
        # Ключ с префиксом: приёмник и отдача считаются отдельно, даже если
        # запросы идут с одного адреса.
        ip = f"{prefix}:{ip}"
        bucket = _buckets.get(ip, (0.0, 0.0))
        bucket, ok = _take(bucket, per_minute, burst, now)
        _buckets[ip] = bucket
        _buckets.move_to_end(ip)
        # Память приёмника не должна расти от перебора адресов.
        while len(_buckets) > _max_tracked_clients:
            _buckets.popitem(last=False)
        if not ok:
            return False
        limit = rate_global_per_minute(prefix)
        _global_bucket, ok = _take(_global_bucket, limit, limit, now)
        return ok


def note_rejected(reason: str) -> int:
    """Запомнить отказ. Сами отказы в журнал не пишем, только считаем."""
    with _lock:
        _rejected[reason] = _rejected.get(reason, 0) + 1
        return _rejected[reason]


def rejected_counters() -> Dict[str, int]:
    with _lock:
        return dict(_rejected)


def reset() -> None:
    """Только для тестов: забыть накопленное состояние."""
    global _global_bucket
    with _lock:
        _buckets.clear()
        _rejected.clear()
        _global_bucket = (0.0, 0.0)


def describe(prefix: str = DEFAULT_PREFIX) -> Dict[str, object]:
    """Что включено. Значение секрета наружу не отдаём, только факт."""
    return {
        "allow_nets": [str(net) for net in allow_nets(prefix)],
        "trusted_proxies": [str(net) for net in trusted_proxies(prefix)],
        "token_required": bool(token(prefix)),
        "rate_per_minute": rate_per_minute(prefix),
        "rate_burst": rate_burst(prefix),
        "rate_global_per_minute": rate_global_per_minute(prefix),
        "rejected": rejected_counters(),
    }
