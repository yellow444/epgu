# Внешний адрес информационной системы

В техпортале у информационной системы два адреса, и оба ведут на наш приёмник:

| Поле в техпортале | Что вписать |
| --- | --- |
| URL системы | `https://smev.mirasnowfox.ru/is` |
| URL для отправки push сообщений | `https://smev.mirasnowfox.ru/push` или `/message` |

Путь для push придумываем мы, ЕПГУ просто ходит по указанному адресу.
Приёмник принимает POST по любому пути и отвечает 200, а на GET по любому
пути отвечает пробой: проверка доступности из техпортала ходит именно GET.

## Как это устроено

Стенд и VPS в разных сетях: у VPS свой WireGuard, у стенда чужой корпоративный
OpenVPN, общего пути между ними нет. Поэтому стенд сам держит исходящий
обратный SSH-туннель до VPS и пробрасывает на нём порт 58080 на свой приёмник.

```
ЕПГУ -> https://smev.mirasnowfox.ru/is /push /message  (443, Caddy на VPS)
        Caddy -> 127.0.0.1:58080 на VPS
        обратный SSH-туннель (держит стенд)
        приёмник inbound на стенде
        порт 55000 операторский API  наружу не выходит никогда
```

Туннель инициирует стенд, VPS только принимает соединение. WireGuard VPS и
OpenVPN стенда при этом не затрагиваются.

## Что уже настроено на VPS

Сделано под root, VPN не тронут:

- пользователь `epgu-tunnel` без shell, его ключ ограничен `restrict,port-forwarding`
  (только проброс портов, ни shell, ни агента);
- в `/etc/caddy/Caddyfile` дописан блок `smev.mirasnowfox.ru`
  ([`Caddyfile`](Caddyfile)), сертификат Let's Encrypt выпущен автоматически.
  Прежний конфиг сохранён в `/etc/caddy/Caddyfile.before-smev`;
- обратный туннель садится на `127.0.0.1:58080` (sshd `gatewayports no`),
  наружу этот порт не смотрит.

## Что настроено на стенде

- сервис `tunnel` в [`docker-compose.tunnel.yml`](../../docker-compose.tunnel.yml):
  контейнер с ssh-клиентом держит `ssh -N -R 127.0.0.1:58080:inbound:5001` и
  сам поднимается после разрыва. Отпечаток ключа хоста VPS закреплён, ключ
  туннеля лежит в `deploy/vps/secret` и в репозиторий не попадает;
- `.env`: `INBOUND_PUBLIC_URL`, `INBOUND_TRUSTED_PROXIES` (docker-подсеть, а не
  VPN-шлюз: приёмник видит соединение от контейнера-туннеля, а настоящий адрес
  ЕПГУ приходит в `X-Forwarded-For`), `TUNNEL_HOST`, `TUNNEL_USER`,
  `TUNNEL_HOSTKEY`.

Запуск всего стенда вместе с туннелем:

```bash
docker compose -f docker-compose.yml -f docker-compose.cryptopro.yml \
               -f docker-compose.tunnel.yml up -d
```

## Проверка

```bash
curl -s https://smev.mirasnowfox.ru/is       # {"status":"ok",...}
curl -s https://smev.mirasnowfox.ru/push     # {"code":"OK",...}
curl -s https://smev.mirasnowfox.ru/message  # {"code":"OK",...}
```

Проверено end to end 2026-08-22: запрос из интернета доходит до приёмника,
в журнале виден настоящий адрес отправителя. Кнопка «Проверить адрес снаружи»
на вкладке «Входящие» делает то же самое из интерфейса.

## Безопасность

- Пароль root, присланный для первичного доступа, надо сменить: он был
  передан открытым текстом. Дальше вход по ключу, пароль не нужен.
- `INBOUND_TOKEN` для публичного адреса не годится: ЕПГУ про наш секрет не
  знает и получит 401. Пока адрес открыт, работают ограничение частоты и
  журнал. После первого настоящего запроса адрес отправителя виден в журнале,
  и тогда его сеть прописывается в `INBOUND_ALLOW_NETS`, а порт закрывается
  для остальных. Подробности в
  [`docs/context/11-inbound-endpoint.md`](../../docs/context/11-inbound-endpoint.md).

## Вариант с nginx

Если на VPS стоит nginx, а не Caddy: [`nginx-smev.conf`](nginx-smev.conf) и
[`proxy_is.conf`](proxy_is.conf), там `proxy_pass` тоже на `127.0.0.1:58080`,
сертификат отдельно через `certbot --nginx -d smev.mirasnowfox.ru`.
