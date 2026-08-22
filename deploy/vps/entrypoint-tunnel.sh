#!/bin/sh
# Держим обратный туннель до VPS. Разорвётся - подождём и поднимем снова.
set -u

VPS_HOST="${TUNNEL_HOST:-132.243.251.210}"
VPS_USER="${TUNNEL_USER:-epgu-tunnel}"
VPS_PORT="${TUNNEL_SSH_PORT:-22}"
# Что публикуем на VPS и куда это ведёт на нашей стороне. По умолчанию порт
# 58080 на 127.0.0.1 VPS заворачивается на приёмник в сети compose.
REMOTE_BIND="${TUNNEL_REMOTE_BIND:-127.0.0.1:58080}"
LOCAL_TARGET="${TUNNEL_LOCAL_TARGET:-inbound:5001}"
KEY=/keys/tunnel_key

install -d -m 700 /root/.ssh
cp "$KEY" /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519
# Ключ хоста закреплён заранее: человек в контейнере на вопрос не ответит,
# а слепое доверие любому ключу открыло бы дорогу подмене.
printf '%s %s\n' "$VPS_HOST" "${TUNNEL_HOSTKEY:-}" > /root/.ssh/known_hosts
chmod 644 /root/.ssh/known_hosts

echo "туннель: $VPS_USER@$VPS_HOST -> $REMOTE_BIND ведёт на $LOCAL_TARGET"

while true; do
    ssh -N \
        -o BatchMode=yes \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o UserKnownHostsFile=/root/.ssh/known_hosts \
        -p "$VPS_PORT" \
        -R "$REMOTE_BIND:$LOCAL_TARGET" \
        "$VPS_USER@$VPS_HOST" || true
    echo "туннель упал, повтор через 10 с"
    sleep 10
done
