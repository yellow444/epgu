#!/bin/sh
set -eu

# Генерируем конфиг из шаблона атомарно до запуска nginx.
envsubst '${BACKEND_API}' < /etc/nginx/conf.d/default.conf.template > /tmp/default.conf
mv /tmp/default.conf /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
