#!/bin/sh
# Генерируем конфиг из шаблона
#rm -f /etc/nginx/conf.d/default.conf
envsubst '${BACKEND_API}' < /etc/nginx/conf.d/default.conf.template > /tmp/default.conf && mv /tmp/default.conf /etc/nginx/conf.d/default.conf
# Запускаем Nginx
exec nginx -g 'daemon off;'
