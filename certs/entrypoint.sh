#!/bin/sh

chown -R root:root /var/opt/cprocsp/keys/root/xxx.000
chown -R root:root /certs
csptest -keyset -enum_cont -fqcn -verifyc | iconv -f cp1251 | grep HDI > envfile

certmgr -inst -file /certs/some.cer -cont $(cat ./envfile)

yes 'o' | certmgr -inst -store root -file /certs/test_ca_rtk2.cer



python /app/app.py