#!/bin/sh

chown -R root:root /var/opt/cprocsp/keys/root/xxx.000
chown -R root:root /certs

csptest -keyset -enum_cont -fqcn -verifyc | iconv -f cp1251 | grep HDI > envfile
certmgr -inst -store uMy -cont $(cat ./envfile) -provtype 81

# Публичные CA (поставляются с репозиторием)
PUBLIC_CERTS=/certs/public
yes 'o' | certmgr -inst -store root -file ${PUBLIC_CERTS}/test_ca_rtk2.cer
yes 'o' | certmgr -inst -store root -file ${PUBLIC_CERTS}/ca-root.crt
yes 'o' | certmgr -inst -store root -file ${PUBLIC_CERTS}/rootca.cer
yes 'o' | certmgr -inst -store mroot -file ${PUBLIC_CERTS}/2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer
for i in $(seq 1 12); do yes $i | certmgr -inst -store mroot -file ${PUBLIC_CERTS}/cacerts.p7b; done

# Личные сертификаты пользователя (монтируются, в репозиторий не попадают)
PERSONAL_CERTS=/certs/personal
if [ -d "${PERSONAL_CERTS}" ]; then
  for cert in ${PERSONAL_CERTS}/*.cer; do
    [ -e "$cert" ] || continue
    yes 'o' | certmgr -inst -store uMy -file "$cert" -cont $(cat ./envfile)
  done
fi

pytest test_app.py -v