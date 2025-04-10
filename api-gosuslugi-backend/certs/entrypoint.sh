#!/bin/sh


csptest -keyset -enum_cont -fqcn -verifyc | iconv -f cp1251 | grep HDI > envfile
certmgr -inst -store uMy -cont $(cat ./envfile) -provtype 81

# certmgr -inst -file /certs/some.cer -cont $(cat ./envfile)



yes 'o' | certmgr -inst -store root -file /certs/test_ca_rtk2.cer
yes 'o' | certmgr -inst -store root -file /certs/ca-root.crt
yes 'o' | certmgr -inst -store root -file /certs/rootca.cer
yes 'o' | certmgr -inst -store root -file /certs/sertum-pro-2024.cer
yes 'o' | certmgr -inst -store mroot -file /certs/2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A.cer
for i in $(seq 1 12); do  yes $i | certmgr -inst -store mroot -file /certs/cacerts.p7b; done
# yes 'o' | certmgr -inst -store mroot -file /certs/cacerts.p7b
python /app/app.py
