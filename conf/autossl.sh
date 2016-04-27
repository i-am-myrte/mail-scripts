#!/bin/bash

/usr/sbin/service nginx stop

cd /usr/local/letsencrypt
./letsencrypt-auto renew -nvv --standalone > /var/log/letsencrypt/renew.log 2>&1
/usr/sbin/service nginx start
LE_STATUS=$?
if [ "$LE_STATUS" != 0 ]; then
    echo Automated renewal failed:
    cat /var/log/letsencrypt/renew.log
    exit 1
fi
