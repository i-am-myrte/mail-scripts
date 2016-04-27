#!/bin/bash

ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
COL_GREEN=$ESC_SEQ"32;01m"
COL_YELLOW=$ESC_SEQ"33;01m"

if [ "$UID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

CDIR=$(pwd)
		
function error_check {
    if [ "$?" = "0" ]; then
        echo -e "$COL_GREEN OK. $COL_RESET"
    else
        echo -e "$COL_RED An error has occured. $COL_RESET"
        read -p "Press enter or space to ignore it. Press any other key to abort." -n 1 key

        if [[ $key != "" ]]; then
            exit
        fi
    fi
}
echo -e "$COL_GREEN"
    printf "
    ########################################################
    # The Shell Script to install the Mailserver           #
    # Nginx+Postfix+Dovecot+PostAdmin+Roundcube+postgresql #
    # Base on Ubuntu14.04 or Debian 8                      #
    # Author: Myrte                                        #
    # Website: https://lzh.be                              #
    # Imap ssl Port 993 and Smtp  tls port 587             #
    ########################################################
    "
echo -e "$COL_RESET"
     if [ -s /etc/selinux/config ]; then
     sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
     fi
     arch=`uname -m`
    if [ $arch = "unknown" ]; then
    arch="i686"
    fi
echo -e "$COL_GREEN"
VPSIP=`wget http://ipecho.net/plain -O - -q ; echo`

NGINX_VER="1.9.15"
    echo "Please input NGINX version:"
    read -p "(Default version 1.9.15,Do not less than 1.9.10 ):" NGINX_VER
    if [ "$NGINX_VER" = "1.9.10" ]; then
	NGINX_VER="1.9.15"
    fi

DOMAIN="lzh.be"
    echo "Please input The Your Domain:"
    read -p "(For example: lzh.be do not have www):" DOMAIN
    if [ "$DOMAIN" = "" ]; then
	DOMAIN="lzh.be"
    fi

DOMAINMX="mail.lzh.be"
    echo "Please input The Your MX Domain:"
    read -p "(For example: mail.lzh.be do not have www):" DOMAINMX
    if [ "$DOMAINMX" = "" ]; then
	DOMAINMX="nail.lzh.be"
    fi
	
DBUSER="myrte"
    echo "Please input The Your PGSQL username:"
    read -p "(For example: myrte):" DBUSER
    if [ "$DBUSER" = "" ]; then
	DBUSER="myrte"
    fi
	
DBNAME="postdix_db"
    echo "Please input The Your PGSQL Database Name:"
    read -p "(For example: postdix_db):" DBNAME
    if [ "$DBNAME" = "" ]; then
	DBNAME="postdix_db"
    fi
	
DBPASS="12345678"
    echo "Please input The Your Password:"
    read -p "(For example: 12345678):" DBPASS
    if [ "$DBPASS" = "" ]; then
	DBPASS="12345678"
    fi
echo -e "$COL_RESET"
clear
   

echo "Change the hostname "
echo "${DOMAINMX}" > /etc/hostname
error_check

echo "Remove Some Software "
sudo apt-get remove -y apache2
sudo apt-get remove -y exim4
sudo apt-get remove -y nginx
sudo apt-get remove -y postfix
sudo apt-get remove -y dovecot
sudo apt-get remove -y sendmail
sudo apt-get remove -y dovecot-core 
sudo apt-get remove -y php5-fpm
echo "Remove Some Software complete"
error_check

echo "Remove user"
userdel postfix
groupdel postdrop
userdel www
groupdel www
userdel vmail
groupdel vmail

echo "Updating system"
apt-get -y update
error_check
apt-get -y upgrade
error_check

echo "Install Some Dependences"
sudo apt-get install -y build-essential gcc g++ make cmake autoconf automake re2c wget cron unzip golang git php5-fpm  curl wget ntpdate


echo "Setting timezone..."
rm -rf /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

echo "[+] Installing ntp..."
ntpdate -u pool.ntp.org
error_check
date

echo "Install Nginx ${NGINX_VER} Starting"
groupadd www
error_check
useradd -s /sbin/nologin -g www www
error_check

cd ${CDIR}
wget http://zlib.net/zlib-1.2.8.tar.gz 
tar -zxvf zlib-1.2.8.tar.gz  
sudo mv zlib-1.2.8 /usr/local/
rm -rf zlib-1.2.8.tar.gz
error_check

cd ${CDIR}
wget http://nchc.dl.sourceforge.net/project/pcre/pcre/8.21/pcre-8.21.tar.gz 
tar -zxvf pcre-8.21.tar.gz  
sudo mv pcre-8.21 /usr/local/
rm -rf pcre-8.21.tar.gz
error_check

cd ${CDIR}
wget -O nginx-ct.zip -c https://github.com/grahamedgecombe/nginx-ct/archive/v1.2.0.zip
unzip nginx-ct.zip
mv nginx-ct-1.2.0 nginx-ct
sudo mv nginx-ct /usr/local/
rm -rf nginx-ct.zip
error_check

cd ${CDIR}
git clone https://github.com/cloudflare/sslconfig
sudo mv sslconfig /usr/local/
error_check

cd ${CDIR}
wget https://github.com/openssl/openssl/archive/OpenSSL_1_0_2g.zip
unzip OpenSSL_1_0_2g.zip
mv openssl-OpenSSL_1_0_2g/ /usr/local/openssl
cd /usr/local/openssl
patch -p1 < ../sslconfig/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102g.patch
error_check

cd ${CDIR}
rm -rf OpenSSL_1_0_2g.zip

wget -c http://nginx.org/download/nginx-${NGINX_VER}.tar.gz
tar zxvfp nginx-${NGINX_VER}.tar.gz
cd nginx-${NGINX_VER}
./configure --prefix=/usr/local/nginx --user=www --group=www --add-module=/usr/local/nginx-ct --with-openssl=/usr/local/openssl --with-zlib=/usr/local/zlib-1.2.8 --with-http_stub_status_module --with-http_v2_module --with-http_ssl_module --with-ipv6 --with-http_gzip_static_module --with-http_realip_module --with-http_flv_module --with-pcre=/usr/local/pcre-8.21 
error_check
make && make install

cd ${CDIR}
rm -rf nginx-${NGINX_VER}.tar.gz
rm -rf nginx-${NGINX_VER}
error_check



ln -sf /usr/local/nginx/sbin/nginx /usr/bin/nginx
rm -f /usr/local/nginx/conf/nginx.conf
cp conf/nginx.conf /usr/local/nginx/conf/nginx.conf
mkdir -p /usr/local/nginx/conf/vhost
cp conf/enable-php.conf /usr/local/nginx/conf/enable-php.conf
touch /usr/local/nginx/conf/vhost/${DOMAIN}.conf
mkdir -p /home/${DOMAIN}
chmod +w /home/${DOMAIN}
chown -R www:www /home/${DOMAIN}
rm -f /etc/init.d/nginx
cp conf/nginx /etc/init.d/nginx
chmod +x /etc/init.d/nginx
update-rc.d -f nginx defaults
update-rc.d -f nginx enable
error_check

echo "## make by Myrte
server {
       listen         80;
       server_name   ${DOMAIN};
       return        301 https://\$server_name\$request_uri;
}
server {
    listen 443 ssl;
    server_name ${DOMAIN};
    root /home/${DOMAIN};
    index index.php index.html index.htm;
	if (\$host != '${DOMAIN}' ) {
        return   301 https://\$server_name\$request_uri;
        }
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparams.pem;
		ssl_ct on;
        ssl_ct_static_scts /etc/letsencrypt/live/${DOMAIN}/scts;
		ssl_session_timeout 12m;
		ssl_session_cache shared:SSL:16m;
		ssl_buffer_size 8k;
		ssl_session_tickets on;
		ssl_stapling on;
		ssl_stapling_verify on;
		resolver 8.8.4.4 8.8.8.8 valid=300s;
		resolver_timeout 10s;
		add_header Strict-Transport-Security \"max-age=31536000;includeSubDomains\";
    include enable-php.conf;
    location / {
        try_files \$uri \$uri/ =404;
    }
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /home/${DOMAIN};
    }
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)\$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)\?\$
        {
            expires      12h;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log  off;
}" > /usr/local/nginx/conf/vhost/${DOMAIN}.conf

error_check

echo "Install Let’s Encrypt SSL Starting"
cd /usr/local/
sudo git clone https://github.com/letsencrypt/letsencrypt
error_check

cd /usr/local/letsencrypt
sudo ./letsencrypt-auto certonly --standalone -d ${DOMAIN} -d www.${DOMAIN}
error_check

sudo ./letsencrypt-auto certonly --standalone -d ${DOMAINMX}
error_check

sudo ls -al /etc/letsencrypt/live/${DOMAIN}/cert.pem
sudo ls -al /etc/letsencrypt/live/${DOMAINMX}/cert.pem
error_check

sudo mkdir /usr/local/nginx/conf/ssl
cd /usr/local/nginx/conf/ssl
sudo openssl dhparam -out dhparams.pem 2048
error_check

cd ${CDIR}
cp conf/autossl.sh /root/autossl.sh
chmod +x /root/autossl.sh
touch /var/spool/cron/crontabs/root
chmod +x /var/spool/cron/crontabs/root
touch /var/log/www-renew.log
chmod +x /var/log/www-renew.log
mkdir /var/log/letsencrypt
cat >>/var/spool/cron/crontabs/root <<EOF
* * */1 * * /root/autossl.sh >> /var/log/www-renew.log 2>&1
EOF
service cron restart
error_check

cd ${CDIR}
wget -O ct-submit.zip -c https://github.com/grahamedgecombe/ct-submit/archive/v1.0.0.zip
unzip ct-submit.zip
cd ct-submit-1.0.0
go build
error_check

mkdir -p /etc/letsencrypt/live/${DOMAIN}/scts
sudo sh -c "./ct-submit-1.0.0 ct.googleapis.com/aviator < /etc/letsencrypt/live/${DOMAIN}/fullchain.pem > /etc/letsencrypt/live/${DOMAIN}/scts/aviator.sct"
error_check

sudo sh -c "./ct-submit-1.0.0 ct.googleapis.com/pilot < /etc/letsencrypt/live/${DOMAIN}/fullchain.pem > /etc/letsencrypt/live/${DOMAIN}/scts/pilot.sct"
error_check

sudo sh -c "./ct-submit-1.0.0 ct.googleapis.com/rocketeer < /etc/letsencrypt/live/${DOMAIN}/fullchain.pem > /etc/letsencrypt/live/${DOMAIN}/scts/rocketeer.sct"
error_check

cd ${CDIR}
rm -rf ct-submit.zip
rm -rf ct-submit-1.0.0

echo "Checking if php5-fpm is working:"
sed -i 's/www-data/www/g' /etc/php5/fpm/pool.d/www.conf
ln  -s  /etc/php5/mods-available/imap.ini /etc/php5/fpm/conf.d/20-imap.ini
service php5-fpm restart
error_check

echo "Checking if Nginx is working:"
/usr/bin/nginx -t
service nginx restart
error_check

echo -e "$COL_GREEN NGINX 1.9.15 Install  complete!. $COL_RESET"
echo -e "$COL_GREEN Please visit Website https://${DOMAIN}. $COL_RESET"
sleep 10

echo -e "$COL_GREEN Now starting MailServer !. $COL_RESET"
sleep 5
echo "Adding group:"
groupadd -g 5000 vmail
error_check

echo "Adding group:"
useradd -u 5000 -g vmail -s /usr/bin/nologin -d /home/vmail -m vmail
error_check

echo "Installing programs:"
apt-get install -y postfix dovecot-core dovecot-imapd postgresql postfix-pgsql dovecot-lmtpd dovecot-pgsql  php5-fpm php5-imap php5-pgsql php5-mcrypt php5-intl
error_check

cd /home/${DOMAIN}
echo "Preparing database:"
CREATEUSER="CREATE USER ${DBUSER} WITH PASSWORD '${DBPASS}';"
CREATEDB="CREATE DATABASE ${DBNAME};"
PERMISSDB="GRANT ALL PRIVILEGES ON DATABASE ${DBNAME} TO ${DBUSER};"
sudo -u postgres psql -c "${CREATEUSER}"
error_check
sudo -u postgres psql -c "${CREATEDB}"
error_check
sudo -u postgres psql -c "${PERMISSDB}"
error_check


echo "Creating postfix config files (/etc/postfix/main.cf):"
echo "relay_domains =
virtual_alias_maps = proxy:pgsql:/etc/postfix/virtual_alias_maps.cf
virtual_mailbox_domains = proxy:pgsql:/etc/postfix/virtual_mailbox_domains.cf
virtual_mailbox_maps = proxy:pgsql:/etc/postfix/virtual_mailbox_maps.cf
virtual_mailbox_base = /home/vmail
virtual_mailbox_limit = 512000000
virtual_minimum_uid = 5000
virtual_transport = virtual
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
local_transport = virtual
local_recipient_maps = \$virtual_mailbox_maps
transport_maps = hash:/etc/postfix/transport
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = \$smtpd_sasl_security_options
smtpd_tls_auth_only = yes
smtpd_tls_cert_file = /etc/letsencrypt/live/${DOMAINMX}/cert.pem
smtpd_tls_key_file = /etc/letsencrypt/live/${DOMAINMX}/privkey.pem
smtpd_sasl_local_domain = \$mydomain
broken_sasl_auth_clients = yes
smtpd_tls_loglevel = 1
html_directory = /usr/share/doc/postfix/html
queue_directory = /var/spool/postfix
mydestination = localhost" > /etc/postfix/main.cf
error_check

echo "Creating postfix config files (/etc/postfix/master.cf):"
echo "#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: \"man 5 master\").
#
# Do not forget to execute \"postfix reload\" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       -       -       -       smtpd
#smtp      inet  n       -       -       -       1       postscreen
#smtpd     pass  -       -       -       -       -       smtpd
#dnsblog   unix  -       -       -       -       0       dnsblog
#tlsproxy  unix  -       -       -       -       0       tlsproxy
submission inet n       -       -       -       -       smtpd
#  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       -       -       -       smtpd
#  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       -       -       -       qmqpd
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
#qmgr     fifo  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about \${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d \${recipient}
#
# ====================================================================
#
# Recent Cyrus versions can use the existing \"lmtp\" master.cf entry.
#
# Specify in cyrus.conf:
#   lmtp    cmd=\"lmtpd -a\" listen=\"localhost:lmtp\" proto=tcp4
#
# Specify in main.cf one or more of the following:
#  mailbox_transport = lmtp:inet:localhost
#  virtual_transport = lmtp:inet:localhost
#
# ====================================================================
#
# Cyrus 2.1.5 (Amos Gouaux)
# Also specify in main.cf: cyrus_destination_recipient_limit=1
#
#cyrus     unix  -       n       n       -       -       pipe
#  user=cyrus argv=/cyrus/bin/deliver -e -r \${sender} -m \${extension} \${user}
#
# ====================================================================
# Old example of delivery via Cyrus.
#
#old-cyrus unix  -       n       n       -       -       pipe
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m \${extension} \${user}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
#
# Other external delivery methods.
#
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t\$nexthop -f\$sender \$recipient
scalemail-backend unix  -   n   n   -   2   pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store \${nexthop} \${user} \${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  \${nexthop} \${user}
cleanup   unix  n       -       -       -       0       cleanup
subcleanup unix n       -       -       -       0       cleanup
 -o header_checks=regexp:/etc/postfix/submission_header_checks
" > /etc/postfix/master.cf
error_check

echo "Creating postfix config files (/etc/postfix/submission_header_checks):"
echo "/^Received:/ IGNORE
/^User-Agent:/ IGNORE" > /etc/postfix/submission_header_checks
error_check

echo "Creating postfix config files (/etc/postfix/virtual_alias_maps.cf):"
echo "user = ${DBUSER}
password = ${DBPASS}
hosts = localhost
dbname = ${DBNAME}
query = SELECT goto FROM alias WHERE address='%s' AND active = true
" > /etc/postfix/virtual_alias_maps.cf
error_check

echo "Creating postfix config files (/etc/postfix/virtual_mailbox_domains.cf):"
echo "user = ${DBUSER}
password = ${DBPASS}
hosts = localhost
dbname = ${DBNAME}
query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = false AND active = true
" > /etc/postfix/virtual_mailbox_domains.cf
error_check

echo "Creating postfix config files (/etc/postfix/virtual_mailbox_maps.cf):"
echo "user = ${DBUSER}
password = ${DBPASS}
hosts = localhost
dbname = ${DBNAME}
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = true
" > /etc/postfix/virtual_mailbox_maps.cf
error_check

echo "Creating dovecot config files (/etc/dovecot/dovecot.conf):"
echo "protocols = imap
auth_mechanisms = plain
passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}
userdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}
service auth {
    unix_listener /var/spool/postfix/private/auth {
        group = postfix
        mode = 0660
        user = postfix
    }
    user = root
}
mail_home = /home/vmail/%d/%u
mail_location = maildir:~
ssl = required
ssl_cert = </etc/letsencrypt/live/${DOMAINMX}/cert.pem
ssl_key = </etc/letsencrypt/live/${DOMAINMX}/privkey.pem" > /etc/dovecot/dovecot.conf
error_check

echo "Creating dovecot config files (/etc/dovecot/dovecot-sql.conf):"
echo "driver = pgsql
connect = host=localhost dbname=${DBNAME} user=${DBUSER} password=${DBPASS}
default_pass_scheme = MD5-CRYPT
user_query = SELECT '/home/vmail/%d/%u' as home, 'maildir:/home/vmail/%d/%u' as mail, 5000 AS uid, 5000 AS gid, concat('dirsize:storage=',  quota) AS quota FROM mailbox WHERE username = '%u' AND active = '1'
password_query = SELECT username as user, password, '/home/vmail/%d/%u' as userdb_home, 'maildir:/home/vmail/%d/%u' as userdb_mail, 5000 as  userdb_uid, 5000 as userdb_gid FROM mailbox WHERE username = '%u' AND active = '1'
" > /etc/dovecot/dovecot-sql.conf
error_check

echo "Creating postmap:"
touch /etc/postfix/transport
postmap /etc/postfix/transport
error_check


echo "Checking if path is correct:"
cd /home/${DOMAIN}
error_check

echo "Downloading postfixadmin:"
wget -O postfixadmin.tar.gz http://sourceforge.net/projects/postfixadmin/files/latest/download
error_check

echo "Unpacking postfixadmin:"
tar -zxvf postfixadmin.tar.gz -C /home/${DOMAIN}
error_check
rm -rf postfixadmin.tar.gz
mv postfixadmin-* postfixadmin

echo "Setting permissions:"
chmod -R 777 postfixadmin/templates_c
error_check
mv postfixadmin/config.inc.php postfixadmin/config.inc.php.bak
touch postfixadmin/config.inc.php
echo "<?php
\$CONF['configured'] = true;
\$CONF['setup_password'] = 'changeme';
\$CONF['default_language'] = 'en';
\$CONF['language_hook'] = '';
\$CONF['database_type'] = 'pgsql';
\$CONF['database_host'] = 'localhost';
\$CONF['database_user'] = '${DBUSER}';
\$CONF['database_password'] = '${DBPASS}';
\$CONF['database_name'] = '${DBNAME}';
\$CONF['database_prefix'] = '';
\$CONF['database_tables'] = array (
    'admin' => 'admin',
    'alias' => 'alias',
    'alias_domain' => 'alias_domain',
    'config' => 'config',
    'domain' => 'domain',
    'domain_admins' => 'domain_admins',
    'fetchmail' => 'fetchmail',
    'log' => 'log',
    'mailbox' => 'mailbox',
    'vacation' => 'vacation',
    'vacation_notification' => 'vacation_notification',
    'quota' => 'quota',
	'quota2' => 'quota2',
);
\$CONF['admin_email'] = '';
\$CONF['smtp_server'] = 'localhost';
\$CONF['smtp_port'] = '25';
\$CONF['encrypt'] = 'md5crypt';
\$CONF['authlib_default_flavor'] = 'md5raw';
\$CONF['dovecotpw'] = \"/usr/sbin/doveadm pw\";
\$CONF['password_validation'] = array(
    '/.{5}/'                => 'password_too_short 5',      
    '/([a-zA-Z].*){3}/'     => 'password_no_characters 3',  
    '/([0-9].*){2}/'        => 'password_no_digits 2',      
);
\$CONF['generate_password'] = 'NO';
\$CONF['show_password'] = 'NO';
\$CONF['page_size'] = '10';
\$CONF['default_aliases'] = array (
    'abuse' => 'abuse@change-this-to-your.domain.tld',
    'hostmaster' => 'hostmaster@change-this-to-your.domain.tld',
    'postmaster' => 'postmaster@change-this-to-your.domain.tld',
    'webmaster' => 'webmaster@change-this-to-your.domain.tld'
);
\$CONF['domain_path'] = 'YES';
\$CONF['domain_in_mailbox'] = 'NO';
\$CONF['maildir_name_hook'] = 'NO';
\$CONF['admin_struct_hook']          = '';
\$CONF['domain_struct_hook']         = '';
\$CONF['alias_struct_hook']          = '';
\$CONF['mailbox_struct_hook']        = '';
\$CONF['alias_domain_struct_hook']   = '';
\$CONF['fetchmail_struct_hook']      = '';
\$CONF['aliases'] = '10';
\$CONF['mailboxes'] = '10';
\$CONF['maxquota'] = '10';
\$CONF['domain_quota_default'] = '2048';
\$CONF['quota'] = 'NO';
\$CONF['domain_quota'] = 'YES';
\$CONF['quota_multiplier'] = '1024000';
\$CONF['transport'] = 'NO';
\$CONF['transport_options'] = array (
    'virtual',  
    'local',    
    'relay'     
);
\$CONF['transport_default'] = 'virtual';
\$CONF['vacation'] = 'NO';
\$CONF['vacation_domain'] = '${DOMAIN}';
\$CONF['vacation_control'] ='YES';
\$CONF['vacation_control_admin'] = 'YES';
\$CONF['vacation_choice_of_reply'] = array (
   0 => 'reply_once',        
   60*60 *24*7 => 'reply_once_per_week'        
);
\$CONF['alias_control'] = 'YES';
\$CONF['alias_control_admin'] = 'YES';
\$CONF['special_alias_control'] = 'NO';
\$CONF['alias_goto_limit'] = '0';
\$CONF['alias_domain'] = 'YES';
\$CONF['backup'] = 'NO';
\$CONF['sendmail'] = 'YES';
\$CONF['logging'] = 'YES';
\$CONF['fetchmail'] = 'YES';
\$CONF['fetchmail_extra_options'] = 'NO';
\$CONF['show_header_text'] = 'NO';
\$CONF['header_text'] = ':: Postfix Admin ::';
\$CONF['show_footer_text'] = 'YES';
\$CONF['footer_text'] = '${DOMAIN}';
\$CONF['footer_link'] = 'https://${DOMAIN}';
\$CONF['motd_user'] = '';
\$CONF['motd_admin'] = '';
\$CONF['motd_superadmin'] = '';
\$CONF['welcome_text'] = <<<EOM
Hi,
Welcome to your new account.
EOM;
\$CONF['emailcheck_resolve_domain']='YES';
\$CONF['show_status']='YES';
\$CONF['show_status_key']='YES';
\$CONF['show_status_text']='&nbsp;&nbsp;';
\$CONF['show_undeliverable']='YES';
\$CONF['show_undeliverable_color']='tomato';
\$CONF['show_undeliverable_exceptions']=array(\"unixmail.domain.ext","exchangeserver.domain.ext\");
\$CONF['show_popimap']='YES';
\$CONF['show_popimap_color']='darkgrey';
\$CONF['show_custom_domains']=array(\"subdomain.domain.ext\",\"domain2.ext\");
\$CONF['show_custom_colors']=array(\"lightgreen\",\"lightblue\");
\$CONF['recipient_delimiter'] = \"\";
\$CONF['mailbox_postcreation_script'] = '';
\$CONF['mailbox_postedit_script'] = '';
\$CONF['mailbox_postdeletion_script'] = '';
\$CONF['domain_postcreation_script'] = '';
\$CONF['domain_postdeletion_script'] = '';
\$CONF['create_mailbox_subdirs'] = array();
\$CONF['create_mailbox_subdirs_host']='localhost';
\$CONF['create_mailbox_subdirs_prefix']='INBOX.';
\$CONF['used_quotas'] = 'NO';
\$CONF['new_quota_table'] = 'YES';
\$CONF['create_mailbox_subdirs_hostoptions'] = array('');
\$CONF['theme_logo'] = 'images/logo-default.png';
\$CONF['theme_css'] = 'css/default.css';
\$CONF['theme_custom_css'] = '';
\$CONF['xmlrpc_enabled'] = false;
if (file_exists(dirname(__FILE__) . '/config.local.php')) {
    include(dirname(__FILE__) . '/config.local.php');
}" > postfixadmin/config.inc.php
chown -R www:www postfixadmin/config.inc.php

echo "Downloading roundcube:"
wget -O roundcube.tar.gz http://sourceforge.net/projects/roundcubemail/files/latest/download
error_check

echo "Unpacking roundcube:"
tar xvf roundcube.tar.gz -C /home/${DOMAIN}
error_check
rm -rf roundcube.tar.gz
mv roundcubemail-* mail


sudo psql -U ${DBUSER} -h localhost -d ${DBNAME} <  /home/${DOMAIN}/mail/SQL/postgres.initial.sql
error_check
mv /home/${DOMAIN}/mail/config/config.inc.php.sample /home/${DOMAIN}/mail/config/config.inc.php
echo "<?php
\$config['db_dsnw'] = 'pgsql://${DBUSER}:${DBPASS}@localhost/${DBNAME}';
" > /home/${DOMAIN}/mail/config/config.inc.php
error_check
mv /home/${DOMAIN}/mail/config/defaults.inc.php /home/${DOMAIN}/mail/config/defaults.inc.php.bak 

cd /home/${DOMAIN}/mail/config/

echo "<?php
\$config = array();
\$rcmail_config['db_dsnw'] = 'pgsql://${DBUSER}:${DBPASS}@localhost/${DBNAME}';
\$config['db_dsnr'] = '';
\$config['db_dsnw_noread'] = false;
\$config['db_persistent'] = false;
\$config['db_prefix'] = '';
\$config['db_table_dsn'] = array();
\$config['db_max_allowed_packet'] = null;
\$config['debug_level'] = 1;
\$config['log_driver'] = 'file';
\$config['log_date_format'] = 'd-M-Y H:i:s O';
\$config['log_session_id'] = 8;
\$config['syslog_id'] = 'roundcube';
\$config['syslog_facility'] = LOG_USER;
\$config['per_user_logging'] = false;
\$config['smtp_log'] = true;
\$config['log_logins'] = false;
\$config['log_session'] = false;
\$config['sql_debug'] = false;
\$config['imap_debug'] = false;
\$config['ldap_debug'] = false;
\$config['smtp_debug'] = false;
\$config['default_host'] = 'ssl://${DOMAINMX}';
\$config['default_port'] = 993;
\$config['imap_conn_options'] = array(
  'ssl'         => array(
	 'verify_peer'  => false,
	 'verfify_peer_name' => false,
   ),
);
\$config['imap_auth_type'] = null;
\$config['imap_timeout'] = 20;
\$config['imap_auth_cid'] = null;
\$config['imap_auth_pw'] = null;
\$config['imap_delimiter'] = null;
\$config['imap_ns_personal'] = null;
\$config['imap_ns_other']    = null;
\$config['imap_ns_shared']   = null;
\$config['imap_force_caps'] = false;
\$config['imap_force_lsub'] = false;
\$config['imap_force_ns'] = false;
\$config['imap_disabled_caps'] = array();
\$config['imap_log_session'] = false;
\$config['imap_cache'] = null;
\$config['messages_cache'] = false;
\$config['imap_cache_ttl'] = '10d';
\$config['messages_cache_ttl'] = '10d';
\$config['messages_cache_threshold'] = 50;
\$config['smtp_server'] = 'tls://${DOMAINMX}';
\$config['smtp_port'] = 587;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['smtp_auth_type'] = '';
\$config['smtp_auth_cid'] = null;
\$config['smtp_auth_pw'] = null;
\$config['smtp_helo_host'] = '';
\$config['smtp_timeout'] = 5;
 \$config['smtp_conn_options'] = array(
   'ssl'         => array(
     'verify_peer'  => false,
     'verify_depth' => 3,
     'cafile'       => '/etc/letsencrypt/live/${DOMAINMX}/cert.pem',
   ),
 );
\$config['ldap_cache'] = 'db';
\$config['ldap_cache_ttl'] = '10m';
\$config['enable_installer'] = true;
\$config['dont_override'] = array();
\$config['disabled_actions'] = array();
\$config['advanced_prefs'] = array();
\$config['support_url'] = '';
\$config['skin_logo'] = null;
\$config['auto_create_user'] = true;
\$config['user_aliases'] = false;
\$config['log_dir'] = RCUBE_INSTALL_PATH . 'logs/';
\$config['temp_dir'] = RCUBE_INSTALL_PATH . 'temp/';
\$config['temp_dir_ttl'] = '48h';
\$config['force_https'] = false;
\$config['use_https'] = true;
\$config['login_autocomplete'] = 0;
\$config['login_lc'] = 2;
\$config['skin_include_php'] = false;
\$config['display_version'] = false;
\$config['session_lifetime'] = 10;
\$config['session_domain'] = '';
\$config['session_name'] = null;
\$config['session_auth_name'] = null;
\$config['session_path'] = null;
\$config['session_storage'] = 'db';
\$config['memcache_hosts'] = null;
\$config['memcache_pconnect'] = true;
\$config['memcache_timeout'] = 1;
\$config['memcache_retry_interval'] = 15;
\$config['ip_check'] = false;
\$config['proxy_whitelist'] = array();
\$config['referer_check'] = false;
\$config['x_frame_options'] = 'sameorigin';
\$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
\$config['username_domain'] = '';
\$config['username_domain_forced'] = false;
\$config['mail_domain'] = '';
\$config['password_charset'] = 'ISO-8859-1';
\$config['sendmail_delay'] = 0;
\$config['max_recipients'] = 0; 
\$config['max_group_members'] = 0; 
\$config['product_name'] = 'Roundcube Webmail';
\$config['useragent'] = 'Roundcube Webmail/'.RCMAIL_VERSION;
\$config['include_host_config'] = false;
\$config['generic_message_footer'] = '';
\$config['generic_message_footer_html'] = '';
\$config['http_received_header'] = false;
\$config['http_received_header_encrypt'] = false;
\$config['mail_header_delimiter'] = NULL;
\$config['line_length'] = 72;
\$config['send_format_flowed'] = true;
\$config['mdn_use_from'] = false;
\$config['identities_level'] = 0;
\$config['identity_image_size'] = 64;
\$config['client_mimetypes'] = null;
\$config['mime_magic'] = null;
\$config['mime_types'] = null;
\$config['im_identify_path'] = null;
\$config['im_convert_path'] = null;
\$config['image_thumbnail_size'] = 240;
\$config['contact_photo_size'] = 160;
\$config['email_dns_check'] = false;
\$config['no_save_sent_messages'] = false;
\$config['use_secure_urls'] = false;
\$config['assets_path'] = '';
\$config['assets_dir'] = '';
\$config['plugins'] = array();
\$config['message_sort_col'] = '';
\$config['message_sort_order'] = 'DESC';
\$config['list_cols'] = array('subject', 'status', 'fromto', 'date', 'size', 'flag', 'attachment');
\$config['language'] = null;
\$config['date_format'] = 'Y-m-d';
\$config['date_formats'] = array('Y-m-d', 'Y/m/d', 'Y.m.d', 'd-m-Y', 'd/m/Y', 'd.m.Y', 'j.n.Y');
\$config['time_format'] = 'H:i';
\$config['time_formats'] = array('G:i', 'H:i', 'g:i a', 'h:i A');
\$config['date_short'] = 'D H:i';
\$config['date_long'] = 'Y-m-d H:i';
\$config['drafts_mbox'] = 'Drafts';
\$config['junk_mbox'] = 'Junk';
\$config['sent_mbox'] = 'Sent';
\$config['trash_mbox'] = 'Trash';
\$config['create_default_folders'] = false;
\$config['protect_default_folders'] = true;
\$config['show_real_foldernames'] = false;
\$config['quota_zero_as_unlimited'] = false;
\$config['enable_spellcheck'] = true;
\$config['spellcheck_dictionary'] = false;
\$config['spellcheck_engine'] = 'googie';
\$config['spellcheck_uri'] = '';
\$config['spellcheck_languages'] = NULL;
\$config['spellcheck_ignore_caps'] = false;
\$config['spellcheck_ignore_nums'] = false;
\$config['spellcheck_ignore_syms'] = false;
\$config['recipients_separator'] = ',';
\$config['sig_max_lines'] = 15;
\$config['max_pagesize'] = 200;
\$config['min_refresh_interval'] = 60;
\$config['upload_progress'] = false;
\$config['undo_timeout'] = 0;
\$config['compose_responses_static'] = array();
\$config['address_book_type'] = 'sql';
\$config['ldap_public'] = array();
\$config['autocomplete_addressbooks'] = array('sql');
\$config['autocomplete_min_length'] = 1;
\$config['autocomplete_threads'] = 0;
\$config['autocomplete_max'] = 15;
\$config['address_template'] = '{street}<br/>{locality} {zipcode}<br/>{country} {region}';
\$config['addressbook_search_mode'] = 0;
\$config['contact_search_name'] = '{name} <{email}>';
\$config['default_charset'] = 'ISO-8859-1';
\$config['skin'] = 'larry';
\$config['standard_windows'] = false;
\$config['mail_pagesize'] = 50;
\$config['addressbook_pagesize'] = 50;
\$config['addressbook_sort_col'] = 'surname';
\$config['addressbook_name_listing'] = 0;
\$config['timezone'] = 'auto';
\$config['prefer_html'] = true;
\$config['show_images'] = 0;
\$config['message_extwin'] = false;
\$config['compose_extwin'] = false;
\$config['htmleditor'] = 0;
\$config['compose_save_localstorage'] = true;
\$config['prettydate'] = true;
\$config['draft_autosave'] = 300;
\$config['preview_pane'] = false;
\$config['preview_pane_mark_read'] = 0;
\$config['logout_purge'] = false;
\$config['logout_expunge'] = false;
\$config['inline_images'] = true;
\$config['mime_param_folding'] = 1;
\$config['skip_deleted'] = false;
\$config['read_when_deleted'] = true;
\$config['flag_for_deletion'] = false;
\$config['refresh_interval'] = 60;
\$config['check_all_folders'] = false;
\$config['display_next'] = true;
\$config['default_list_mode'] = 'list';
\$config['autoexpand_threads'] = 0;
\$config['reply_mode'] = 0;
\$config['strip_existing_sig'] = true;
\$config['show_sig'] = 1;
\$config['sig_below'] = false;
\$config['force_7bit'] = false;
\$config['search_mods'] = null;  
\$config['addressbook_search_mods'] = null;  
\$config['delete_always'] = false;
\$config['delete_junk'] = false;
\$config['mdn_requests'] = 0;
\$config['mdn_default'] = 0;
\$config['dsn_default'] = 0;
\$config['reply_same_folder'] = false;
\$config['forward_attachment'] = false;
\$config['default_addressbook'] = null;
\$config['spellcheck_before_send'] = false;
\$config['autocomplete_single'] = false;
\$config['default_font'] = 'Verdana';
\$config['default_font_size'] = '10pt';
\$config['message_show_email'] = false;
\$config['reply_all_mode'] = 0;
" > defaults.inc.php
error_check

chown -R www:www /home/${DOMAIN}/mail/config/defaults.inc.php
error_check

mv /home/${DOMAIN}/mail/installer /home/${DOMAIN}/mail/installerdjsdlfjs4353dsffer
error_check

cd ${CDIR}

echo "Starting postfix daemon:"
service postfix restart
error_check

echo "Starting dovecot daemon:"
service dovecot restart
error_check

echo "Enabling services:"
update-rc.d postfix defaults
update-rc.d dovecot defaults
error_check

clear
echo -e "$COL_GREEN Setup complete. $COL_RESET"
echo -e "$COL_YELLOW"
echo "Now you should configure postfixadmin on https://${DOMAIN}/postfixadmin/setup.php"
echo "The roundcube is https://${DOMAIN}/mail."
echo "imap's port 993, host to: ssl://${DOMAINMX}"
echo "smtp's port 587, host to tls://${DOMAINMX}"
echo "Use these settings:"
echo "database type: pgsql"
echo "database host: localhost"
echo "database user: ${DBUSER}"
echo "database pass: ${DBPASS}"
echo "database name: ${DBNAME}"
echo -e "$COL_RESET"