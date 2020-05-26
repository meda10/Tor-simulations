# ------------------------------------------------------------------------
# Author: Alexander Kachkaev
# Webpage: https://github.com/kachkaev
# Skript : https://github.com/nginx-proxy/nginx-proxy/issues/456
# Creates user credentials for nginx based on .env file
# ------------------------------------------------------------------------

#build.sh
#!/bin/bash

if [ "${HTTP_AUTH_PASSWORD}" != "" ]; then
  sed -i "s/#auth_basic/auth_basic/g;" /etc/nginx/conf.d/default.conf
  rm -rf /etc/nginx/.htpasswd
  echo -n $HTTP_AUTH_LOGIN:$(openssl passwd -apr1 $HTTP_AUTH_PASSWORD) >> /etc/nginx/.htpasswd
  echo "Basic auth is on for user ${HTTP_AUTH_LOGIN}..."
else
  echo "Basic auth is off (HTTP_AUTH_PASSWORD not provided)"
fi

nginx -g "daemon off;"