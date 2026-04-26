#!/bin/bash
mkdir -p nginx/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/certs/ngfw.key \
  -out nginx/certs/ngfw.crt \
  -subj "/C=US/ST=State/L=City/O=NGFW/OU=IT/CN=localhost"
echo "SSL Certs generated in nginx/certs/"
