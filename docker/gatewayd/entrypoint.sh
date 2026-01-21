#!/bin/sh

# Bcrypt hash the password before giving it to the gateway
FM_GATEWAY_BCRYPT_PASSWORD_HASH=$(gateway-cli create-password-hash "$APP_PASSWORD" \
  | sed 's/^"//; s/"$//' \
  | sed 's/\$/$$/g'
)
export FM_GATEWAY_BCRYPT_PASSWORD_HASH

gatewayd ldk
