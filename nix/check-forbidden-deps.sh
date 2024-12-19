#!/usr/bin/env bash

set -eo pipefail

if grep -E "fedimint-[a-zA-Z0-9]+-(server|client|common)" fedimint-server/Cargo.toml | grep -v -E "fedimint-api-client|fedimint-dummy-common|fedimint-dummy-server" >&2 ; then
  >&2 echo "fedimint-server/Cargo.toml must not depend on modules"
  return 1
fi
if grep -E "fedimint-[a-zA-Z0-9]+-(server|client)" fedimint-testing/Cargo.toml | grep -v "fedimint-api-client" >&2 ; then
  >&2 echo "fedimint-testing/Cargo.toml must not depend on modules"
  return 1
fi
find modules/ -name Cargo.toml | grep common/ | while read -r cargo_toml ; do
  if grep -E "fedimint-" "$cargo_toml" | grep -E -v "fedimint-core|fedimint-api-client|-common|fedimint-logging" >&2 ; then
    >&2 echo "Fedimint modules' -common crates should not introduce new fedimint dependencies: $cargo_toml"
    >&2 echo "The goal is to avoid circular deps that blow up build times. Ping @dpc for help."
    return 1
  fi
done
find gateway/ -name Cargo.toml | while read -r cargo_toml ; do
  if grep -E "fedimint-server" "$cargo_toml" >&2 ; then
    >&2 echo "$cargo_toml must not depend on fedimint-server"
    return 1
  fi
done
find fedimint-client/ -name Cargo.toml | while read -r cargo_toml ; do
  if grep -E "fedimint-server" "$cargo_toml" >&2 ; then
    >&2 echo "$cargo_toml must not depend on fedimint-server"
    return 1
  fi
done
echo Cargo.lock | while read -r cargo_lock ; do
  if grep -E "openssl" "$cargo_lock" >&2 ; then
    >&2 echo "$cargo_lock must not depend on openssl"
    return 1
  fi
done
