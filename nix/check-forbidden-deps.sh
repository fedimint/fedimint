#!/usr/bin/env bash

set -eo pipefail

if grep -E "(fedimint-mint|fedimint-wallet|fedimint-ln)" fedimint-server/Cargo.toml >&2 ; then
  >&2 echo "fedimint-server/Cargo.toml must not depend on modules"
  return 1
fi
if grep -E "(fedimint-mint|fedimint-wallet|fedimint-ln)" fedimint-testing/Cargo.toml >&2 ; then
  >&2 echo "fedimint-testing/Cargo.toml must not depend on modules"
  return 1
fi
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
find ./ -name Cargo.lock | while read -r cargo_lock ; do
  if grep -E "openssl" "$cargo_lock" >&2 ; then
    >&2 echo "$cargo_lock must not depend on openssl"
    return 1
  fi
done
