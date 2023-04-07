#!/usr/bin/env bash

# if command specified - run it inside
if [ -n "$*" ]; then
 exec "$@"
fi

if [ -z "$FM_DATA_DIR" ]; then
  1>&2 echo "Must provide FM_DATA_DIR environment variable"
  exit 1
fi

if [ -z "$FM_PASSWORD" ]; then
  1>&2 echo "Must provide FM_PASSWORD environment variable"
  exit 1
fi

if [ ! -e "$FM_DATA_DIR" ]; then
  1>&2 echo "Creating $FM_DATA_DIR"
  mkdir -p "$FM_DATA_DIR" && chmod 0600 "$FM_DATA_DIR"
fi

mkdir -p "$FM_DATA_DIR"

if [ -z "$FM_LISTEN_UI" ]; then
  export FM_LISTEN_UI=0.0.0.0:8176
fi

1>&2 echo 'Starting fedimintd'
fedimintd --data-dir "$FM_DATA_DIR/"
