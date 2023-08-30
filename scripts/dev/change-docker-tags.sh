#!/usr/bin/env bash

path=${1:?Missing path, Usage: $0 <path-to-docker-compose-files> <new-tag>}
new_tag=${2:?Missing tag, Usage: $0 <path-to-docker-compose-files> <new-tag>}

files=$(find "$path" -name "docker-compose.y?ml" -type f)

if [ -z "$files" ]; then
  echo "No docker-compose files found in $path"
  exit 1
fi

for file in $files; do
  sed -ri "s/image: fedimint\/(fedimintd|gatewayd):.*/image: fedimint\/\1:$new_tag/g" "$file"
done

