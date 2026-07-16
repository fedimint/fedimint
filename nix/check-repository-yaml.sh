#!/usr/bin/env bash

set -euo pipefail

python3 -m unittest discover -s .github/scripts/tests -p 'test_*.py'
python3 .github/scripts/validate-repository-yaml.py
actionlint

validate_compose() {
  local file="$1"

  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    docker compose -f "${file}" config --quiet
  elif command -v docker-compose >/dev/null; then
    docker-compose -f "${file}" config --quiet
  else
    echo "docker compose is required to validate ${file}" >&2
    return 1
  fi
}

validate_compose docker/fedimintd/docker-compose.yaml
validate_compose docker/gatewayd/docker-compose.yaml
