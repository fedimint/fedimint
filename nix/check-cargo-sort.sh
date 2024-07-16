#!/usr/bin/env bash

set -eo pipefail

cargo sort -w -g --order package,features,bin,lib,test,bench,dependencies,dev-dependencies,build-dependencies --check >/dev/null
