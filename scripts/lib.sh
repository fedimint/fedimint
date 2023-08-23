#!/usr/share/env bash
#
# Utility functions for scripts.
#
# Functions only, please don't put any code that actually does things.

# kill the pid running on background (with '&') at the end of a script
# optionally can have name passed
function kill_on_exit() {
  pid=$1

  cmd="{ \
    if kill -0 $pid >& /dev/null; then \
      >&2 echo 'Auto-killing ${2:-}(PID: $pid)'; \
      kill $pid; \
    else \
      >&2 echo 'Process ${2:-}(PID: $pid) already finished'; \
    fi \
  }"
  # For shellcheck - we want these expanded right away
  # shellcheck disable=SC2064
  trap "$cmd" EXIT
}
