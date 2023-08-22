#!/usr/share/env bash
#
# Utility functions for scripts.
#
# Functions only, please don't put any code that actually does things.

# kill the last command spawned in the background (with '&') at the end of a script
# optionally can have name passed
function auto_kill_last_cmd() {
  pid=$!

  # For shellcheck - we want these expanded right away
  # shellcheck disable=SC2064
  trap ">&2 echo 'Auto-killing ${1:-}(PID: $pid)'; kill $pid" EXIT  
}
