#!/bin/bash

# Check for required commands
for cmd in lsof rg awk xargs; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: $cmd is not installed. Please install it and try again."
    exit 1
  fi
done

# List the processes
processes=$(lsof | rg 'fedimintd|lnd|bitcoind|gatewayd' | awk '{print $2}')

# Check if there are any processes to kill
if [ -z "$processes" ]; then
  echo "No matching processes found."
  exit 0
fi

# Confirm the action
echo "The following processes will be killed:"
echo "$processes"
read -p "Are you sure you want to continue? (y/N) " choice

if [[ $choice =~ ^[Yy]$ ]]; then
  echo "$processes" | xargs kill -9
  echo "Processes killed."
else
  echo "Operation canceled."
fi
