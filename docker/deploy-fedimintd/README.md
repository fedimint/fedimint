# Fedimint docker-compose-based deployment

This script will deploy fedimintd node on a fresh
Ubuntu system.

The `./deploy.sh <domain>` will use ssh to install docker
containers for:

* `bitcoind`
* `traefik`
* `fedimintd` (includes built-in guardian dashboard UI)

The `<domain>` needs to point at a fresh Ubuntu server.

We recommend you review the provided files before using them.
It's all fairly small.
