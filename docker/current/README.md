# Example Fedimint docker-compose-based deployment

This script will deploy Fedimint setup on a fresh
Ubuntu VM.

The `./deploy.sh <domain>` will use ssh to install docker
containers for:

* `bitcoind`
* `traefik`
* `fedimintd`
* `fedimint-ui`

The `<domain>` needs to point at fresh Ubuntu server.

We recommend you review the provided files before using them.
It's all fairly small.
