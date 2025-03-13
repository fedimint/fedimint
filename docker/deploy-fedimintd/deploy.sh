#!/usr/bin/env bash

set -euo pipefail

##
## Args handling
##

# domain to use for a host
domain="$1"
# ssh host name to use for ssh commands (defaults to the domain above)
ssh_host="${2:-${domain}}"

# host dir we'll keep the files on
host_dir=/root/fedimint-docker

##
## Verify intention
##

if [ -z "${FM_DOCKER_COMPOSE_DEPLOY:-}" ]; then
  cat >&2 << EOF
This script will use ssh to set up 'docker-compose'-based Fedimint node
on $ssh_host which is supposed to be a fresh Ubuntu OS.

To make sure you're aware of it, please set FM_DOCKER_COMPOSE_DEPLOY
env variable.

If unsure, please ask for help on the Fedimint Discord #mint-ops channel.
EOF
  exit 1
fi


if [ -z "${FM_DOCKER_COMPOSE_DEPLOY_WIPE:-}" ]; then
  # shellcheck disable=SC2087
  if ssh "root@$ssh_host" "test -e $host_dir" ; then

    cat >&2 << EOF
!!!
!!! Previous installation of this script detected.
!!!

If your intention is to WIPE the previous installation
and start from scratch, set FM_DOCKER_COMPOSE_DEPLOY_WIPE env var.
EOF
  exit 1

  fi
fi

##
## Wipe the previous host
##

echo >&2 '### Wiping previous setup'

# shellcheck disable=SC2087
ssh -q "root@$ssh_host" << EOF
  touch ~/.hushlogin

  systemctl stop fedimint-docker-compose 2>/dev/null || true

  if [ -e $host_dir  ] ; then
    # Stop the docker-compose stack
    cd $host_dir && docker-compose down 2>/dev/null || true
    # We remove only the fedimintd_data named volume
    docker volume rm fedimint-docker_fedimintd_data 2>/dev/null || true
  fi

  rm -rf /root/fedimint-docker
  rm -rf /etc/systemd/system/fedimint-docker-compose.service
  sudo systemctl daemon-reload

EOF


##
## Setup new machine
##

echo >&2 '### Setting up the server'

echo >&2 '### Copying files...'
cat << EOF | ssh "root@$ssh_host" "sudo cat > /etc/systemd/system/fedimint-docker-compose.service"
[Unit]
Description=Fedimint Docker Compose Service
Requires=docker.service
After=docker.service

[Service]
WorkingDirectory=${host_dir}
ExecStart=/usr/bin/docker-compose up
ExecStop=/usr/bin/docker-compose down
Restart=always

[Install]
WantedBy=multi-user.target
EOF

scp -r .env docker-compose.yaml "root@$ssh_host:/root/fedimint-docker"

echo >&2 '### Setting up...'

# shellcheck disable=SC2087
ssh -q "root@$ssh_host" << EOF
  touch ~/.hushlogin

  sed -i 's/my-super-host.com/$domain/g' $host_dir/.env

  ufw --force reset

  apt-get update && apt-get install -q -y docker-compose

  systemctl daemon-reload
  systemctl enable fedimint-docker-compose
  systemctl start fedimint-docker-compose
EOF

cat >&2 << EOF

##
## Done. Here are some things you might want to know:
##

Make sure you protect access to this system. AT MINIMUM,
disable password-based authentication.
See https://serverfault.com/a/909821 and similar articles.

The firewall was configured and enabled for you.

docker-compose services were defined in the $host_dir and
if ever need arise you can adjust them from there. You can
'cd' to that directory and use 'docker-compose' to do basic
operations. E.g. 'docker-compose logs fedimintd' to view the
logs, or 'docker-compose exec -u bitcoin bitcoin bash' to
"enter" bitcoind container.

Systemd unit 'fedimint-docker-compose' was installed and
enabled to start all services automatically. Use

* 'journalctl -u fedimint-docker-compose -f' to view all logs
* 'systemctl status fedimint-docker-compose' to check status

All service volumes are managed by docker/docker-compose and can
be found in '/var/lib/docker/volumes/'.

Bitcoin Core node will run in a pruned mode with minimum resource
usage, but it might take it days to finish IBD. You can speed
it up by copying an existing chain data.

You should be able to go to https://$domain and access
Fedimint Admin UI.

EOF
