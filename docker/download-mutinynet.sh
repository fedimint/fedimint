#!/bin/bash
# shellcheck disable=SC2128,SC2178
# This file downloads the mutinynet docker-compose files for the LN gateway and fedimintd
# You can download and run it with: curl -sSL https://raw.githubusercontent.com/fedimint/fedimint/master/docker/download-mutinynet.sh | bash

DOCKER_COMPOSE=docker-compose
if docker compose version|grep 'Docker Compose' >& /dev/null; then
  DOCKER_COMPOSE="docker compose"
elif ! [ -x "$(command -v docker-compose)" ]; then
  # check if we are running as root
  if [ "$EUID" -ne 0 ]; then
    echo 'Error: docker-compose is not installed and we can not install it for you.' >&2
    exit 1
  fi
  if [ -x "$(command -v apt)" ]; then
    apt install -y docker-compose
  elif [ -x "$(command -v yum)" ]; then
    yum install -y docker-compose
  elif [ -x "$(command -v dnf)" ]; then
    dnf install -y docker-compose
  elif [ -x "$(command -v pacman)" ]; then
    pacman -S --noconfirm docker-compose
  elif [ -x "$(command -v apk)" ]; then
    apk add docker-compose
  else
    echo 'Error: docker-compose is not installed and we could not install it for you.' >&2
    exit 1
  fi
  if ! [ -x "$(command -v docker-compose)" ]; then
    echo 'Error: docker-compose is not installed and we could not install it for you.' >&2
    exit 1
  fi
fi

if ! [ -x "$(command -v curl)" ]; then
  echo 'Error: curl is not installed.' >&2
  exit 1
fi


download() {
  local url=$1
  local path=$2
  curl -sSL $url -o $path
}

while true; do
  read -p "Enter the version of Fedimint you want to use [0 for latest (0.2), 1 for 0.1, 2 for 0.2, or 'exit' to quit]: " -a fedimint_version < /dev/tty
  case "$fedimint_version" in
    1)
      fedimint_version=0.1
      break
      ;;
    2)
      fedimint_version=0.2
      break
      ;;
    ""|0)
      fedimint_version=latest
      break
      ;;
    "exit")
      exit 1
      ;;
    *)
      echo "Invalid input. Please enter 0 for latest, 1 for 0.1, 2 for 0.2, or 'exit' to quit."
      ;;
  esac
done

GATEWAY_DIR=gateway
FEDIMINTD_DIR=fedimintd

EXTERNAL_IP=$(curl -sSL ifconfig.me)

read -p "Enter the external IP of your server [$EXTERNAL_IP]: " -a external_ip < /dev/tty
if [[ -z ${external_ip[*]} ]]; then
  external_ip=$EXTERNAL_IP
fi

replace_external_ip() {
  local path=$1
  sed -i "s/127.0.0.1/$external_ip/g" $path
}

read -p "Do you want to install fedimintd? [Y/n] " -n 1 -r -a fedimintd_install < /dev/tty
if [[ ${fedimintd_install[*]} =~ ^[Yy]?$ ]]; then
  mkdir -p $FEDIMINTD_DIR
  download https://raw.githubusercontent.com/fedimint/fedimint/master/docker/${fedimint_version}/fedimintd-mutinynet/docker-compose.yaml $FEDIMINTD_DIR/docker-compose.yaml
  replace_external_ip $FEDIMINTD_DIR/docker-compose.yaml
fi

read -p "Do you want to install the LN gateway? [Y/n] " -n 1 -r -a gateway_install < /dev/tty
if [[ ${gateway_install[*]} =~ ^[Yy]?$ ]]; then
  # ask the user for the gateway password
  DEFAULT_GATEWAY_PASSWORD=thereisnosecondbest
  read -p "Enter the password for the LN gateway: [$DEFAULT_GATEWAY_PASSWORD] " -a gateway_password < /dev/tty
  if [[ -z ${gateway_password[*]} ]]; then
    gateway_password=$DEFAULT_GATEWAY_PASSWORD
  fi
  mkdir -p $GATEWAY_DIR
  download https://raw.githubusercontent.com/fedimint/fedimint/master/docker/${fedimint_version}/gateway-mutinynet/docker-compose.yaml $GATEWAY_DIR/docker-compose.yaml
  replace_external_ip $GATEWAY_DIR/docker-compose.yaml
  sed -i "s/$DEFAULT_GATEWAY_PASSWORD/$gateway_password/g" $GATEWAY_DIR/docker-compose.yaml
fi

if [[ ${fedimintd_install[*]} =~ ^[Yy]?$ ]]; then
  echo "Running '$DOCKER_COMPOSE -f $FEDIMINTD_DIR/docker-compose.yaml up -d' to start fedimintd"
  $DOCKER_COMPOSE -f $FEDIMINTD_DIR/docker-compose.yaml up -d
  echo "Optionally run '$DOCKER_COMPOSE -f $FEDIMINTD_DIR/docker-compose.yaml logs -f' to see the logs"
  echo
fi

if [[ ${gateway_install[*]} =~ ^[Yy]?$ ]]; then
  echo "Running '$DOCKER_COMPOSE -f $GATEWAY_DIR/docker-compose.yaml up -d' to start the LN gateway"
  $DOCKER_COMPOSE -f $GATEWAY_DIR/docker-compose.yaml up -d
  echo "Optionally run '$DOCKER_COMPOSE -f $GATEWAY_DIR/docker-compose.yaml logs -f' to see the logs"
  echo
fi

if [[ ${fedimintd_install[*]} =~ ^[Yy]?$ ]]; then
  echo "You can access the fedimintd dashboard at http://$external_ip:3000"
  echo "Note: by default you should open ports 8173 and 8174 for external access on your router/firewall, plus the ports mentioned above"
fi

if [[ ${gateway_install[*]} =~ ^[Yy]?$ ]]; then
  echo "You can access the LN gateway at http://$external_ip:3001"
  echo "And the node management interface RTL at http://$external_ip:3003"
  echo "Note: by default you should open port 9735 for external access on your router/firewall, plus the ports mentioned above"
fi
