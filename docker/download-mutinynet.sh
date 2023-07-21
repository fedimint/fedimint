#!/bin/bash

# This file downloads the mutinynet docker-compose files for the LN gateway and fedimintd
# You can download and run it with: curl -sSL https://raw.githubusercontent.com/fedimint/fedimint/master/docker/download-mutinynet.sh | bash

if ! [ -x "$(command -v curl)" ]; then
  echo 'Error: curl is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  exit 1
fi

download() {
  local url=$1
  local path=$2
  curl -sSL $url -o $path
}

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
  download https://raw.githubusercontent.com/fedimint/fedimint/master/docker/fedimintd-mutinynet/docker-compose.yaml $FEDIMINTD_DIR/docker-compose.yaml
  replace_external_ip $FEDIMINTD_DIR/docker-compose.yaml
fi

read -p "Do you want to install the LN gateway? [Y/n] " -n 1 -r -a gateway_install < /dev/tty
if [[ ${gateway_install[*]} =~ ^[Yy]?$ ]]; then
  # ask the user for the gateway password
  DEFAUT_GATEWAY_PASSWORD=thereisnosecondbest
  read -p "Enter the password for the LN gateway: [$DEFAUT_GATEWAY_PASSWORD] " -a gateway_password < /dev/tty
  if [[ -z ${gateway_password[*]} ]]; then
    gateway_password=$DEFAUT_GATEWAY_PASSWORD
  fi
  mkdir -p $GATEWAY_DIR
  download https://raw.githubusercontent.com/fedimint/fedimint/master/docker/gateway-mutinynet/docker-compose.yaml $GATEWAY_DIR/docker-compose.yaml
  replace_external_ip $GATEWAY_DIR/docker-compose.yaml
  sed -i "s/$DEFAUT_GATEWAY_PASSWORD/$gateway_password/g" $GATEWAY_DIR/docker-compose.yaml
fi

if [[ ${fedimintd_install[*]} =~ ^[Yy]?$ ]]; then
  echo "Running 'docker-compose -f $FEDIMINTD_DIR/docker-compose.yaml up -d' to start fedimintd"
  docker-compose -f $FEDIMINTD_DIR/docker-compose.yaml up -d
  echo "Optionally run 'docker-compose -f $FEDIMINTD_DIR/docker-compose.yaml logs -f' to see the logs"
  echo
fi

if [[ ${gateway_install[*]} =~ ^[Yy]?$ ]]; then
  echo "Running 'docker-compose -f $GATEWAY_DIR/docker-compose.yaml up -d' to start the LN gateway"
  docker-compose -f $GATEWAY_DIR/docker-compose.yaml up -d
  echo "Optionally run 'docker-compose -f $GATEWAY_DIR/docker-compose.yaml logs -f' to see the logs"
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
