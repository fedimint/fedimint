#!/bin/bash

# This file downloads the mutinynet docker-compose files for the LN gateway and fedimintd
# Important: This version uses TLS certificates, so you must have a domain under your control that you can change the DNS records for
# You can download this script and run it with: curl -sSL https://raw.githubusercontent.com/fedimint/fedimint/master/docker/tls-download-mutinynet.sh | bash

DOCKER_COMPOSE_FILE=https://raw.githubusercontent.com/fedimint/fedimint/master/docker/full-tls-mutinynet/docker-compose.yaml

if ! [ -x "$(command -v docker-compose)" ]; then
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

COMMANDS="awk curl sed tr wc jq"
for command in $COMMANDS; do
  if ! [ -x "$(command -v $command)" ]; then
    echo "Error: $command is not installed. Please try to install it" >&2
    exit 1
  fi
done

if [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 2000000 ]; then
  echo 'Error: Your machine must have at least 2GB of RAM' >&2
  exit 1
fi



resolve_host() {
  local host=$1
  if [ -x "$(command -v host)" ]; then
    host $host | awk '/has address/ { print $4 ; exit }'
  elif [ -x "$(command -v nslookup)" ]; then
    nslookup $host | awk '/^Address: / { print $2 ; exit }'
  elif [ -x "$(command -v dig)" ]; then
    dig $host | awk '/^;; ANSWER SECTION:$/ { getline ; print $5 ; exit }'
  elif [ -x "$(command -v getent)" ]; then
    getent hosts $host | awk '{ print $1 ; exit }'
  else
    echo "Error: no command found to resolve host $host" >&2
    exit 1
  fi
}

download() {
  local url=$1
  local path=$2
  curl -sSL $url -o $path
}

replace_host() {
  local external_host=$1
  local path=$2
  sed -i "s/fedimint.my-super-host.com/$external_host/g" $path
}

count_dots() {
  local s=$1
  tr -dc '.' <<<"$s" | wc -c
}

EXTERNAL_IP=$(curl -sSL ifconfig.me)

SERVICES="fedimintd guardian-ui gatewayd gateway-ui rtl"

echo
echo "Welcome to the fedimint setup script with TLS certificates by Let's Encrypt"
echo
echo "Your ip is $EXTERNAL_IP. You __must__ open the port 443 on your firewall so we can setup the TLS certificates."
echo "If you are unable to open this port, then the TLS setup and everything else will catastrophically or silently fail."
echo "So in this case you can not use this script and you must setup the TLS certificates manually or use a script without TLS"
read -p "Press enter to acknowledge this " -r -n 1 < /dev/tty

echo
echo "Next step you will setup some DNS records pointing to this machine's ip ($EXTERNAL_IP), something like:"
for service in $SERVICES; do
  echo "$service.fedimint.example.com"
done

echo
while true; do
  read -p "What will be your host name suffix? (like fedimint.example.com in the above example): " -r -a host_name < /dev/tty
  if [[ $(count_dots "${host_name[*]}") -eq 0 ]]; then
    echo "Error: invalid host name, it must be a subdomain, like fedimint.example.com"
  elif [[ $(count_dots "${host_name[*]}") -eq 1 ]]; then
    echo "We recommend having a subdomain for the services, like fedimint.example.com (instead of just example.com)"
    read -p "Are you sure you want to use ${host_name[*]}? [Y/n] " -n 1 -r -a use_host_name < /dev/tty
    echo
    if [[ ${use_host_name[*]} =~ ^[Yy]?$ ]]; then
      break
    fi
  else
    break
  fi
done

echo
echo "So now you should setup the following DNS records:"
echo "We recommend creating an 'A' record of '${host_name[*]}' pointing to $EXTERNAL_IP then set 'CNAME's pointing to ${host_name[*]} for the services, something like:"
echo
echo "${host_name[*]} A $EXTERNAL_IP"
for service in $SERVICES; do
  echo "$service.${host_name[*]} CNAME ${host_name[*]}"
done

echo
read -p "Press enter after you have created the above DNS records " -r -n 1 < /dev/tty
echo
echo "DNS propagation may take a while and and caching may cause issues, so try to verify on another machine if the following is true:"
echo "${host_name[*]} -> $EXTERNAL_IP"
for service in $SERVICES; do
  echo "$service.${host_name[*]} -> $EXTERNAL_IP"
done
echo
read -p "Press enter after you have verified them on another machine  " -r -n 1 < /dev/tty
echo
while true; do
  error=""
  echo "Checking DNS records..."
  for service in root $SERVICES; do
    if [[ $service == "root" ]]; then
      external_host=${host_name[*]}
    else
      external_host=$service.${host_name[*]}
    fi
    resolved_host=$(resolve_host $external_host)
    if [[ -z $resolved_host ]]; then
      echo "Error: $external_host does not resolve to anything!"
      error=true
    elif [[ $resolved_host != "$EXTERNAL_IP" ]]; then
      echo "Error: $external_host does not resolve to $EXTERNAL_IP, it resolves to $resolved_host"
      error=true
    fi
  done

  if [[ -z $error ]]; then
    echo "All DNS records look good"
    break
  else
    echo "Some DNS records are not correct"
    read -p "Check again? [Y/n] " -n 1 -r -a check_again < /dev/tty
    if [[ ${check_again[*]} =~ ^[Yy]?$ ]]; then
      continue
    else
      echo
      echo "If you are sure the DNS records are correct, you can continue without checking"
      echo "But if there is some issue with them, the Let's Encrypt certificates will not be able to be created"
      echo "And you may receive a throttle error from Let's Encrypt that may take hours to go away"
      echo "Therefore we recommend you double check everything"
      echo "If you suspect it's just a caching issue, then wait a few minutes and try again. Do not continue."
      echo
      read -p "Continue without checking? [y/N] " -n 1 -r -a continue_without_checking < /dev/tty
      echo
      if [[ ${continue_without_checking[*]} =~ ^[Yy]$ ]]; then
        echo "You have been warned, continuing..."
        break
      fi
    fi
  fi
done

download $DOCKER_COMPOSE_FILE ./docker-compose.yaml
replace_host "${host_name[*]}" ./docker-compose.yaml
# ask the user for the gateway password
DEFAULT_GATEWAY_PASSWORD=thereisnosecondbest
read -p "Enter the password for the gateway and RTL interface [$DEFAULT_GATEWAY_PASSWORD]: " -a gateway_password < /dev/tty
if [[ -z ${gateway_password[*]} ]]; then
  gateway_password=$DEFAULT_GATEWAY_PASSWORD
fi
sed -i "s/$DEFAULT_GATEWAY_PASSWORD/$gateway_password/g" ./docker-compose.yaml

echo
echo "Running 'docker-compose up -d' to start the services"
docker-compose up -d

echo -n "Waiting for fedimintd to be ready. Don't do anything yet..."

wait_fedimintd_ready() {
  flags=$1
  while true; do 
    status=$(curl $flags -s -q -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0", "method": "status", "params": [{"params":null}],"id":1}'  "https://fedimintd.${host_name[*]}" | jq -r .result.server )
    if [[ $status == "AwaitingPassword" ]]; then
      echo
      break
    else
      echo -n "."
      sleep 1
    fi
  done
}

wait_fedimintd_ready --insecure

echo "Looks good. Now will check if certificate is okay."
echo "You may take a look at 'docker-compose logs -f traefik' it this takes too long"
echo "But before doing that, please wait at least 5 minutes, as it may take a while to get the certificate. Be patient."
echo -n "Checking, please wait..."

wait_fedimintd_ready

echo "Good!"
echo "Restarting to make sure all services will read the updated certificate"

docker-compose restart

echo
echo "Optionally run 'docker-compose logs -f' to see the logs"
echo "You can access the fedimint dashboard at https://guardian-ui.${host_name[*]}"
echo "The LN gateway at https://gateway-ui.${host_name[*]}"
echo "And the node management interface RTL at https://rtl.${host_name[*]}"
echo "Note: by default you should open ports 8173 and 9735 for external access on your router/firewall, plus 443 as mentioned before"

