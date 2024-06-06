#!/bin/bash

# You can download this script and run it with: curl -sSL https://raw.githubusercontent.com/Kodylow/fedimint/kl/docker-deploy/docker/downloader.sh | bash

echo
echo """
                                                    %%
                                                  ######
                                                  ((((
                                      %%##(                    (##%%
                                      ##((/       ******       /((##
                                            *******,,*******
                                            ****          ***,
                                            ***            ***
                                  *#((    ****            ****    ((#
                                  %%##((    ****          ****   ,((##%*
                                    ##(       **************       (##
                                                **********

                                          ##((((        ((((##
                                            %%##*        ###%%


@@@@@@@@@@@@                              @@@    @@@@                           @@@@                      @@@
@@@                                       @@@                                                             @@@
@@@             @@@@@@@@@%      /@@@@@@@@ @@@    @@@    @@@(@@@@@@  @@@@@@@     @@@    @@@ @@@@@@@@   @@@@@@@@@@@
@@@@@@@@@@@.  @@@@      @@@    @@@.      @@@@    @@@    @@@     @@@@     @@@    @@@    @@@@      @@@      @@@
@@@           @@@@@@@@@@@@@@  @@@         @@@    @@@    @@@     /@@@     @@@    @@@    @@@       #@@&     @@@
@@@           @@@             @@@         @@@    @@@    @@@     /@@@     @@@    @@@    @@@       #@@&     @@@
@@@           .@@@,     @@@    @@@@     &@@@@    @@@    @@@     /@@@     @@@    @@@    @@@       #@@&     @@@
@@@              @@@@@@@@        @@@@@@@@ @@@    @@@    @@@     /@@@     @@@    @@@    @@@       #@@&      @@@@@@
"""

echo
echo
echo "Welcome to the Fedimint Docker Installer. This script will:"
echo "1. Download/check docker and other required dependencies."
echo "2. Ask some questions to set:"
echo "   - The type of installation (guardian or gateway)."
echo "   - Which services to install or use an external source for."
echo "   - Whether to install and use Let's Encrypt TLS certificates."
echo "3. Download and configure the docker-compose files for the Fedimint services."
echo "4. Run the docker-compose files to start the services."

echo
echo "Fedimint is early stage software, so please be patient and report any issues you encounter by opening an issue on Github: https://github.com/fedimint/fedimint/issues"
echo "Or join the Fedimint Discord server and post an issue there: https://discord.gg/9CFbk6BvaJ"
echo
echo "Ready to start?"
while true; do
  read -p "Type 'yes' to start: " START </dev/tty
  if [[ $START == "yes" ]]; then
    break
  fi

done

echo "Checking docker and other required dependencies..."

DOCKER_COMPOSE=docker-compose
if docker compose version | grep 'Docker Compose' >&/dev/null; then
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

COMMANDS="awk curl sed tr wc jq"
for command in $COMMANDS; do
  if ! [ -x "$(command -v $command)" ]; then
    echo "Error: $command is not installed. Please try to install it" >&2
    exit 1
  fi
done

if [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 900000 ]; then
  echo 'Error: Your machine must have at least 1GB of RAM' >&2
  exit 1
fi

echo "Dependencies are ready. Let's continue..."
echo
echo "Do you want to install a Fedimint Guardian or a Lightning Gateway? [guardian/gateway]"
echo "Guardian: connects with other guardians to form and run a Fedimint"
echo "Gateway: a lightning network service provider to users of Fedimints"
while true; do
  read -p "Type 'guardian' or 'gateway': " INSTALL_TYPE </dev/tty

  case $INSTALL_TYPE in
  guardian)
    SERVICES="fedimintd guardian-ui bitcoindxmpp"
    IS_GATEWAY=false
    break
    ;;
  gateway)
    SERVICES="gatewayd gateway-ui thunderhub"
    IS_GATEWAY=true
    break
    ;;
  *)
    echo "Invalid option. Please type 'guardian' or 'gateway'."
    ;;
  esac
done

echo
echo "Which Bitcoin network are you setting up for? [mainnet/mutinynet]"
while true; do
  read -p "Type your choice: " NETWORK_TYPE </dev/tty

  case $NETWORK_TYPE in
  mainnet)
    echo "Warning: Fedimint is alpha software. Running mainnet is currently recommended only for experienced developers who understand the risks."
    echo "You MUST setup with TLS if you are running mainnet."
    read -p "Do you acknowledge this and wish to continue? (Type the word 'yes' to acknowledge): " ACKNOWLEDGE </dev/tty
    if [[ $ACKNOWLEDGE != "yes" ]]; then
      echo "Installation aborted. Please reconsider the network choice if you are not ready for mainnet."
      exit 1
    else
      SETUP_TLS=true
      TLS_DIR="tls"
      break
    fi
    ;;
  mutinynet)
    break
    ;;
  *)
    echo "Invalid network type. Please choose from mainnet or mutinynet."
    ;;
  esac
done

echo "Setting up for $NETWORK_TYPE. Proceeding with installation."

if [[ -z $SETUP_TLS ]] || [[ -z $TLS_DIR ]]; then
  echo
  echo "Do you want to setup TLS certificates with Let's Encrypt? [yes/no]"
  while true; do
    read -p "Type 'yes' to setup TLS certificates or 'no' to skip: " SETUP_TLS </dev/tty
    case $SETUP_TLS in
    yes)
      SETUP_TLS=true
      TLS_DIR="tls"
      break
      ;;
    no)
      SETUP_TLS=false
      TLS_DIR="no-tls"
      break
      ;;
    *)
      echo "Invalid option. Please type 'yes' or 'no'."
      ;;
    esac
  done
else
  echo "Running mainnet, you must setup with TLS."
fi

DOCKER_COMPOSE_FILE="https://raw.githubusercontent.com/Kodylow/fedimint/kl/docker-deploy/docker/${INSTALL_TYPE}/${TLS_DIR}/docker-compose.yaml"

echo
if [ "$IS_GATEWAY" = false ]; then
  echo "The Guardian requires a source of blockchain data, either a Bitcoin Node or using an Esplora API."
  echo "Do you want to configure this Fedimint Guardian with:"
  echo "1. An Esplora API"
  echo "2. An existing Bitcoin node"
  while true; do
    read -r -n 1 -p "Your choice (1/2): " choice </dev/tty
    echo
    case $choice in
    1)
      USE_ESPLORA=true
      break
      ;;
    2)
      USE_ESPLORA=false
      break
      ;;
    *)
      echo "Invalid option. Please choose 1 or 2."
      ;;
    esac
  done
else # Is Gateway
  echo "The Lightning Gateway requires a Lightning node to connect to."
  echo "This installer is only compatible with LND, for Core Lightning you'll need to run the gateway plugin."
  echo "Do you want to configure this Lightning Gateway to:"
  echo "1. Start and use a new LND Lightning node"
  echo "2. Point at an existing LND Lightning node"
  while true; do
    read -r -n 1 -p "Your choice (1/2): " choice </dev/tty
    echo
    case $choice in
    1)
      START_NEW_LND_NODE=true
      break
      ;;
    2)
      START_NEW_LND_NODE=false
      break
      ;;
    *)
      echo "Invalid option. Please choose 1 or 2."
      ;;
    esac
  done

  # Ask if they want to run fedimint's thunderhub fork
  echo "Do you want to run thunderhub for the lightning gateway?"
  echo "This is a fork of thunderhub that is compatible with the Fedimint lightning gateway."
  echo "It lets you manage your lightning node and multiple fedimints' ecash from a single interface."
  echo
  while true; do
    read -p "Do you want to run thunderhub alongside the gateway? [yes/no]: " choice </dev/tty
    case $choice in
    yes)
      USE_THUNDERHUB=true
      SERVICES="gatewayd lightningd thunderhub"
      break
      ;;
    no)
      USE_THUNDERHUB=false
      SERVICES="gatewayd gateway-ui"
      break
      ;;
    *)
      echo "Invalid option. Please choose yes or no."
      ;;
    esac
  done
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
  echo "Downloading $url in background..."
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

EXTERNAL_IP=$(curl -4 -sSL ifconfig.me)
REMOTE_USER=$(whoami)

if [[ $SETUP_TLS == true ]]; then
  if [[ $INSTALL_TYPE == "guardian" ]]; then
    echo "Do you want to setup an xmpp chat server on this instance? [yes/no]"
    while true; do
      read -r -n 1 -p "Your choice (yes/no): " choice </dev/tty
      echo
      case $choice in
      yes)
        SETUP_XMPP=true
        break
        ;;
      no)
        SETUP_XMPP=false
        # remove xmpp service from services list
        SERVICES=$(echo $SERVICES | sed -e 's/xmpp//g')
        # remove xmpp meta from fedimintd setup
        sed -i '/FM_EXTRA_DKG_META=chat_server_domain=xmpp.fedimint.my-super-host.com/d' $path
        # remove xmpp section from docker-compose.yaml
        sed -i '/### START_XMPP ###/,/### END_XMPP ###/d' $path
        # remove prosody volume from docker-compose.yaml
        sed -i '/prosody_datadir:/d' $path
        break
        ;;
      *)
        echo "Invalid option. Please type 'yes' or 'no'."
        ;;
      esac
    done
  fi
  # All the TLS setup steps go here
  echo
  echo "Fedimint ${INSTALL_TYPE} setup with TLS certificates by Let's Encrypt:"
  echo
  echo "Your ip is $EXTERNAL_IP. You __must__ open the port 443 on your firewall so we can setup the TLS certificates."
  echo "If you are unable to open this port, then the TLS setup and everything else will catastrophically or silently fail."
  echo "So in this case you can not use this script and you must setup the TLS certificates manually or use a script without TLS"
  read -p "Press enter to acknowledge this " -r -n 1 </dev/tty
  echo
  echo "Next step you will setup some DNS records pointing to this machine's ip ($EXTERNAL_IP), something like:"
  for service in $SERVICES; do
    echo "$service.fedimint.example.com"
  done

  echo
  while true; do
    read -p "What will be your host name suffix? (like fedimint.example.com in the above example): " -r -a host_name </dev/tty
    if [[ $(count_dots "${host_name[*]}") -eq 0 ]]; then
      echo "Error: invalid host name, it must be a subdomain, like fedimint.example.com"
    elif [[ $(count_dots "${host_name[*]}") -eq 1 ]]; then
      echo "We recommend having a subdomain for the services, like fedimint.example.com (instead of just example.com)"
      read -p "Are you sure you want to use ${host_name[*]}? [Y/n] " -n 1 -r -a use_host_name </dev/tty
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
  read -p "Press enter after you have created the above DNS records " -r -n 1 </dev/tty
  echo
  echo "DNS propagation may take a while and and caching may cause issues, so try to verify on another machine if the following is true:"
  echo "${host_name[*]} -> $EXTERNAL_IP"
  for service in $SERVICES; do
    echo "$service.${host_name[*]} -> $EXTERNAL_IP"
  done
  echo
  read -p "Press enter after you have verified them on another machine  " -r -n 1 </dev/tty
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
      read -p "Check again? [Y/n] " -n 1 -r -a check_again </dev/tty
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
        read -p "Continue without checking? [y/N] " -n 1 -r -a continue_without_checking </dev/tty
        echo
        if [[ ${continue_without_checking[*]} =~ ^[Yy]$ ]]; then
          echo "You have been warned, continuing..."
          break
        fi
      fi
    fi
  done
fi

download $DOCKER_COMPOSE_FILE ./docker-compose.yaml

rename_localhost() {
  local path=$1
  local ip=$2
  if [[ "$(uname)" == "Darwin" ]]; then # macOS uses BSD sed
    sed -i '' "s/127.0.0.1/$ip/g" "$path"
  else
    sed -i "s/127.0.0.1/$ip/g" "$path"
  fi
}

if [[ $SETUP_TLS == false ]]; then
  EXTERNAL_IP=$(curl -sSL ifconfig.me)
  read -p "Enter the external IP of your server [$EXTERNAL_IP]: " input_external_ip
  external_ip=${input_external_ip:-$EXTERNAL_IP}

  rename_localhost ./docker-compose.yaml "$external_ip"
fi

if [ "$IS_GATEWAY" = true ]; then
  # ask the user for the gateway password
  DEFAULT_GATEWAY_PASSWORD=thereisnosecondbest
  read -p "Set the password for the gateway [$DEFAULT_GATEWAY_PASSWORD]: " -a gateway_password </dev/tty
  if [[ -z ${gateway_password[*]} ]]; then
    gateway_password=$DEFAULT_GATEWAY_PASSWORD
  fi
  sed -i "s/$DEFAULT_GATEWAY_PASSWORD/$gateway_password/g" ./docker-compose.yaml

  if [ "$START_NEW_LND_NODE" = false ]; then
    # Remove the LND and Bitcoin sections from the docker-compose file
    sed -i '/### START_LND ###/,/### END_LND ###/d' ./docker-compose.yaml
    sed -i '/### START_BITCOIND ###/,/### END_BITCOIND ###/d' ./docker-compose.yaml
    # Remove the volume binding for lnd_datadir:/root/.lnd
    sed -i '/- lnd_datadir:\/root\/\.lnd/d' ./docker-compose.yaml
    # Remove the 'depends_on: - lnd' lines
    sed -i '/depends_on:/,+1d' ./docker-compose.yaml
    # Remove empty volume declarations for lnd_datadir and bitcoin_datadir
    sed -i '/lnd_datadir:/d' ./docker-compose.yaml
    sed -i '/bitcoin_datadir:/d' ./docker-compose.yaml

    # ask the user for their LND rpc
    DEFAULT_LND_RPC=lnd_gprc_url
    echo
    read -p "Enter the RPC for your LND node (ex. https://mynode.m.voltageapp.io:10009): " -a lnd_rpc </dev/tty
    if [[ -z ${lnd_rpc[*]} ]]; then
      echo 'Error: You must set an LND rpc if you configure the gateway with an existing LND node' >&2
      exit 1
    fi
    sed -i "s|$DEFAULT_LND_RPC|$lnd_rpc|g" ./docker-compose.yaml

    # confirm that the user put their LND files in the proper place
    echo
    echo
    echo "The gateway needs two files in order to connect to your LND node."
    echo "Please transfer these files to '~/.lnd':"
    echo "  - admin.macaroon"
    echo "  - tls.cert"
    echo

    # create ~/.lnd directory if it doesn't exist
    if [ ! -d "$HOME/.lnd" ]; then
      mkdir -p "$HOME/.lnd"
      echo "Directory has been created at: $HOME/.lnd"
    fi

    echo
    echo "You can transfer these files in with SCP:"
    echo "  scp admin.macaroon $REMOTE_USER@$EXTERNAL_IP:/home/$REMOTE_USER/.lnd/"
    echo "  scp tls.cert $REMOTE_USER@$EXTERNAL_IP:/home/$REMOTE_USER/.lnd/"
    echo
    read -p "Press enter after you have transferred the files " -r -n 1 </dev/tty
    echo

    while true; do
      echo "Checking files..."

      # check if the two files are present in the .lnd directory
      if [ -f "$HOME/.lnd/admin.macaroon" ] && [ -f "$HOME/.lnd/tls.cert" ]; then
        echo "All files look good..."
        break
      else
        echo "Some files do not look correct. Make sure you put them both in your .lnd directory."
        read -p "Press enter after you have transferred the files " -r -n 1 </dev/tty
        continue
      fi
    done
  fi
  if [ "$USE_THUNDERHUB" = false ]; then
    # Remove thunderhub from the docker-compose file
    sed -i '/### START_THUNDERHUB ###/,/### END_THUNDERHUB ###/d' ./docker-compose.yaml

    # Remove thunderhub data directory 'thunderhub_datadir:' from the docker-compose file
    sed -i '/thunderhub_datadir:/d' ./docker-compose.yaml
  fi
else # Is Guardian
  if [ "$USE_ESPLORA" = true ]; then
    case $NETWORK_TYPE in
    mainnet)
      DEFAULT_ESPLORA_URL="https://blockstream.info/api"
      ;;
    testnet)
      DEFAULT_ESPLORA_URL="https://blockstream.info/testnet/api"
      ;;
    signet)
      DEFAULT_ESPLORA_URL="https://blockstream.info/signet/api"
      ;;
    mutinynet)
      DEFAULT_ESPLORA_URL="https://mutinynet.com/api"
      ;;
    *)
      echo "Error: Unknown network type for Esplora URL."
      exit 1
      ;;
    esac

    read -p "Enter the Esplora URL you'd like to use to get $NETWORK_TYPE blockdata from, or click enter to use the network default: [$DEFAULT_ESPLORA_URL]: " ESPLORA_URL </dev/tty
    ESPLORA_URL=${ESPLORA_URL:-$DEFAULT_ESPLORA_URL}
    echo "Using Esplora URL: $ESPLORA_URL"

    # Set the esplora URL in the docker-compose file
    sed -i "s|FM_BITCOIN_RPC_URL=|FM_BITCOIN_RPC_URL=$ESPLORA_URL|" ./docker-compose.yaml

    # Set the bitcoin network in the docker-compose file (mainnet is bitcoin for network)
    case $NETWORK_TYPE in
    mutinynet)
      sed -i "s|FM_BITCOIN_NETWORK=signet|FM_BITCOIN_NETWORK=signet|" ./docker-compose.yaml
      ;;
    mainnet)
      sed -i "s|FM_BITCOIN_NETWORK=signet|FM_BITCOIN_NETWORK=bitcoin|" ./docker-compose.yaml
      ;;
    esac

    # Remove the bitcoind service from the docker-compose file
    sed -i '/### START_BITCOIND ###/,/### END_BITCOIND ###/d' ./docker-compose.yaml

  else # Using Bitcoin Node for Guardian blockchain data
    echo
    echo "Do you want to start a new Bitcoin node or use an existing one? [new/existing]"
    while true; do
      read -p "Type 'new' to start a new node or 'existing' to use an existing node: " node_choice </dev/tty
      case $node_choice in
      new)
        break
        ;;
      existing)
        break
        ;;
      *)
        echo "Invalid option. Please type 'new' or 'existing'."
        ;;
      esac
    done

    if [[ $node_choice == "new" ]]; then
      echo "You will need to provide the Bitcoin Node RPC URL to get blockchain data."
      echo "A new bitcoin node will be started as part of your docker compose setup."
    elif [[ $node_choice == "existing" ]]; then
      read -p "Enter the RPC URL for your existing Bitcoin node (ex. https://mynode.m.voltageapp.io:8332): " -a bitcoin_rpc_url </dev/tty
      if [[ -z ${bitcoin_rpc_url[*]} ]]; then
        echo 'Error: You must set a Bitcoin RPC URL if you configure the guardian with an existing Bitcoin node' >&2
        exit 1
      fi
      echo "Using Bitcoin RPC URL: $bitcoin_rpc_url"
      # Set the bitcoin RPC URL in the docker-compose file
      sed -i "s|FM_BITCOIN_RPC_URL=|FM_BITCOIN_RPC_URL=$bitcoin_rpc_url|" ./docker-compose.yaml
      # Remove the bitcoind service from the docker-compose file
      sed -i '/### START_BITCOIND ###/,/### END_BITCOIND ###/d' ./docker-compose.yaml
      # Remove the volume binding for bitcoin_datadir:/root/.bitcoin
      sed -i '/bitcoin_datadir:/d' ./docker-compose.yaml
    else
      echo "Invalid option. Please type 'new' or 'existing'."
    fi
  fi
fi

echo
echo "Running '$DOCKER_COMPOSE up -d' to start the services"
$DOCKER_COMPOSE up -d

echo -n "Waiting for fedimintd to be ready. Don't do anything yet..."

sleep 5

wait_fedimintd_ready() {
  flags=$1
  while true; do
    status=$(curl $flags -s -q -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0", "method": "status", "params": [{"params":null}],"id":1}' "https://fedimintd.${host_name[*]}" | jq -r .result.server)
    if [[ $status == "awaiting_password" ]]; then
      echo
      break
    else
      echo -n "."
      sleep 1
    fi
  done
}

echo
echo "Optionally run '$DOCKER_COMPOSE logs -f' to see the logs."
if [[ $SETUP_TLS == true ]]; then
  wait_fedimintd_ready --insecure

  echo "Looks good. Now will check if certificate is okay."
  echo "You may take a look at '$DOCKER_COMPOSE logs -f traefik' if this takes too long."
  echo "But before doing that, please wait at least 5 minutes, as it may take a while to get the certificate. Be patient."
  echo -n "Checking, please wait..."

  wait_fedimintd_ready

  echo "Good!"
  echo "You can access the services at:"
  if [ "$IS_GATEWAY" = true ]; then
    echo "Gateway-UI: https://gateway-ui.${host_name[*]}"
    if [ "$USE_THUNDERHUB" = true ]; then
      echo "Thunderhub: https://thunderhub.${host_name[*]}"
    fi
  else
    echo "Guardian-UI: https://guardian-ui.${host_name[*]}"
    if [ "$SETUP_XMPP" = true ]; then
      echo "XMPP Prosody Server: https://xmpp.${host_name[*]}"
    fi
  fi
  echo "Note: by default, you should open ports 8173 and 9735 for external access on your router/firewall, plus 443 as mentioned before."
else
  if [ "$IS_GATEWAY" = true ]; then
    echo "Gateway-UI: http://${EXTERNAL_IP}:3001"
    if [ "$USE_THUNDERHUB" = true ]; then
      echo "Thunderhub: http://${EXTERNAL_IP}:3002"
    fi
  else
    echo "Guardian-UI: http://${EXTERNAL_IP}:3000"
  fi
fi
