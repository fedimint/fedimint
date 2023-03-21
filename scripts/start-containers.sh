#!/usr/bin/env bash

BUILD_IMAGES=${1:-0}
FM_FED_SIZE=${2:-2}
export DOCKER_DIR=${3-"$(mktemp -d)"}
BASE_PORT=8173

function generate_certs() {
    echo "Generating certificates..."

    CERTS=""
    for ((ID=0; ID<FM_FED_SIZE; ID++));
    do
        mkdir -p $1/server-$ID
        fed_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
        api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
        export FM_PASSWORD="pass$ID"
        docker run -v $1/server-$ID:/var/fedimint -e FM_PASSWORD=pass$ID $2 distributedgen create-cert --p2p-url ws://server-$ID:$fed_port --api-url ws://server-$ID:$api_port --out-dir /var/fedimint --name "Server-$ID"
        CERTS="$CERTS,$(cat $1/server-$ID/tls-cert)"
    done
    export CERTS=${CERTS:1}
}

function run_dkg() {
    echo "version: \"3.9\"" >> $3
    echo "services:" >> $3

    for ((ID=0; ID<FM_FED_SIZE; ID++));
    do
        fed_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
        api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
        echo "  server-$ID:" >> $3
        echo "    image: $2" >> $3
        echo "    command: distributedgen run --bind-p2p 0.0.0.0:$fed_port --bind-api 0.0.0.0:$api_port --out-dir /var/fedimint --certs $CERTS" >> $3
        echo "    ports:" >> $3
        echo "      - $fed_port:$fed_port" >> $3
        echo "      - $api_port:$api_port" >> $3
        echo "    volumes:" >> $3
        echo "      - $1/server-$ID:/var/fedimint" >> $3
        echo "    environment:" >> $3
        echo "      - CERTS=$CERTS" >> $3
        echo "      - FM_PASSWORD=pass$ID" >> $3
        echo "" >> $3
    done

    echo "Running DKG with certs: $CERTS"
    docker-compose -f $3 up -d
    wait_for_dkg
}

function wait_for_dkg() {
    while [ "$(docker ps | grep fedimint | wc -l)" -ne 0 ]
    do
        sleep 1
    done
}

function generate_docker_compose() {
    echo "Generating docker-compose..."

    echo "version: \"3.9\"" >> $3
    echo "services:" >> $3

    generate_bitcoind_container_def $3

    for ((ID=0; ID<FM_FED_SIZE; ID++)); do
        base_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
        api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
        generate_fedimintd_container_def $ID $base_port $api_port $1 $2 $3
    done
}

function generate_bitcoind_container_def() {
    echo "  bitcoind:" >> $1
    echo "    image: ruimarinho/bitcoin-core:23.0" >> $1
    echo "    environment:" >> $1
    echo "      - BITCOIN_DATA=/var/fedimint/bitcoind" >> $1
    echo "    command: bitcoind -printtoconsole -regtest=1 -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 -rpcport=18443 -rpcuser=bitcoin -rpcpassword=bitcoin" >> $1
    echo "    ports:" >> $1
    echo "      - 18443:18443" >> $1
}

function generate_fedimintd_container_def() {
    echo "  server-$1:" >> $6
    echo "    image: $5" >> $6
    echo "    command: fedimintd /var/fedimint" >> $6
    echo "    ports:" >> $6
    echo "      - $2:$2" >> $6
    echo "      - $3:$3" >> $6
    echo "    volumes:" >> $6
    echo "      - $4/server-$1:/var/fedimint" >> $6
    echo "    environment:" >> $6
    echo "      - FM_PASSWORD=pass$1" >> $6
    echo "" >> $6
}

echo "Run with 'source ./scripts/start-containers.sh [build-images] [fed_size] [dir]"
rm -rf $DOCKER_DIR
init="$DOCKER_DIR/init"
mkdir -p $init
fed="$DOCKER_DIR/fed"
mkdir -p $fed

if [[ "$BUILD_IMAGES" != "0" ]]; then
    echo "Building the containers..."
    container=$(nix build .\#container.fedimintd && docker load < ./result)
    container_image=$(echo "${container/Loaded image: /}")
else
    echo "Pulling containers from dockerhub"
    container_image="fedimint/fedimintd:master"
fi

echo "Generating certificates..."
generate_certs $DOCKER_DIR $container_image

echo "Running DKG"
run_dkg $DOCKER_DIR $container_image "$init/docker-compose.yaml"

generate_docker_compose $DOCKER_DIR $container_image "$fed/docker-compose.yaml"
cat "$fed/docker-compose.yaml"
docker-compose -f "$fed/docker-compose.yaml" up -d
export DOCKER_COMPOSE="$DOCKER_DIR/fed/docker-compose.yaml"
echo "Stop federation with 'docker-compose -f $DOCKER_COMPOSE stop'"
