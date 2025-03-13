#!/usr/bin/env bash

FM_API_PORT=8174
docker_fm_cli='docker-compose exec -T fedimint-cli fedimint-cli --password dummy'

source ./iroh-peer-ips.env

peers=(
  "$peer_0_ip"
  "$peer_1_ip"
  "$peer_2_ip"
  "$peer_3_ip"
)

for i in "${!peers[@]}"; do
  peer_label="peer_${i}"
  echo "Deploying ${peer_label}: ${peers[$i]}"

  FM_DOCKER_COMPOSE_DEPLOY_WIPE=1 FM_DOCKER_COMPOSE_DEPLOY=1 just deploy-docker-demo "${peers[$i]}"
done

run_with_retry() {
  local command="$1"
  local expected="$2"
  local label="$3"
  local max_retries=20
  local retry=0
  local output=""

  while [ $retry -lt $max_retries ]; do
    output=$(eval "$command")
    if [[ "$expected" == "null" ]]; then
      if [ -z "$output" ]; then
        echo "$output"
        return 0
      fi
    fi
    if [[ "$output" == *"$expected"* ]]; then
      echo "$output"
      return 0
    fi

    echo "${label}: Attempt $((retry+1)) failed, output: $output. Retrying in 10 seconds..."
    sleep 10
    retry=$((retry+1))
  done

  echo "${label}: Max retries reached. Last output: $output"
  echo "$output"
  return 1
}

build_local_params_cmd() {
  local peer="$1"
  local index="$2"
  if [ "$index" -eq 0 ]; then
  echo "ssh -q root@${peer} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} set-local-params --federation-name test $index
EOF
"
  else
  echo "ssh -q root@${peer} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} set-local-params $index
EOF
"
  fi
}

local_params_outputs=()

for i in "${!peers[@]}"; do
  peer_label="peer_${i}"

  echo "Processing ${peer_label}: ${peers[$i]}"
  status_cmd="ssh -q root@${peers[$i]} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} server-status
EOF
"

  status_result=$(run_with_retry "$status_cmd" "AwaitingLocalParams" "$peer_label")
  echo "${peer_label}: Final status output: $status_result"
done

for i in "${!peers[@]}"; do
  peer_label="peer_${i}"

  local_params_cmd=$(build_local_params_cmd "${peers[$i]}" "$i")
  echo "${peer_label}: Executing local params command: $local_params_cmd"

  start_dkg_result=$(run_with_retry "$local_params_cmd" "fedimint" "$peer_label")
  echo "${peer_label}: Local params output: $start_dkg_result"
  
  local_params_outputs[$i]="$start_dkg_result"
done

echo "Saved set-local-params outputs:"
for i in "${!local_params_outputs[@]}"; do
  echo "peer_${i}: ${local_params_outputs[$i]}"
done

for i in "${!local_params_outputs[@]}"; do
  source_peer_label="peer_${i}"
  source_info="${local_params_outputs[$i]}"
    
  for j in "${!peers[@]}"; do
    if [ "$i" -ne "$j" ]; then
      target_peer_label="peer_${j}"
      target_endpoint="${peers[$j]}"
            
      add_peer_cmd="ssh -q root@${target_endpoint} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} add-peer-connection-info ${source_info}
EOF
"
            
      echo "${target_peer_label}: Adding connection info from ${source_peer_label}..."
      add_result=$(run_with_retry "$add_peer_cmd" "$i" "${target_peer_label}")
      echo "${target_peer_label}: add-peer-connection-info output: ${add_result}"
    fi
  done
done


for i in "${!peers[@]}"; do
  peer_label="peer_${i}"

  start_dkg_cmd="ssh -q root@${peers[$i]} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} start-dkg
EOF
"
  echo "${peer_label}: Executing start dkg command: $start_dkg_cmd"

  start_dkg_result=$(run_with_retry "$start_dkg_cmd" "null" "$peer_label")
  echo "${peer_label}: start dkg output: $start_dkg_result"
done

for i in "${!peers[@]}"; do
  peer_label="peer_${i}"

  status_cmd="ssh -q root@${peers[$i]} << EOF
cd /root/fedimint-docker
$docker_fm_cli admin config-gen --ws ws://fedimintd:${FM_API_PORT} server-status
EOF
"
  echo "${peer_label}: Executing status command: $status_cmd"

  status_result=$(run_with_retry "$status_cmd" "ConsensusRunning" "$peer_label")
  echo "${peer_label}: status output: $status_result"
done
