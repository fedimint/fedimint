FROM debian:buster-slim as builder

ARG BITCOIN_VERSION="d8434da3c14e"
ARG TRIPLET=${TRIPLET:-"x86_64-linux-gnu"}

RUN apt-get update && \
    apt-get install -qq --no-install-recommends ca-certificates dirmngr gosu wget libc6 procps python3
WORKDIR /tmp

# install bitcoin binaries
RUN BITCOIN_URL="https://github.com/benthecarman/bitcoin/releases/download/custom-signet-blocktime/bitcoin-${BITCOIN_VERSION}-${TRIPLET}.tar.gz" && \
    BITCOIN_FILE="bitcoin-${BITCOIN_VERSION}-${TRIPLET}.tar.gz" && \
    wget -qO "${BITCOIN_FILE}" "${BITCOIN_URL}" && \
    mkdir -p bin && \
    tar -xzvf "${BITCOIN_FILE}" -C /tmp/bin --strip-components=2 "bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli" "bitcoin-${BITCOIN_VERSION}/bin/bitcoind" "bitcoin-${BITCOIN_VERSION}/bin/bitcoin-wallet" "bitcoin-${BITCOIN_VERSION}/bin/bitcoin-util"
# TODO: move this download to runtime so we can update it without rebuilding the image
RUN mkdir -p /tmp/.bitcoin/signet && wget https://fedi-public-snapshots.s3.amazonaws.com/bitcoind-mutinynet-signet.tar -O - | tar -C /tmp/.bitcoin/signet -xvf -

FROM debian:buster-slim as custom-signet-bitcoin

ENV BITCOIN_DIR /root/.bitcoin
COPY --from=builder "/tmp/bin" /usr/local/bin
COPY --from=builder "/tmp/.bitcoin" $BITCOIN_DIR

VOLUME $BITCOIN_DIR
EXPOSE 28332 28333 28334 38332 38333 38334
ENTRYPOINT ["bitcoind", "-rpcbind=::", "-rpcbind=0.0.0.0", "-fallbackfee=0.00008", "-signet=1", "-txindex", "-signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae", "-addnode=mutinynet-upstream.dev.fedibtc.com:38333", "-addnode=public.mutinynet-bitcoind-01.dev.fedibtc.com:38333", "-dnsseed=0", "-signetblocktime=30", "-rpcallowip=0.0.0.0/0" ]
