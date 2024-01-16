# Based on https://github.com/prosody/prosody-docker

FROM debian:12-slim

# Install dependencies
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        lsb-base \
        procps \
        adduser \
        lua-bitop \
        lua-dbi-mysql \
        lua-dbi-postgresql \
        lua-dbi-sqlite3 \
        lua-event \
        lua-expat \
        lua-filesystem \
        lua-sec \
        lua-socket \
        lua-unbound \
        lua-zlib \
        lua5.1 \
        lua5.2 \
        openssl \
        ca-certificates \
        ssl-cert \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && wget https://prosody.im/files/prosody.sources -O /etc/apt/sources.list.d/prosody.sources \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y prosody

RUN mkdir -p /var/run/prosody && chown prosody:prosody /var/run/prosody

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 80 443 5222 5269 5347 5280 5281
ENV __FLUSH_LOG yes
CMD ["prosody", "-F"]
