# Stage 1: Download yq in a full-featured image
FROM alpine:latest AS downloader
ARG TARGETARCH
ARG YQ_VERSION=v4.47.1
RUN case "$TARGETARCH" in \
        amd64) YQ_ARCH="amd64" ;; \
        arm64) YQ_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    wget -O /tmp/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${YQ_ARCH}" && \
    chmod +x /tmp/yq

# Stage 2: Main image
FROM fedimint/fedimintd:v0.9.1

# Copy yq from downloader stage
COPY --from=downloader /tmp/yq /usr/local/bin/yq

ADD ./docker_entrypoint.sh /docker_entrypoint.sh
ADD ./check-web.sh /usr/local/bin/check-web.sh
RUN chmod +x /docker_entrypoint.sh /usr/local/bin/check-web.sh

VOLUME ["/fedimintd", "/start-os"]
EXPOSE 8175/tcp

ENTRYPOINT ["/docker_entrypoint.sh"]
