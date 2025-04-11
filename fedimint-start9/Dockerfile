FROM fedimint/fedimintd:v0.7.0

ADD ./docker_entrypoint.sh /docker_entrypoint.sh
ADD ./check-web.sh /usr/local/bin/check-web.sh
RUN chmod +x /docker_entrypoint.sh /usr/local/bin/check-web.sh

VOLUME ["/fedimintd", "/start-os"]
EXPOSE 8175/tcp

ENTRYPOINT ["/docker_entrypoint.sh"]
