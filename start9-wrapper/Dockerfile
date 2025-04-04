FROM fedimint/fedimintd:da61291173e71a11358e1cd4154e649cf413d9e9

ADD ./docker_entrypoint.sh /docker_entrypoint.sh
ADD ./check-web.sh /usr/local/bin/check-web.sh
RUN chmod +x /docker_entrypoint.sh /usr/local/bin/check-web.sh

VOLUME ["/fedimintd", "/start-os"]
EXPOSE 8173/tcp 8174/udp 8175/tcp

ENTRYPOINT ["/docker_entrypoint.sh"]

