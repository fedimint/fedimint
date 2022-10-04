# User Interface

Fedimint has a very basic user interface that currently only implements setting up a federation using a trusted dealer.

To run this on a single host, run `./scripts/run-ui.sh` and visit ports 10000-10003 in your browser to setup a federation.

To run in docker, try the following command. For this to work you'll need a Bitcoin node running somewhere with an accessible RPC port. Lookup latest `<tag>` [here](https://hub.docker.com/repository/docker/fedimint/fedimintd/tags?page=1&ordering=last_updated).

```
docker run -p 17440:17440 -p 17340:17340 -p 17240:17240 -v $PWD/demo:/var/fedimint fedimint/fedimintd:<tag> fedimintd /var/fedimint/mint.json /var/fedimint/mint.db 17440
```

Once the federation has been set up, you can also use the docker to interact with it. Lookup latest `<tag>` [here](https://hub.docker.com/repository/docker/fedimint/fedimint-cli).

```
docker run -v $PWD/demo:/var/fedimint fedimint/fedimint-cli:<tag> fedimint-cli /var/fedimint join-federation <connection-string>
```
