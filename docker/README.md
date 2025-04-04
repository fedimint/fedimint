# Docker support

Our CI
[automatically](https://github.com/fedimint/fedimint/blob/67760e2f21d2fa628ec9cd549b4bfb65571e4511/.github/workflows/ci-
nix.yml#L375C3-L375C13) publishes [docker container images of all fedimintd
components](https://hub.docker.com/u/fedimint).

See [./deploy-fedimintd] for a script deploying `fedimintd` to a fresh system.
It is reguarily tried, so should stay working.

In the past we had more elaborated tutorial and documentation, but we had to scale
it down, due to amount of time required to keep them up to date. See content
of this directory in the past releases for more info.

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or `#mint-ops` channel on [Fedimint's Discord server](https://chat.fedimint.org/).

## Iroh (Experimental)

To try the experimental Iroh integration, use the provided Docker Compose setup:

```bash
cd iroh-fedimintd
docker compose up -d
```

Then, access the web UI at [http://localhost:8175](http://localhost:8175).

If Docker runs on a remote machine, forward the port locally with:

```bash
ssh -NL 8175:127.0.0.1:8175 <your_server>
```
