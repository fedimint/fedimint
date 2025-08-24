# Docker support

Our CI [automatically](https://github.com/fedimint/fedimint/blob/67760e2f21d2fa628ec9cd549b4bfb65571e4511/.github/workflows/ci-nix.yml#L375C3-L375C13)
publishes [docker container images of all fedimintd components](https://hub.docker.com/u/fedimint).

Stable Docker deployment scripts live in the release branches. For example, refer to [`releases/v0.7`](https://github.com/fedimint/fedimint/tree/releases/v0.7/docker/deploy-fedimintd) for the latest `v0.7.*` release.

In the past we had more elaborated tutorial and documentation, but we had to scale
it down, due to amount of time required to keep them up to date. See content
of this directory in the past releases for more info.

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or `#mint-ops` channel on [Fedimint's Discord server](https://chat.fedimint.org/).

## System Requirements
### 3-of-4 Federation with remote Bitcoin backend
* Memory: 1GB minimum, 2GB recommended
* Disk: 10GB minimum
* CPU: 1 core minimum, 2 cores recommended

Notably, we did successfully test a 3-of-4 federation with one guardian on a Raspberry Pi Zero 2 W **with only 500MB of
memory and 500MB of swap space**, which is likely the lowest power device one can run Fedimint on, but it's not
advisable for production deployments.

### 3-of-4 Federation with local Bitcoin backend
* Memory: 2GB minimum, 4GB recommended
* Disk: 1TB recommended (50GB if running pruned, but there be dragons)
* CPU: 2 cores minimum, 4 cores recommended

Worst-case memory consumption scales with the number of guardians (about 250MB per guardian), while this is only a
worst-case number for adversarial scenarios, please keep it in mind for larger federations (5-of-7, 7-of-10, …).

## Setup

To deploy a federation using Docker Compose:

```bash
docker compose up -d
```

Then, access the web UI at [http://localhost:8175](http://localhost:8175).

If Docker runs on a remote machine, forward the port locally with:

```bash
ssh -NL 8175:127.0.0.1:8175 <your_server>
```
