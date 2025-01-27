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
