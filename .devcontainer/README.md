# Development Container

This directory contains all files which pertain to this project's development container. The development container has been tested with [VSCode](https://code.visualstudio.com).

To use the development container environment simply open the project's top level directory with VSCode. Consider also [these](https://code.visualstudio.com/docs/remote/containers#_installation) instructions. This environment should work for MacOS, Windows, and Linux host systems.

## Build Docker Image

Building the docker image is usually unnecessary for most developers. Instead, VSCode will automatically retrieve an existing docker image from Docker Hub based on the `image` field in `.devcontainer/devcontainer.json`.

The build process can take ~40mins or more. The development container's base docker image can be built by executing this command in the project's root directory:

```bash
docker build -t fedimint-dev -f .devcontainer/Dockerfile .
```
