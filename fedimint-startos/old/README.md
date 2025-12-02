<p align="center">
  <img src="icon.png" alt="Project Logo" width="21%">
</p>

# Fedimint for StartOS

This project packages Fedimint for StartOS.

## Dependencies

These steps were run on Ubuntu 24.04.

Install the system dependencies below to build this project by following the instructions in the provided links. You can find instructions on how to set up the appropriate build environment in the [Developer Docs](https://docs.start9.com/latest/developer-docs/packaging).

- [docker](https://docs.docker.com/get-docker)
- [docker-buildx](https://docs.docker.com/buildx/working-with-buildx/)
- [yq](https://mikefarah.gitbook.io/yq)
- [deno](https://deno.land/)
- [make](https://www.gnu.org/software/make/)
- [start-sdk](https://github.com/Start9Labs/start-os/tree/sdk/)

## Build environment
Prepare your StartOS build environment.
1. Install docker
```
curl -fsSL https://get.docker.com | bash
sudo usermod -aG docker "$USER"
exec sudo su -l $USER
```
2. Set buildx as the default builder
```
docker buildx install
docker buildx create --use
```
3. Enable cross-arch emulated builds in docker
```
docker run --privileged --rm linuxkit/binfmt:v0.8
```
4. Install yq
```
sudo snap install yq
```
5. Install deno
```
sudo snap install deno
```
6. Install essentials build packages
```
sudo apt-get install -y build-essential openssl libssl-dev libc6-dev clang libclang-dev ca-certificates
```
7. Install Rust
```
curl https://sh.rustup.rs -sSf | sh
# Choose nr 1 (default install)
source $HOME/.cargo/env
```
8. Build and install start-sdk
```
git clone https://github.com/Start9Labs/start-os.git && \
 cd start-os && git submodule update --init --recursive && \
 make sdk
```
Initialize sdk & verify install
```
start-sdk init
start-sdk --version
```
Now you are ready to build the `fedimintd` package!

## Cloning

Clone the project locally:

```
git clone https://github.com/fedimint/fedimint.git
cd fedimint/fedimint-start9
git submodule update --init --recursive
```

## Building

To build the `fedimintd` package for all platforms using start-sdk, run the following command:

```
make
```

To build the `fedimintd` package for a single platform using start-sdk, run:

```
# for amd64
make x86
```
or
```
# for arm64
make arm
```

## Installing (on StartOS)

Run the following commands to determine successful install:
> :information_source: Change server-name.local to your Start9 server address

```
start-cli auth login
# Enter your StartOS password
start-cli --host https://server-name.local package install fedimintd.s9pk
```

If you already have your `start-cli` config file setup with a default `host`, you can install simply by running:

```
make install
```

> **Tip:** You can also install the fedimintd.s9pk using **Sideload Service** under the **System > Manage** section.

### Verify Install

Go to your StartOS Services page, select **Fedimint**, and start the service. Then, verify the web interface is accessible.

**Done!**
