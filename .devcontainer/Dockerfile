# This file defines a development environment container image for this project.
#
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y curl xz-utils git sudo bash nano && \
    git config --global --add safe.directory /workspaces/* && \
    # Setup a non-root user (username: nonroot) to install nix.
    useradd -m nonroot && mkhomedir_helper nonroot && usermod -s /bin/bash nonroot && \
    mkdir -m 0755 /nix && chown -R nonroot /nix && chmod u+wxr ./nix

# Install nix using nonroot user. This user can be added to sudo group later.
USER nonroot
ENV USER=nonroot
RUN curl -L https://nixos.org/nix/install > ~/nix_install.sh && \
    chmod u+x ~/nix_install.sh && \
    ~/nix_install.sh --no-daemon && \
    rm ~/nix_install.sh && \
    . /home/nonroot/.nix-profile/etc/profile.d/nix.sh && \
    nix-channel --update
# Add global nix config file.
USER root
RUN mkdir -p /etc/nix && echo "sandbox = false" >> /etc/nix/nix.conf

# Use nix to build project dependencies.
USER nonroot
ADD --chown=nonroot:nonroot . /home/nonroot/tmp_src
RUN . /home/nonroot/.nix-profile/etc/profile.d/nix.sh && \
    (cd /home/nonroot/tmp_src && nix develop --extra-experimental-features nix-command --extra-experimental-features flakes)
# Setup bashrc with nix develop trigger.
RUN cat /home/nonroot/tmp_src/.devcontainer/bashrc >> /home/nonroot/.bashrc
RUN rm -rf /home/nonroot/tmp_src

# Give sudo permissions to nonroot user.
USER root
ENV USER=root
RUN echo "nonroot ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/nonroot