(import
  (
    let lock = builtins.fromJSON (builtins.readFile ./flake.lock); in
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
      sha256 = lock.nodes.flake-compat.locked.narHash;
    }
  )
  { src = ./.; }
  # Since a lot of existing CI tests is based on `shell.nix`
  # we forward to the integrationTests shell, instead of the
  # default (developer) shell.
).shellNix.devShells.x86_64-linux.integrationTests
