# Understanding Fedimint's Nix-based building system and CI

## Nix

The building system is implemented in [Nix](https://nixos.org/). If you want to know more about Nix I highly recommend going through [Nix Pills](https://nixos.org/guides/nix-pills/why-you-should-give-it-a-try.html#idm140737320788880).

For brevity it's important to understand that:

* Nix is purely functional. Everything is described as an expression/function, taking some inputs and producing deterministic outputs. This guarantees reproducible results and makes caching everything easy.
* Nix expressions are lazy. Anything described in Nix code will only be executed if some other expression needs its results. This is very powerful but somewhat unnatural for developers not familiar with functional programming.

## Flakes

Flakes are a recent Nix feature and a whole new way of working with Nix. A good way to think about Flakes is "Cargo.toml, but for everything". A Flake describes its inputs (Nix derivations which can be any file system artifacts that Nix can build like programs, and libraries) and produces outputs (also Nix derivations). All inputs are "locked" in `flake.lock` file in the same way that `Cargo.lock` "lock" Rust projects dependencies. 

`nix flake update` and `nix flake lock --update-input <input-name>` are Nix's versions of `cargo update` and `cargo update -p <package-name>`.

## Nix dev shells

`nix develop` can be used to start a Nix dev shell. Dev shells provide developers with strictly defined reproducible environments. [Default fedimint's dev shell](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L402) provides the toolchain and all the tools as used for building Fedimint in the CI. 

## Fenix

[fenix](https://github.com/nix-community/fenix) is a Nix flake providing Rust toolchains in all profiles (stable, beta, nightly), shapes, and colors.

[`fenix` is an input of Fedimint's flake](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L7) to [provide the known to work Rust toolchain](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L33).


## Crane

[crane](https://github.com/ipetkov/crane) is a Nix flake providing a Nix library and tools for composing flexible and efficient Nix expressions building Rust projects.

The core mechanism that `crane` uses is storing `./target` directory created by `cargo` commands as a build output and restoring it when used as an input to other Nix expressions utilizing `cargo`.

### Build external dependencies package

The lowest level phase of Fedimint's build system is the [`workspaceDeps`](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L154) Nix package.

The way it works is that it collects all the `Cargo.toml` and `Cargo.lock` files, ignores the real source code, and uses dummy stubs instead. This way it can build a Nix package containing `./target` directory with only the external dependencies built. This package will be stored in the local Nix store and potentially in the remote `cachix` cache. Since dependencies of the Rust project change rarely, all the following build phases and future builds (both local and in the CI) can reuse it.

It's possible to trigger the build of this package directly as it's exposed as [`deps` output package of the flake](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L372):

```
> nix build -L .#deps
[...]
workspace-deps-deps>     Finished release [optimized] target(s) in 1m 38s
workspace-deps-deps> buildPhase completed in 8 minutes 53 seconds
workspace-deps-deps> installing
workspace-deps-deps> copying target to /nix/store/38ilsgr5ivshjr5zkpr4fax8l67sb6zn-workspace-deps-deps-0.0.1/target.tar.zst
workspace-deps-deps> /*stdin*\            : 21.86%   (  4.18 GiB =>    936 MiB, /nix/store/38ilsgr5ivshjr5zkpr4fax8l67sb6zn-workspace-deps-deps-0.0.1/target.tar.zst)
workspace-deps-deps> post-installation fixup
workspace-deps-deps> shrinking RPATHs of ELF executables and libraries in /nix/store/38ilsgr5ivshjr5zkpr4fax8l67sb6zn-workspace-deps-deps-0.0.1
workspace-deps-deps> strip is /nix/store/ag2bpk0lzjvj409znklrz5krkpc5imzs-gcc-wrapper-11.3.0/bin/strip
workspace-deps-deps> patching script interpreter paths in /nix/store/38ilsgr5ivshjr5zkpr4fax8l67sb6zn-workspace-deps-deps-0.0.1
workspace-deps-deps> checking for references to /build/ in /nix/store/38ilsgr5ivshjr5zkpr4fax8l67sb6zn-workspace-deps-deps-0.0.1...

> ls -alh result/
total 936M
dr-xr-xr-x 1 root root     28 Dec 31  1969 .
drwxrwxr-t 1 root nixbld 4.8M Aug 31 00:53 ..
-r--r--r-- 1 root root   936M Dec 31  1969 target.tar.zst
```

As you see the result of building this package is a compressed `./target` directory.

It's quite large because it contains the result of all 3: `cargo build`, `cargo check`, and `cargo doc` for all the dependencies.

### Build workspace package

[`workspaceBuild`](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L192) is the next major build phase. As the name suggests - it build the whole cargo workspace. `cargoArtifacts = workspaceDeps;` annotation makes the `crane` use the (now cached) result of `workspaceDeps` and extract it into `./target` directory before running any `cargo` commands.

`doCheck = false;` makes Nix skip running any unit tests which is the default behavior for Nix packages. This `cargo test` step is extracted into a separate Nix package: [`workspaceTest`](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L198)


### Cli Tests

Fedimint's features a set of integration tests, which are expressed as separate Nix packages in the `flake.nix`, [like `cliTestCli`](https://github.com/fedimint/fedimint/blob/2a02caab33e97895ccffc24cd2b7eb445f1daa5f/flake.nix#L223). `cargoBuildCommand = "patchShebangs ./scripts && ./scripts/cli-test.sh";` is used to make `crane` run an arbitrary command (in this case: a script executing the test), instead of the default `cargo build`.

A notable feature of expressing tests as Nix packages is that once a given test ran successfully Nix will store the package in the Nix store and know that there is no point to re-run the tests unless any relevant input file changes.

### Other Nix packages

There are other Nix packages defined, but they are similar to the ones described above and follow the template of:

* (optionally) take the existing `./target` output from another phase (passed as `cargoArtifacts` value)
* run some commands (arbitrary, but usually just `cargo xyz`)
* (optionally) store the `./target` directly in the output of the Nix package


### Source file filtering

Nix packages being built take the `src` argument pointing to the source code of the package. If the value of `src` is a local *path* all the files inside it will be used as a build input. Unfortunately, since Nix does not understand `cargo` build system's inner workings, it assumes that if any input file changes, the result of the whole package built process will change and rebuilds the package from scratch.

To prevent changes in unrelated files causing rebuilds, some [filtering of `src` file is implemented using `lib.cleanSourceWith`](https://github.com/fedimint/fedimint/blob/dabd9e46a7049f725b2c26126db01c8e250e54c9/flake.nix#L103).

Without getting into exact details, the whole thing is a combination of:

* leaving all `Cargo.{toml,lock}` files unfiltered, so `cargo` can analyze the whole workspace,
* using some regexes to match the files that are needed, like `.*\.rs` (note it's a regex and not a glob).

It's also important to notice that `cargo` auto-detects binaries and libraries based on the existence of files like `./src/lib.rs`, `./src/main.rs`. It however can't do that if these files were filtered out. To allow seamless filtering out of unnecessary files all `[[bin]]`, `[lib]`, and similar in `Cargo.toml` files need to be populated explicitly.

Some of the filtering functionality implemented for the project from scratch will likely become a built-in part of the `crane`. 
