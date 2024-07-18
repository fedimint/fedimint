# Release Process

WIP

Capturing steps while working through v0.3.3 and v0.4.0 release processes. I'll clean up this doc before moving the PR out of draft.

## Steps

- `releases/v*` (e.g. `releases/v0.3`) contains commits ready for a release
  - if there's a new major version, e.g. 0.4.0, but there isn't a `releases/v0.4` branch, create one branching from `master`
- bump the cargo version to a new release candidate

Ex:

reference https://github.com/fedimint/fedimint/pull/5647
latest cargo version is v0.3.2
to bump to v0.3.3-rc.0, run

```
cargo workspaces version --all --exact --no-git-commit --yes --force '*' --pre-id rc prerelease
```

This is also defined as a just command, so alternatively run
```
just release-bump-version
```

if you instead are ready to cut the patch release (e.g. v0.3.3-rc.0 -> v0.3.3), run
```
just release-bump-version patch
```

- open a pr targeting the `releases/v*` branch
- once this pr is merged, open a new release in github (https://github.com/fedimint/fedimint/releases/new)
- reference previous releases and stay consistent with style of title and release notes for release candadites and official releases
  - https://github.com/fedimint/fedimint/releases
- manually test upgrade to release
  - `just test-upgrades "<previous release> <new release>"`
  - possible to add more versions as args
- publish to crates (TODO: not sure of process yet)
  - `cargo workspaces publish --from-git`
  - this may cause errors. not ideal, but hack workaround for now is to manually publish each package that had issues using:
    - `cargo publish --no-verify -p <package>`
    - `cargo publish --no-verify -p <package>`
  - elsirion and dpc are only two with permissions
