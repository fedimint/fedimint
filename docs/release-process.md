# Release Process

The release process evolves each cycle, so don't hesitate to make frequent edits to this doc.

### Steps

- For release candidates
  - If this is a new major release but there isn't a `releases/v0.4` branch, create the new branch off of `master`
  - Bump the cargo version to a new release candidate (e.g `0.4.3-rc.0`)
  - Open a PR targeting the `releases/v*` branch
  - Once this PR is merged, pull the release branch locally and push a new signed tag to GH
- For final releases
  - Bump the cargo version to a final release (e.g. `0.4.3`)
  - Create a new branch off of `releases/v*` with the final release tag (e.g. `releases/v0.4.3`)
    - This new branch isn't protected, so you can push directly to GH
  - Create a new signed tag and push to GH
- When a tag is pushed, the GH workflow will automatically publish a new release with this tag
- Publish to crates
  - `cargo workspaces publish --from-git`
  - `@elsirion` and `@dpc` are the only two with permissions
- Start upgrade tests using the new tag
  - https://github.com/fedimint/fedimint/actions/workflows/upgrade-tests.yml
  - The upgrade paths and upgrade test kinds varies based on the release (coordinated shutdown vs staggered, etc)

### Commands

To bump versions, run
```
just bump-version <FROM_VERSION> <TO_VERSION>
ex:
just bump-version 0.5.0-alpha 0.5.0-rc.0
```

We've previously used the following command to bump versions, however this fails for `[dev-dependencies]`. This command may still be useful if there are version collisions using the previous command.

```
cargo workspaces version --all --exact --no-git-commit --yes --force '*' --pre-id rc prerelease
```

To create a new signed tag, run
```
git tag -a -s <tag> && git push <upstream> <tag>
ex:
git tag -a -s 0.5.0-rc.0 && git push upstream 0.5.0-rc.0
```
