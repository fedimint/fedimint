# Release Process

### Steps

- For beta releases
  - Beta releases are only for new major releases, skip to creating the release candidate for the minor/patch version
  - If this is a new major release but there isn't a `releases/v*` branch (e.g. `releases/v0.4`)
    - Create a new `releases/v*` branch off of `master`
    - Add a new commit bumping the version from `*-alpha` to the beta release (e.g. `0.4.0-alpha -> 0.4.0-beta.0`)
    - Push the release branch to `upstream`
    - Add branch protection rules to the release branch in GH
    - Push a signed tag to GH
    - Create a PR that bumps master to a new `*-alpha` (e.g. `0.4.0-alpha -> 0.5.0-alpha`)
  - If there is already a `releases/v*` branch
    - Bump the cargo version to a new beta version (e.g. `0.4.3-beta.1`)
    - Open a PR targeting the `releases/v*` branch
    - Once this PR is merged, pull the release branch locally and push a new signed tag to GH
  - Start back-compat and upgrade tests (see [Back-Compat and Upgrade Tests](#back-compat-and-upgrade-tests))
  - Publish to crates.io
- For release candidates
  - Once the beta releases have passed initial testing and the release is considered production ready
    - Bump the version to the release candidate (e.g. `0.4.0-beta.0 -> 0.4.0-rc.0`)
    - Open a PR targeting the `releases/v*` branch
    - Once this PR is merged, pull the release branch locally and push a new signed tag to GH
    - After releasing `rc.0`, commit to supporting backwards compatibility
  - Start back-compat and upgrade tests (see [Back-Compat and Upgrade Tests](#back-compat-and-upgrade-tests))
  - Wait for tests to pass before publishing
    - Once you've cut an RC you're committed to back-compat support, so a test failure after publishing to crates.io puts you in a harder spot with a broken public artifact
  - Publish to crates.io
- For final releases
  - Bump the cargo version to a final release (e.g. `0.4.3`)
  - Create a new branch off of `releases/v*` with the final release tag (e.g. `releases/v0.4.3`)
    - This new branch isn't protected, so you can push directly to GH
  - Create a new signed tag and push to GH
  - Publish to crates.io
  - Sign binaries
    - `just sign-release <tag>`
    - ex: `just sign-release v0.5.0`
  - Bump the version on `releases/v0.*` to the next minor `-alpha`
    - example on `releases/v0.5`: `just bump-version 0.5.0-rc.5 0.5.1-alpha`
  - Update master's CI to use the new tag for back-compat and upgrade tests on PRs/merge queue
    - `.github/workflows/ci-backwards-compatibility.yml`
    - `.github/workflows/upgrade-tests.yml`
    - `justfile.fedimint.just`
- When a tag is pushed, the GH workflow will automatically publish a new release with this tag

### Back-Compat and Upgrade Tests

CI runs a thinned-down version matrix on PRs/merge queue. Release testing runs the full matrix against each tag.

**Setup**

Create a test branch off the release branch and push to upstream (not your fork). Example for v0.10 (adjust accordingly):
```
git checkout releases/v0.10
git checkout -b v0.10.0-tests
git push upstream v0.10.0-tests
```

**For each new tag**

1. Rebase onto the release branch to pick up any backported fixes:
```
   git fetch upstream
   git rebase upstream/releases/v0.10
```

2. Update version strings and test configuration. Reference commit: https://github.com/fedimint/fedimint/commit/8e275eeaae1c6a05b492819818e45f4920cfefb4

   For a complete release iteration, refer to the commits on the `v0.10.0-tests` branch.

3. Commit and push:
```
   git commit -am "run back-compat/upgrade tests vs v0.10.0-rc.0"
   git push --force upstream v0.10.0-tests
```

4. Trigger workflows manually in GitHub Actions:
   - Go to Actions → Backwards-Compatibility (or Upgrade Tests)
   - Click "Run workflow"
   - Select your test branch from the dropdown
   - Run

The test branch is never merged.

**Version matrix**

Back-compat tests against all supported versions. Upgrade tests cover:
- Direct upgrades: each old version → new tag
- Sequential upgrade: full path through all versions

**Notes**
- If CI times out, bump the timeout in the workflow file
- Run for each beta and RC

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
git tag -a -s <tag>
git push <upstream> <tag>

ex:
git tag -a -s v0.5.0-rc.0
git push upstream v0.5.0-rc.0
```

Publish to crates.io (`@elsirion` and `@dpc` are the only users with permissions)

```
just publish-release
```
