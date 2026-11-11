# Container image size budgets

**The checked-in budgets are provisional and not accepted.** This draft is
blocked on post-fix measurements of all seven images on both platforms, with
particular attention to ARM, and updated budgets. If those measurements confirm
remaining runtime or toolchain retention, address it before setting final budgets.
Do not mark the PR ready or merge it before completing this work.

The `containers` job checks every built image before loading or publishing it.
Each image and architecture has a fixed baseline in
[`container-image-sizes.json`](container-image-sizes.json). The maximum is the
baseline plus 25%, rounded down to a whole byte. A missing baseline fails the
job rather than leaving a new image unguarded.

The metric is the sum of the **uncompressed layer tar sizes**, including tar
headers and padding, for the single image in the Nix Docker archive. It does
not include the outer archive's metadata, and it is not a Docker Hub download
size or a filesystem's disk usage. `check-container-size.py` streams the
archive without extracting it and verifies the platform before comparing the
size with the budget.

## Baseline provenance

The provisional baselines use the current published `releases/v0.13` images,
tagged with source revision
`d0a0b430c18d7ccd5715c4947cafe6a3ffa3e4b4`, measured on November 11, 2026.
The JSON records each platform manifest digest. For each image, the measurement
sums the decompressed bytes of its manifest's layer blobs. Measurement checks
verified the compressed blob hashes and uncompressed `rootfs.diff_ids`. This is
the same layer tar byte count read from a locally built archive by the guard.

These release images predate master's release-debuginfo reduction in #9362,
which landed on November 2, 2026.
They record published production sizes, not a post-reduction master target.
Maintainers have not accepted these sizes as budgets; replace them after the
post-fix measurements of all seven images on both platforms. Current master
x86 builds of all seven images are much smaller; ARM remains unmeasured.
The missing ARM measurements do not establish that another fix is necessary.
The job still builds only release branches and tags; this change
does not enable additional image builds on pull requests or master.

## Investigating a failure

Read the actual, baseline, and maximum byte counts in the build log. Check for
unintended runtime dependencies and embedded debuginfo before accepting growth.
Do not automatically raise a baseline after a failure.

To measure a newly built archive with the same metric:

```sh
nix build .#container.fedimintd
nix shell --inputs-from . nixpkgs#python3 --command \
  python3 .github/scripts/check-container-size.py fedimintd x86_64-linux result
```

The command prints the actual byte count even when the budget is exceeded.
For deliberate changes, update the relevant baseline and its source revision
and manifest digest together after measuring that image on that platform.
Keep unrelated images' baselines unchanged. Run the guard's regression tests
with:

```sh
nix shell --inputs-from . nixpkgs#python3 --command \
  python3 .github/scripts/test-check-container-size.py
```
