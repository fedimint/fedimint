# Guardian availability screenshots

These are real Chromium captures of the production Maud renderer, with
**synthetic local-observer data**, not a running federation. They use the
existing dashboard layout, CSS, general information card, and latency card.
They do not show the complete dashboard or exercise live consensus traffic.

- `observed-desktop.png`: observed values, partial coverage, self excluded,
  and a peer with missing observations.
- `observed-mobile.png`: the same view at a narrow viewport; the table scrolls
  horizontally to reveal the last-observed column.
- `startup.png`: no persisted observations yet.
- `stale.png`: old observations explicitly labeled historical.

The fixed times and names are public fixtures from
`fedimint-server-ui/src/dashboard/availability/tests.rs`. No guardian
configuration, credentials, or production data is used.

## Reproduce

From the repository root, inside the pinned development environment:

```sh
fixtures=$(mktemp -d /tmp/public/guardian-availability-fixtures.XXXXXXXX)
FM_AVAILABILITY_FIXTURE_DIR="$fixtures" cargo test -p fedimint-server-ui \
  export_browser_fixtures --locked -- --ignored
python3 docs/screenshots/guardian-availability/capture.py \
  /path/to/chromium "$fixtures"
```

The captures use Chromium from this repository's lock-pinned `nixpkgs`, with
its sandbox enabled. The script serves fixtures only on loopback and shuts
the server down after capturing. It overwrites the four PNG files in this directory.
The fixture server does not implement the dashboard's connectivity check or
refresh endpoint; captures demonstrate rendering rather than those requests.
Loading, unavailable, startup, partial, stale, and invalid observations are
covered by renderer tests.
