## Important Fedimint v0.4 Release Notes

This document describes only critically important release notes.
For all the non-critical release notes, see usual places (like github
[release pages](https://github.com/fedimint/fedimint/releases)).

### Lock-step upgrade requirement

Upgrading Federations that were created using previous (0.3.x)
versions of `fedimintd` requires stopping all peers at the exact same session count
(mint's internal consensus height), before simultaneously switching to new v0.4.x release
binaries.

If you are setting up a new Federation using 0.4.x version, you don't need to do anything
special, but you do need to acknowledge being aware of this requirement (see last section
of this document).

**You must first upgrade your 0.3.x Federation to version v0.3.3 or higher for functionality
required to coordinate shutdown to be available.**

All guardians should be available to coordinate upgrading using an out-of-band communication
channel, e.g. a group chat. Once all guardians are available, confirm the current session count.

Get the current session count using `fedimint-cli`:

```
fedimint-cli session-count
```

The minimum time required to complete a session is 3 minutes, so choose a future session that
will give all guardians enough time to schedule a shutdown after the session count (e.g. 15
minutes implies 5 sessions after the current session count).

To schedule stopping your `fedimintd` after a specific session count, use the
`fedimint-cli` command:

```
fedimint-cli --password <password> --our-id <our_id> admin shutdown <session_count>
```

Alternatively, the current session count and scheduling a shutdown after session count is
accessible through the guardian UI. At the bottom of the page are actions in a danger zone
section. Click on "Schedule Shutdown" and fill in the form to schedule a shutdown after a
future session count, referencing the current session count in the UI.

After all peers have shutdown, verify that all peers shut-down at the expected session count,
e.g. by reading fedimintd system logs and looking for last message of the form:

```
INFO consensus: Session 12345 completed
```

Only after all guardians have verified it, proceed to upgrade the binary to the new 0.4.x
version. Be careful not to accidentally start `fedimintd` service with the old binary.

### Acknowledging

To acknowledge that you are aware of requirements described above please set:

```
FM_REL_NOTES_ACK=0_4_xyz
```

in your `fedimintd` environment when running `fedimintd v0.4.x`.

If you are a `fedimintd` integrator (e.g. wrap `fedimintd` in shell scripts, Dockerfiles, NixOS modules, etc.),
please make sure the end user/operator of `fedimintd` is required to set it.
