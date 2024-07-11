## Important Fedimint v0.4 Release Notes

This document describes only critically important release notes.
For all the non-critical release notes, see usual places (like github release pages).

### Lock-step upgrade requirement

Upgrading existing Federations that were created using previous (pre v0.4.x)
versions of `fedimintd` requires stopping all peers at the exact same session count
(mint's internal consensus height), and switching to new v0.4.x release at the same time,
before starting them again.


To schedule stopping your `fedimintd` at specific consensus height you can
use `fedimin-cli` command:

**Details to be described in the near feature. Check newer version of this document.**

### Acknowledging

To acknowledge that you are aware of requirements described above please set:

```
FM_REL_NOTES_ACK=0_4_xyz
```

in your `fedimintd` environment when running `fedimintd v0.4.x`.

If you are a `fedimintd` integrator (e.g. wrap `fedimintd` in shell scripts, Dockerfiles, NixOS modules, etc.),
please make sure the end user/operator of `fedimintd` is required to set it.
