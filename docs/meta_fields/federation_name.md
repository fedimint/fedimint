# `federation_name`

The name of the federation. While it cannot be used to identify/authenticate the federation, it can be used in apps to
display a more human-readable identifier than the hex-encoded federation ID.

## Structure

The value can be any valid unicode string.

## Setting the name

New federations do not set an immutable name during setup. The setup CLI's
`--federation-name` option is deprecated and ignored by new guardians.

After setup, open the **Meta** module in each guardian's dashboard, set
`federation_name` to the desired string, and submit the metadata. A guardian
consensus threshold must submit the same complete metadata value before the
new name takes effect. Preserve other metadata fields when updating the name.
The Meta module must be enabled to set or change the name.

The dashboard and gateway prefer the Meta module name. For existing federations,
they continue to read the immutable configuration name when the module has no
usable name (including when the module is absent). Existing configurations are
not rewritten. Gateway metadata is cached and refreshed periodically, so name
changes may not appear immediately.
