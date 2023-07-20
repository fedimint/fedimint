# `federation_expiry_timestamp`

A UNIX timestamp in seconds after which the federation will shut down. During early testing of Fedimint federation will shut down
frequently to upgrade to newer versions. If users leave funds on them these will be lost. By setting this field clients
can warn users about this and encourage them to remove their funds.

Since clients can only nag users but not force them to remove their funds, it is encouraged to also set the
[`welcome_message`] field and mention what will happen with left-over funds there (e.g. donation).

## Structure
Base 10 encoded integer representing the UNIX timestamp in seconds of the targeted shutdown time after which no federation
operations will be possible anymore.
