# Protected command-line inputs

Prefer protected files or standard input over literal secret command-line
arguments. Existing value arguments remain supported for compatibility, but are
discouraged for passwords, recovery secrets, e-cash and private invite codes.
Environment variables remain supported where already available; a protected file
is preferable to copying credentials into the process environment.

The CLI accepts these additive file options:

| Command | File option |
| --- | --- |
| Global guardian authentication | `--password-file` |
| Global custom federation secret | `--federation-secret-hex-file` |
| `admin auth` | `--password-file` |
| `restore` | `--mnemonic-file`, `--invite-code-file` |
| `join`, `dev decode invite-code`, `dev query-federation-ips` | `--invite-code-file` |
| `dev api` | `--password-file`, `--params-file` |
| `dev config-encrypt`, `dev config-decrypt` | `--password-file` |
| `dev encode invite-code` | `--api-secret-file` |
| `dev encode notes` | `--notes-json-file` |
| `dev decode notes` | `--file` (existing option, now also supports stdin) |
| `module mint reissue`, `split`, `combine`, `validate` | `--notes-file` |
| `module mint dev check-nonce` (e-cash input form) | `--notes-file` |
| Legacy `reissue`, `split`, `combine` | `--notes-file` |
| `module mintv2 receive` | `--ecash-file` |

Use `-` as the file name to read standard input. For example, with files mounted by
a secret manager and readable only by the intended user:

```sh
fedimint-cli --password-file /run/secrets/guardian-password admin status
fedimint-cli restore \
  --mnemonic-file /run/secrets/client-mnemonic \
  --invite-code-file /run/secrets/federation-invite
fedimint-cli dev decode notes --file - < /run/secrets/ecash
fedimint-cli module mint reissue --notes-file - < /run/secrets/ecash
fedimint-cli module mint combine \
  --notes-file /run/secrets/ecash-one \
  --notes-file /run/secrets/ecash-two
```

Do not use command substitution to pass the contents of a protected file back as
a literal argument. Avoid shell commands containing literal secrets in examples,
history, scripts or logs. The CLI does not create or change permissions on input
files: use restrictive owner-only permissions, a protected directory, or your
secret manager's access controls.

File input and the corresponding direct/environment input are mutually exclusive.
Only one input per invocation can consume stdin. Unset an existing credential
environment variable when selecting the file alternative.

Root and legacy-command source conflicts, and all known module/global stdin
conflicts, are checked before client startup. Module commands retain their
existing parsing lifecycle: direct/file exclusivity is checked after opening the
client, but before reading the module's secret input or performing its action.

Files must contain UTF-8 text. Exactly one final newline (`LF` or `CRLF`) is
removed; all other whitespace is preserved. Credential and invite inputs are
limited to 1 MiB per file; e-cash and JSON payloads are limited to 16 MiB per file,
including the optional line ending. These are input limits, not recommended credential sizes.
Errors while loading or parsing protected inputs do not include their contents.
For `combine`, repeat `--notes-file` with one serialized e-cash value per file;
do not mix file inputs and positional note values.

Outputs are unchanged: commands that print recovery secrets, e-cash, decoded
notes, invite codes or decrypted configuration still produce sensitive output.
Protect output files, pipes and terminal logs accordingly.
