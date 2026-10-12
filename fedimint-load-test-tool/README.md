# fedimint load test tool

This a tool with two main functionalities:

1) `test-connect`: keep many connections open to assess how many clients the server is able to handle simultaneously
2) `load-test`: try many reissues and gateway payments to measure the user experience according to a given number of simultaneous users

It can handle both federations running locally or remotely.

## How to use it

The easiest way is to test locally in the standard `nix develop` environment.

Then run:

```
just mprocs
```

And execute for instance:

```bash
fedimint-load-test-tool --users 10 load-test --generate-invoice-with ln-cli
```

If there is no local `fedimint-cli` and/or `gateway-cli` then there are alternative ways of providing ecash and lightning invoices. Run `fedimint-load-test-tool load-test --help` for more options.

## Protected input files

Bearer ecash passed with `--initial-notes` grants control of funds. Invite codes
are normally public, but can include an optional access secret. To avoid exposing
these inputs in shell history or process arguments, use files with access limited
to the user running the tool:

```bash
fedimint-load-test-tool load-test --initial-notes-file notes.txt --invite-code-file invite.txt
fedimint-load-test-tool test-connect --invite-code-file -
```

`--initial-notes-file` is available on `load-test` and `ln-circular-load-test`;
`--invite-code-file` is available on all four commands. `-` reads standard input,
with at most one stdin input per invocation. Each file option conflicts with its
legacy direct-value option, which remains supported. Inputs must be UTF-8, with
at most 16 MiB for notes and 1 MiB for invites (including any trailing newline).
Exactly one final LF or CRLF is removed; other whitespace is preserved.
The file content uses the same note or invite encoding as the direct option.
