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
