# Chrome Tracing

Integration test can export chrome tracing file. 

- run `FEDIMINT_TRACE_CHROME=1 cargo test test_name`
- file `trace-{UNIX_TIME}.json` will be created in CWD.
- open this file in [perfetto] or `chrome://tracing`

# Open Telemetry

Fedimint uses [opentelemetry] and [jaeger] for telemetry.

## Running Server with telemetry

- Running jaeger
```shell
docker run -d -p6831:6831/udp -p16686:16686 jaegertracing/all-in-one:latest
```

port `6831` is for receiving telemetry data.
port `16686` is for jaeger web ui.

- Starting the server

```shell
cargo run --features telemetry --bin server -- --with-telemetry <CFG_PATH>
```

[perfetto]: https://ui.perfetto.dev/
[opentelemetry]: https://opentelemetry.io/
[jaeger]: https://www.jaegertracing.io/
