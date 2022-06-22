# Telemetry

Minimint uses [opentelemetry] and [jaeger] for telemetry.

## Running Server with telemetry

- Running jaeger
```shell
docker run -d -p6831:6831/udp -p16686:16686 jaegertracing/all-in-one:latest
```

port `6831` is for recieving telemetry data.
port `16686` is for jaeger web ui.

- Starting the server

```shell
cargo run --features telemetry --bin server -- --with-telemetry <CFG_PATH>
```

[opentelemetry]: https://opentelemetry.io/
[jaeger]: https://www.jaegertracing.io/
