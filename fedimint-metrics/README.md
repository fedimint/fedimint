# fedimint-metrics

## Introduction

This crate helps expose metrics in [prometheus](https://prometheus.io/) format for monitoring and administration of federations.

## Getting started

The easiest way to test it is to create an account on https://grafana.com/, then `Add new connection`, pick `Hosted Prometheus metrics` and `Via Grafana Agent`. Follow the instructions to create a new config and change
```yaml
- targets: ['localhost:9100']
```
to
```yaml
- targets: ['localhost:3000']
```

Then you can build dashboards using the `grafanacloud-xxx-prom` `data source`.

But of course before that start the metrics with something like:
```bash
for i in 0; do fedimint-metrics monitor --database $FM_DATA_DIR/server-$i/database --cfg-dir $FM_DATA_DIR/server-$i --password pass$i;done
```

And to make some lightning payments, you can run
```bash
fedimint-load-test-tool load-test --generate-invoice-with ln-cli
```
