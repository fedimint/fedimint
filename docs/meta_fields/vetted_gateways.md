# `vetted_gateways`

A list of gateway identifiers vetted by the federation. When available, Clients should prefer to select a gateway from this subset of the registered gateways

## Structure

JSON list of hex encoded gateway ids

```json
{
  "vetted_gateways": [
    "<gateway_id_hex_str>"
    ]
}
```
