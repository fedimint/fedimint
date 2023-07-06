# docker

This directory contains files to help run federation components with `docker`.

To install `docker` and `docker-compose`, follow standard directions on web.

## Running fedimintd + guardian-ui

Enter the specific directory for `fedimintd`:

```bash
cd docker/fedimintd
```

Replace `127.0.0.1` with your external ip address, e.g:

```bash
sed -i 's/127.0.0.1/111.222.333.444/g' docker-compose.yaml
```

(or edit `docker-compose.yaml` with your favorite editor)

Then spin up fedmintd + guardian-ui with `docker-compose`:

```bash
docker-compose up
```

Or to let it run in background you can use:

```bash
docker-compose up -d
```

By default you should open ports 8173 and 8174 of `fedimintd` for external access on your router/firewall.

To access the ui externally you can use `http://your-external-ip:3000` (if you open port 3000) but if possible we recommend accessing it locally from inside the machine at `http://127.0.0.1:3000`

### Changing configuration

By default the `docker-compose` is configured for [mutinynet signet](https://blog.mutinywallet.com/mutinynet/), but this can be altered by changing the following environment variables on `docker-compose.yaml`:

```
- FM_BITCOIN_RPC_KIND=...
- FM_BITCOIN_RPC_URL=...
- FM_BITCOIN_NETWORK=...
```
