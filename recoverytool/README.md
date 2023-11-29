# Recovery tool

The `recoverytool` allows extracting wallet descriptors and their corresponding private keys from an offline federation.
This is useful in cases where a federation has been shut down and users have withdrawn their funds, but due to lost
e-cash notes or other operational difficulties there are funds left in the federation's on-chain wallet.

**IMPORTANT**:
* **This is an expert tool, handle with care**
* **Do not share any output with untrusted parties, it contains secret key material**
* **Do not use while federation is running or if it is expected to be ever started again**

## Usage

```
Tool to recover the on-chain wallet of a Fedimint federation

Usage: recoverytool [OPTIONS] --password <PASSWORD> <--cfg <CONFIG>|--descriptor <DESCRIPTOR>> <COMMAND>

Commands:
  direct  Derive the wallet descriptor using a single tweak
  utxos   Derive all wallet descriptors of confirmed UTXOs in the on-chain wallet. Note that unconfirmed change UTXOs will not appear here
  epochs  Derive all wallet descriptors of tweaks that were ever used according to the epoch log. In a long-running and busy federation this list will contain many empty descriptors
  help    Print this message or the help of the given subcommand(s)

Options:
      --cfg <CONFIG>             Directory containing server config files
      --password <PASSWORD>      The password that encrypts the configs [env: FM_PASSWORD=]
      --descriptor <DESCRIPTOR>  Wallet descriptor, can be used instead of --cfg
      --key <KEY>                Wallet secret key, can be used instead of config together with --descriptor
      --network <NETWORK>        Network to operate on, has to be specified if --cfg isn't present [default: bitcoin]
      --readonly                 Open the database in read-only mode, useful for debugging, should not be used in production
  -h, --help                     Print help
```

To recover a wallet this tool requires the guardian's secret key, the federation's wallet descriptor and the tweaks used
to derive wallet descriptors.

The secret key and wallet descriptor can be supplied in two ways:
  1. **Config**: By specifying the `--cfg` flag the tool will read the key and descriptor directly from the config files
  2. **Direct argument**: Otherwise the `--key` and `--descriptor` flags have to be provided. Optionally the `--network`
flag can be provided to specify the network in this case since it cannot be determined from the config.

The tweaks making up the wallet can be provided in three ways, these correspond to the commands listed in the help
above:
  1. **direct**: Provide a single tweak manually (e.g. extracted from user wallet that attempted a peg-in after 
federation shutdown) 
  2. **utxos**: Read all confirmed UTXOs from the provided database, this will leave out in-flight UTXOs
  3. **epochs**: Scan entire epoch history in the provided database for tweaks, this will return the most wallet
descriptors, most of them empty, but should cover funds and edge cases.

In case of **utxos** and **epochs** the provided database does not need to be the one of the guardian that is trying to
recover, but of any guardian that stayed in-consensus till the end. This means funds are recoverable even with 1
database and `t` of `n` configs/secret keys.

## Recovery
This tool is meant to be used together with a Bitcoin Core wallet and the `jq` tool. While we include a brief overview
of a possible usage pattern below, please consult the [Bitcoin Core documentation](https://bitcoincore.org/en/doc/24.0.0/)
for more information about wallet and transaction handling.

The output of `recoverytool` consists of an array of wallet descriptors with optionally some meta-data. The descriptors
include n-1 public keys and 1 private key (belonging to the guardian running the script):

```
$ recoverytool --cfg server-1 --password pass1 utxos --db server-1/database/ | jq
[
  {
    "outpoint": "c76d51c9c6dc6b8e462c37b3fa376e7c2055f04f16a8fffc2ab66c5bf0deff55:1",
    "descriptor": "wsh(sortedmulti(3,0280bf3115766b7e1cb23f2f57caf4de5a9171d3985934f2895cc568b384b52319,cSRM825vXJwf8iXcngedon8nQsPC9VMB18wSiG1Fgw6Y1Kzi16ta,021123625d9b21822e1178fc0d2b3f737d0397584cfac821df3250e49c3127cab5,03865705be62a71a3776cca1169908099ad6d138a0c0ed4aeeaf2c8e64616f4085))#h2zg3uhw",
    "amount_sat": 20000
  },
  {
    "outpoint": "d19b1545907679882e925ea0c2130969eab26ab2e27431404fef7d30a5fd649c:1",
    "descriptor": "wsh(sortedmulti(3,025fbaf8b94d101215d608ae6485b5746142933c261dc5616190f3a331eeaf5f3a,cTgHDPq43RFCy5i9jr2XwMQQNEJ1Y2cYHxhyvXj2wLpF8pi2LxUj,02e25f08feee064cb4bbbb3b33c7e0ddf4d06ed261201f40532c4f5d2152072ecf,03b215967b608d4309fec126a42d49950f6049406b439d4f743cb368362a0cfce0))#v6s5xpsa",
    "amount_sat": 10000
  }
]
```

To import it into bitcoin core use the following `jq` command to transform the tool's output into a valid input format
for [`bitcoin-cli importdescriptors`](https://bitcoincore.org/en/doc/24.0.0/rpc/wallet/importdescriptors/):

```bash
$ WALLETS="$(recoverytool --cfg server-1 --password pass1 utxos --db server-1/database/ | jq '. | map({"desc": .descriptor, "timestamp":0})')"
[
  {
    "desc": "wsh(sortedmulti(3,0280bf3115766b7e1cb23f2f57caf4de5a9171d3985934f2895cc568b384b52319,cSRM825vXJwf8iXcngedon8nQsPC9VMB18wSiG1Fgw6Y1Kzi16ta,021123625d9b21822e1178fc0d2b3f737d0397584cfac821df3250e49c3127cab5,03865705be62a71a3776cca1169908099ad6d138a0c0ed4aeeaf2c8e64616f4085))#h2zg3uhw",
    "timestamp": 0
  },
  {
    "desc": "wsh(sortedmulti(3,025fbaf8b94d101215d608ae6485b5746142933c261dc5616190f3a331eeaf5f3a,cTgHDPq43RFCy5i9jr2XwMQQNEJ1Y2cYHxhyvXj2wLpF8pi2LxUj,02e25f08feee064cb4bbbb3b33c7e0ddf4d06ed261201f40532c4f5d2152072ecf,03b215967b608d4309fec126a42d49950f6049406b439d4f743cb368362a0cfce0))#v6s5xpsa",
    "timestamp": 0
  }
]
```

And run `importdescriptors` in `bitcoin-cli`:

```
$ bitcoin-cli importdescriptors "$WALLETS"
[                                                                                                                                       
  {                                                                                                                                                                                                                                                                             
    "success": true,                                                                                                                                                                                                                                                            
    "warnings": [                                                                                                                                                                                                                                                               
      "Not all private keys provided. Some wallet functionality may return unexpected errors"                                                                                                                                                                                       ]                                                                                                                                                                                                                                                                             },                                                                                                                                                                                                                                                                            
  {                                                                                                                                                                                                                                                                             
    "success": true,                                                                                                                                                                                                                                                            
    "warnings": [                                                                                                                                                                                                                                                               
      "Not all private keys provided. Some wallet functionality may return unexpected errors"
    ]                                                                                                                                   
  }                                                                                                                                                                                                                                                                             ]
```

To move these funds create a transaction using [`walletcreatefundedpsbt`](https://bitcoincore.org/en/doc/24.0.0/rpc/wallet/walletcreatefundedpsbt/),
sign it with `t` of the wallets using [`walletprocesspsbt`](https://bitcoincore.org/en/doc/24.0.0/rpc/wallet/walletprocesspsbt/)
and extract the final transaction with [`finalizepsbt`](https://bitcoincore.org/en/doc/24.0.0/rpc/rawtransactions/finalizepsbt/).
The resulting transaction can be broadcasted using [`sendrawtransaction`](https://bitcoincore.org/en/doc/24.0.0/rpc/rawtransactions/sendrawtransaction/).

This workflow has been tested with `n` different wallets in Bitcoin Core and with PSBTs to collaboratively sign
transactions. You might be able to import all keys into one wallet though and sign transactions right away.
