# lnurlp

A tiny command line tool to fetch BOLT11 invoices from LNURLs.

## Usage
```
A tiny command line tool to fetch BOLT11 invoices from LNURLs

Usage: lnurlp [OPTIONS] --amount <AMOUNT> <LNURL>

Arguments:
  <LNURL>  The LNURL to fetch the invoice from (can be LNURL or Lightning Address)

Options:
  -a, --amount <AMOUNT>    The amount in millisatoshis to request
  -c, --comment <COMMENT>  Optional comment to include with the payment
  -h, --help               Print help
  -V, --version            Print version
  ```