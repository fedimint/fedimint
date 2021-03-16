# Transactions

Currently there are three types of transactions:

* Peg-ins
* Reissuances
* Peg-outs

Each such transaction should have a transaction id computable by both the client and the federation. It should be a
cryptographic hash of all components of a transaction so that a signature of it e.g. binds the spent coins to it.