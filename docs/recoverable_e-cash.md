# Recoverable E-Cash

By deriving both nonces and blinding keys deterministically from a seed we can build a scheme that allows restoring
e-cash tokens from said seed with help of the federation. In the following we describe the two components of the scheme:
deterministic e-cash derivation and recovery of blind signatures from the federation to reconstruct the e-cash wallet.

## Deterministic Key Derivation
Our deterministic key derivation scheme consists of three parts:

1. A scheme that allows storing input key material (IKM) in human readable form
2. A scheme that uses this IKM to derive more pseudo random keys (PRKs)
3. A scheme that reduces these PRKs to the respective required keys (secp256k1, BLS12-381)

### IKM Storage

**TBD.** Candidates are:
* [BIP39]
* [SLIP39]
* [CODEX32]

### PRK Derivation
We base our key derivation scheme on [RFC5869]. We instantiate the HKDF with SHA512 as its hash function. For the root
key the inputs to HKDF-extract are:

* IKM: 512bit IKM from previous step
* Salt: `b"Fedimint Client Salt"`

The output is saved as the 512bit secret of the root node in our key tree.

To derive child keys from this root key we first define the following helper function that takes a *secret* of the
parent key, a 8byte *tag* representing the use of the derived key and a child key *index* as inputs and outputs a new
PRK:

```python
def derive(secret, tag, index):
    info = bytes(tag) + to_le_bytes_64(index)
    return HKDF-expand(prk = secret, info = info, length = 64)
```

To generate child keys we call `derive(parent_secret, b"childkey", idx)` with `idx` being the child key's 64bit index.
Child keys can be derived from both the root key and other child keys.

### Key reduction
To prevent accidental use of the same randomness in two different schemes we first add another derivation step instead
reducing the secret of a key directly.

#### Secp256k1
For secp256k1 the probability of a random 256bit secret being a valid secret key is very high. To prevent failure in the
unlikely case of drawing an invalid key we try again with new randomness in that case. This means that the algorithm is
not constant time, but since failure is exceedingly improbable the information leaked is negligible. 

```python
def reduce_to_secp256k1_key(secret):
    for i in range(0, 2**64-1):
        key = derive(secret, b"secp256k", i)[0:32]
        if is_valid_secp256k1_key(key):
            return key
```

#### BLS12-381
For BLS12-381 keys the probability that a random 256bit secret lies outside the key range is significant. To prevent
timing attacks we thus use a different approach where a significantly larger secret (in our case 512bit) is taken modulo
the order of the secret key field [^1].

```python
def reduce_to_bls12_381_key(secret):
    key = derive(secret, b"secp256k", 0)
    bls_key = key % BLS_FIELD_ORDER
    return bls_key
```

#### ChaCha20-Poly1305

```python
def reduce_to_chacha20_poly1305_key(secret):
    return derive(secret, b"c20p1305", 0)
```

# Derivation paths
The key derivation scheme described above allows to describe keys using their descendence path from the root key, called
derivation path. The first two derivation steps of each key concern the federation and the fedimint module, so the key
handed over to any particular module client would be derived using the following derivation path:

```
[federation_id, module_id]
```

In the following we define how secrets should be derived for specific use cases.

## Usage: E-Cash

For deriving e-cash notes we define the following derivation path:

* **module_id**: The mint module has id `0`
* **mint_module_key_type**: The key type of e-cash tokens inside the mint module is `0`
* **amount**: The value of the note (in msats)
* **index**: Index of the e-cash note to be minted, automatically incremented
* **key_type**: `0` for the secp256k1 spend key, `1` for the BLS12-381 blinding key

```
[federation_id, module_id, mint_module_key_type, amount, index, key_type]
```

The **spend keys** are secp256k1 secret keys. Their corresponding compressed public key is used as the
e-cash note nonce.

The **blinding keys** are BLS12-381 secret keys and are used to blind the e-cash note nonces and to unblind
issued blind signatures.

The **amount** is included in the path to prevent hypothetical attacks where a malicious
user would race to mint notes with the same blind nonce, but a different amount trying to
confuse the recovery code to use a smaller denomination version and loose money. By
including **amount** in the derivation, the e-cash recovery code knows the expected
denomination beforehand.

## Mint module e-cash backup snapshot keys

The encryption and signing key used for e-cash backups both use the following derivation path:

* **module_id**: The mint module has id `0`
* **mint_module_key_type**: The key type of backup snapshot keys is `1`

The implicit per key type derivation (ChaCha20-Poly1305 vs secp256k1) makes the two keys actually different.


[^1]: See BSI [TR-03111] section 4.1.1 and [TR-02102] section B.4 for details.

<!-- markdown-link-check-disable -->

[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[SLIP39]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
[CODEX32]: https://github.com/roconnor-blockstream/SSS32/blob/ms32/MasterSeed32.md 
[RFC5869]: https://www.rfc-editor.org/rfc/rfc5869
[TR-03111]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile&v=1
[TR-02102]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile&v=4
