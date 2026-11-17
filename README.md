# sattle.me checkout: specification

What an online shop's **server** does to take Lightning and on-chain payments for a
[sattle.me](https://sattle.me) merchant, specified for implementations in any language, with the
conformance vectors every implementation passes.

| File                                 | What it is                                                                          |
| ------------------------------------ | ----------------------------------------------------------------------------------- |
| [`SPEC.md`](SPEC.md)                 | The protocol, the client's API and data model, its errors, every rule and constant. |
| [`currencies.json`](currencies.json) | The currencies an order may be priced in, with their decimals.                      |
| [`vectors/`](vectors)                | Conformance vectors (JSON), each file saying what it holds.                         |
| [`vectors/app/`](vectors/app)        | Records made by the merchant's app, and a declaration and a checkout link it reads. |
| [`vectors/nip44/`](vectors/nip44)    | The official NIP-44 v2 vectors.                                                     |
| [`PORTING.md`](PORTING.md)           | How to write an implementation in another language, in its own repository.          |
| [`manifest.json`](manifest.json)     | This version, and the SHA-256 of every file above, which implementations pin.       |

## Implementations

This repository holds no implementation and depends on none: `SPEC.md` alone is authoritative.
Implementations follow [`PORTING.md`](PORTING.md), each in its own repository
(`sattleme/checkout-<language>`).

## Using it

An implementation never reads this repository at run time nor from its tests' network: it keeps a
**copy** of the files [`manifest.json`](manifest.json) lists, pinned to one commit, and its tests
check every file's SHA-256 against the manifest ([PORTING.md](PORTING.md#the-pinned-copy-of-the-specification)).

## Versions

`manifest.json` gives this repository's version (semantic versioning) and the protocol's. The
two are distinct: the protocol's version is the one its records and keys carry.

From 1.0.0, its first public version, the specification is final, and its versions mean:

- **major**: a new version of the protocol, which implementations of the previous one do not read;
- **minor**: a rule or a vector added or changed: implementations take the new copy and pass it;
- **patch**: wording only, no rule or vector changes.

[CHANGELOG.md](CHANGELOG.md) says what each version changed. A version is a tag `vX.Y.Z` on the
default branch, pushed by a maintainer.

## Where the vectors come from

The expected values of [`vectors/`](vectors) are written by hand from `SPEC.md`, and checked
against an implementation; [`vectors/app/`](vectors/app) is made by the merchant's app and by an
implementation of this specification, each reading the other's. They are published here, unchanged,
by pull request.

This repository's CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) checks every file
against its schema ([`schemas/`](schemas)), the manifest, the links and the format, and computes
part of the vectors again with an independent implementation: the integration keys, the key
derivations, the app's channel, declarations and lot, NIP-44, the conversions of prices, https URLs
and Lightning addresses, BOLT11 invoices and their checks, checkout links' records, the pay requests
of the app's checkout links, and the on-chain rules (deposit addresses, leases, witnesses, the
methods of an order, on-chain statuses, the rest of an underpayment: its keys, records, declarations
and when it is asked; the merchant's tolerance, acceptance records, the merchant's acceptances; the
merchant's Bitcoin node: its URL, the channel's field, which explorers a read asks, the node of a
checkout link's record), the complete reads of relays, and an order's earlier invoices.

## Reporting a problem

Where `SPEC.md`, the vectors and an implementation disagree, one of them has a bug: please report
it. Anything that could cost a merchant money or reveal a key is a vulnerability: report it
privately ([SECURITY.md](SECURITY.md)).

## License

[MIT](LICENSE)
