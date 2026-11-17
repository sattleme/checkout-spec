# Changelog

Versions of this specification and its vectors ([README](README.md#versions)). Each says what an
implementation must change to follow it.

## 1.0.0

First public version: version 1 of the protocol.

- `SPEC.md`: what an online shop's server does to take Lightning and on-chain payments for a
  sattle.me merchant: the integration key, the channel, relays and their complete reads, invoices
  and their declaration, an order's earlier invoices, payment checks, prices in a currency and
  rate sources, checkout links and redirect URLs, on-chain payments (deposit addresses, leases and
  their confirmation, one explorer: mempool.space, or the merchant's Bitcoin node that the channel
  names, with its fallback, and that the pages of checkout links read too when the merchant allows
  it; witnesses, replacements, the rest of an underpayment, the merchant's tolerance, the merchant's
  acceptance, counted when a majority of the merchant's relays hold it, and acceptance records),
  security and constants.
- `PORTING.md`: how to write an implementation in another language, in its own repository.
- `currencies.json`, the conformance vectors of `vectors/` with their schemas, the vectors of the
  merchant's app (`vectors/app/`) and the official NIP-44 vectors (`vectors/nip44/`).
- `manifest.json`: the SHA-256 of every file an implementation pins.
