# sattle.me checkout: specification

Version 1 of the protocol. This document is for anyone who writes an implementation, in any
language (TypeScript, PHP, C#, Python, Java, Go…): an implementation that follows it and passes
the [conformance vectors](#29-conformance-vectors) takes payments exactly as any other does, and
reads the invoices another stored. This document alone is authoritative.

The key words MUST, MUST NOT, SHOULD and MAY are those of RFC 2119. Report any discrepancy (between
this document, its vectors and an implementation, or within this document) as an issue on
[this repository](https://github.com/sattleme/checkout-spec); a vulnerability, privately
([SECURITY.md](https://github.com/sattleme/checkout-spec/blob/main/SECURITY.md)).

## Contents

1. [What an integration does](#1-what-an-integration-does)
2. [Conventions](#2-conventions)
3. [Data model](#3-data-model)
4. [Client](#4-client)
5. [Errors](#5-errors)
6. [Text](#6-text)
7. [Numbers](#7-numbers)
8. [The integration key](#8-the-integration-key)
9. [Relay lists](#9-relay-lists)
10. [Key derivations](#10-key-derivations)
11. [Nostr events](#11-nostr-events)
12. [Sealed records](#12-sealed-records)
13. [Relays](#13-relays)
14. [Reading the channel](#14-reading-the-channel)
15. [HTTP](#15-http)
16. [Lightning address](#16-lightning-address)
17. [Creating an invoice](#17-creating-an-invoice)
18. [Invoice checks](#18-invoice-checks)
19. [BOLT11](#19-bolt11)
20. [The declaration](#20-the-declaration)
21. [One order, one invoice at a time](#21-one-order-one-invoice-at-a-time)
22. [Payment check](#22-payment-check)
23. [Waiting for a payment](#23-waiting-for-a-payment)
24. [Finding an order's invoices](#24-finding-an-orders-invoices)
25. [Prices in a currency](#25-prices-in-a-currency)
26. [Rate sources](#26-rate-sources)
27. [Security](#27-security)
28. [Constants](#28-constants)
29. [Conformance vectors](#29-conformance-vectors)
30. [Checkout links](#30-checkout-links)
31. [On-chain payments](#31-on-chain-payments)

## 1. What an integration does

A merchant uses the sattle.me app. An **integration** is an online shop, or any tool, whose
**server** makes the merchant's customers pay in Lightning, or on-chain
([§31](#31-on-chain-payments)). The merchant creates the integration in the app and gives its
**secret key** (`sattleme_ck_…`) to the integrator.

With that key alone, the integrator's server:

1. reads the integration's **channel** on Nostr relays: the merchant's Lightning address, payment
   registry and relays ([§14](#14-reading-the-channel));
2. asks the merchant's Lightning address (LNURL, `breez.tips`) for the **invoice** of an order, and
   checks it ([§17](#17-creating-an-invoice), [§18](#18-invoice-checks));
3. when the amount allows it, **leases** a deposit address of the merchant's wallet, from the lot
   the merchant's app gives the integration ([§31](#31-on-chain-payments));
4. **declares** the invoice in the merchant's registry, on a majority of the merchant's relays,
   before it is shown ([§20](#20-the-declaration));
5. gives the invoice and the address to the shop's page, which shows them;
6. **checks the payment** (LUD-21, and for the address an explorer: mempool.space, or the
   merchant's Bitcoin node) and marks the order paid ([§22](#22-payment-check)); when less than the
   amount came on-chain, it asks a Lightning invoice of the rest, declares it and publishes it for
   the checkout link's page
   ([§31](#the-rest-of-an-underpayment)), unless what came is short of the amount by no more than
   the merchant's tolerance ([§31](#the-merchants-tolerance)), or the merchant accepted what came
   ([§31](#the-merchants-acceptance)): the order is then paid.

sattle.me runs no server and no API. Payments go straight to the merchant's wallet. The
key can make invoices that pay the merchant and declare sales; it can never spend funds.

The customer's browser gets the invoice and the address alone, from the shop's page. Or, when the
integrator asks for it, a **checkout link** ([§30](#30-checkout-links)): a URL of the merchant's web
app, where the customer's browser reads the invoice from the relays, pays it, has its payment
checked, and is sent back to the shop once it is paid.

An implementation is made for a server that may live for one call: it keeps nothing between calls.
Each call reads the channel again (a removal stops the very next invoice), opens one connection
per relay and closes them when it is done.

## 2. Conventions

- **Bytes and hex**: hex is lowercase, two characters per byte. "Hex32" is 64 lowercase hex
  characters (32 bytes).
- **JSON**: RFC 8259, read the same way everywhere this document reads it (an answer, a record, a
  relay's message, a stored invoice), as JavaScript reads it: of members with one name, the last
  counts (names that differ in case are different names; a name may hold any character, U+0000
  included); a number is its value as an IEEE 754 double, rounded to the nearest, whatever its
  spelling and its length (beyond the largest double it is infinite: `1e400`, an integer of 400
  digits), so where this document asks for an integer, `500`, `500.0` and `5e2` are all 500, and an
  infinite number is none; a string may hold a lone surrogate (`"\ud800"`: [§11](#11-nostr-events)
  says where it matters); a boolean is never a number. Nothing else is JSON: no leading zero (`01`),
  no trailing comma, no whitespace but space, tab, line feed and carriage return, no byte order mark
  (but the one [§15](#15-http) ignores); nor a text in which more than 64 arrays and objects nest
  one in another, a depth every platform's parser reads without exhausting its stack, far beyond
  any this document reads. A member is `null` only when it is there with that value: where this
  document says that a member may be `null`, an absent one is invalid, unless it says that it may
  be absent. Strings in this document are written as JSON strings.
- **Time**: Unix seconds, integers. "Now" is the server's clock in seconds, rounded down. The
  server's clock MUST be synchronized (NTP): an invoice more than 300 s off is refused.
- **Majority** of `n` relays: `floor(n / 2) + 1`. Any two majorities of one list share a relay.
- **HKDF**: HKDF-SHA256 (RFC 5869), output 32 bytes, salt and info as UTF-8 bytes.
- **HMAC**: HMAC-SHA256.
- **Base64url**: RFC 4648 §5 without padding. **Base64**: RFC 4648 §4 with padding. Both are
  decoded **strictly**: only the canonical encoding of some bytes is accepted (unused trailing bits
  are zero, no whitespace, no other alphabet, padding exactly where §4 puts it). Many platform
  decoders are lenient (they skip unknown characters, accept both alphabets): do not use them as
  they are.

## 3. Data model

What the client gives and takes. Every object an integrator stores MUST be serialized as the JSON
below, with these field names, whatever the language: an invoice stored by one implementation is
checked by another. An implementation MAY expose idiomatic names in its own API (`bolt11` as a
property, `expires_at` in Python…) as long as its JSON uses the names below.

Every amount is a **string of digits** (sats, minor units), never a float. Every date is an
integer of Unix seconds. A value that is absent is written `null`, never left out
([§2](#2-conventions)).

### Invoice

What `createInvoice` returns: the integrator stores it with the order. The shop's page needs
`paymentUri` (or `bolt11` and `onchainAddress`) and `expiresAt` only; with a checkout link, the
shop sends its customer to `checkoutUrl` instead. An order is paid with a Lightning invoice, a
deposit address, or both ([§31](#31-on-chain-payments)): at least one of `bolt11` and
`onchainAddress` is not null.

| Field            | Type             | Meaning                                                                                      |
| ---------------- | ---------------- | -------------------------------------------------------------------------------------------- |
| `ref`            | string           | The order's reference.                                                                       |
| `bolt11`         | string or null   | The BOLT11 invoice, as the Lightning address wrote it; null for an order paid on-chain only. |
| `paymentHash`    | hex32 or null    | Its payment hash; null without `bolt11`.                                                     |
| `verifyUrl`      | string or null   | Its LUD-21 verify URL (https); null without `bolt11`.                                        |
| `onchainAddress` | string or null   | The deposit address the order leased ([§31](#31-on-chain-payments)); null without one.       |
| `paymentUri`     | string           | What to show as one QR code ([§31](#31-on-chain-payments)): `bitcoin:…` or `lightning:…`.    |
| `sats`           | string of digits | The amount, in sats: the invoice's, and what the address must receive.                       |
| `fiat`           | Fiat or null     | The order's price when given in a currency.                                                  |
| `rate`           | RateInfo or null | The rate `fiat` was converted at.                                                            |
| `note`           | string           | What the merchant's app shows: the note, else the reference.                                 |
| `createdAt`      | integer          | The invoice's date: its BOLT11 timestamp; without `bolt11`, when the address was leased.     |
| `expiresAt`      | integer          | When it can no longer be paid: `createdAt` + its expiry (BOLT11) or `durationSeconds`.       |
| `checkoutUrl`    | string or null   | Its checkout link ([§30](#30-checkout-links)), null without one.                             |
| `redirectUrl`    | string or null   | Where its checkout link sends the customer once it is paid.                                  |

### DeclaredInvoice

An invoice as the merchant's registry holds it (`findInvoices`, `InvoicePendingError`,
`OrderPaidError`): every field of an Invoice but `rate`, `checkoutUrl` and `redirectUrl`, plus
`declaredAt` (integer: the `created_at` of its declaration, else of its lease).

### InvoiceToCheck

What a payment check needs: `bolt11`, `paymentHash`, `verifyUrl`, `onchainAddress`, `sats`,
`expiresAt`, and with an address its order's `ref` (the witnesses of its payment are its order's
sale's for its `expiresAt`; its lease and its rest invoices, its order's sale's). An Invoice or a
DeclaredInvoice is one. Without `onchainAddress`, it reads as null.

### Fiat

| Field      | Type             | Example   |
| ---------- | ---------------- | --------- |
| `amount`   | string           | `"24.50"` |
| `currency` | string           | `"CHF"`   |
| `minor`    | string of digits | `"2450"`  |
| `digits`   | integer          | `2`       |

`amount` has exactly `digits` decimals ([§25](#25-prices-in-a-currency)).

### RateInfo

| Field       | Type            | Meaning                                                                              |
| ----------- | --------------- | ------------------------------------------------------------------------------------ |
| `source`    | string          | `"coingecko"`, `"mempool"`, `"opennode"`, `"coinbase"`, `"kraken"`, `"custom"`       |
| `currency`  | string          | ISO 4217.                                                                            |
| `price`     | string          | The price of one bitcoin, plain decimal, shortest ([§25](#25-prices-in-a-currency)). |
| `fetchedAt` | integer         | When the implementation read it.                                                     |
| `time`      | integer or null | When the source says the price was set.                                              |

### PaymentStatus

One of:

```text
{ "state": "open", "expiresAt": 1791379180, "received": "0", "rest": null }
{ "state": "open", "expiresAt": 1791379180, "received": "30000", "rest": <Rest> }
{ "state": "unconfirmed", "received": "49000", "confirmations": 1, "txids": ["<hex32>"] }
{ "state": "paid", "method": "lightning", "preimage": "<hex32>" }
{ "state": "paid", "method": "onchain", "received": "49000", "txids": ["<hex32>"] }
{ "state": "paid", "method": "mixed", "received": "49000", "txids": ["<hex32>"], "preimages": ["<hex32>"] }
{ "state": "expired", "received": "0" }
```

- `open`: not paid yet; it may still be, until `expiresAt`, and is reported up to 120 s later
  (on-chain: until then, [§31](#31-on-chain-payments); an invoice of its rest, made by a server
  whose clock runs ahead, up to 300 s later);
- `unconfirmed`: enough was received in time, on-chain by the transactions `txids` (and in
  Lightning by invoices of its rest), not deep enough yet (3 confirmations,
  [§31](#31-on-chain-payments)); not paid yet, it may still fail (a transaction replaced or
  dropped). Enough is the amount, or less within the merchant's tolerance
  ([§31](#the-merchants-tolerance)) or down to what the merchant accepted
  ([§31](#the-merchants-acceptance)), as for `paid` on-chain or mixed;
- `paid` with `method: "lightning"`: paid in Lightning; the preimage is the proof of payment, to
  keep;
- `paid` with `method: "onchain"`: paid on-chain, by the transactions `txids` (3 confirmations on
  the explorer read, [§31](#explorers));
- `paid` with `method: "mixed"`: paid on-chain by the transactions `txids` (3 confirmations on the
  explorer read), and in Lightning by invoices of the rest of that underpayment, whose preimages
  are `preimages` (the proofs of those payments, to keep); `txids` is empty when those invoices
  alone pay the amount ([§31](#the-rest-of-an-underpayment));
- `expired`: never paid, for good. One exception, the merchant's acceptance: when a relay that
  holds it fails at a check after the lease's end, that check may give `expired`, and a later
  one, which the relay answers, `unconfirmed`, then `paid` ([§27](#27-security)). An integrator
  that has cancelled the order then settles it by hand.

`received` is what the order received in time, in sats: on-chain to its address, and in Lightning
by invoices of the rest of an on-chain underpayment ([§31](#the-rest-of-an-underpayment)); `"0"`
without an address. Below `sats` in `open` and `expired`, where it is an underpayment the merchant
received; and in `unconfirmed` and `paid` (on-chain or mixed) when the merchant's tolerance
([§31](#the-merchants-tolerance)) or the merchant's acceptance
([§31](#the-merchants-acceptance)) accepted less than the amount: the order is paid all the same.

`rest` (of `open` only) is null unless `received` is above 0 before the invoice's end; then it is
what is left to pay, and how ([§31](#the-rest-of-an-underpayment)):

| Field        | Type             | Meaning                                                                                          |
| ------------ | ---------------- | ------------------------------------------------------------------------------------------------ |
| `sats`       | string of digits | `sats` − `received`: all that is left, whatever the tolerance or the merchant's acceptance.      |
| `bolt11`     | string or null   | A Lightning invoice of exactly that amount, declared for the order; null while there is none.    |
| `paymentUri` | string or null   | What to show as one QR code: `bitcoin:…` from 1 000 sats, else `lightning:…`; null with neither. |

### Merchant

`{ "businessName": <string>, "minSats": <string of digits>, "maxSats": <string of digits>,
"onchainAddresses": <integer> }`: `minSats` and `maxSats` are the Lightning address's sendable sats
([§16](#16-lightning-address)); `onchainAddresses` the number of addresses of the integration's lot
([§31](#31-on-chain-payments)), leased or not. Never the merchant's Lightning address: the app never
shows it to the integrator.

## 4. Client

The API every implementation offers, in its language's idiom (names, async style, cancellation).

### Construction

| Option            | Default              | Rule                                                                    |
| ----------------- | -------------------- | ----------------------------------------------------------------------- |
| `key`             | required             | The integration key ([§8](#8-the-integration-key)). Else `invalid_key`. |
| `rateSource`      | the default list     | A rate source, or a list of them ([§26](#26-rate-sources)).             |
| `coingeckoApiKey` | none                 | Optional: CoinGecko's Demo key, sent to CoinGecko only (below).         |
| `relayTimeoutMs`  | 10 000               | Per relay request, connection included: an integer, 100 to 60 000.      |
| `httpTimeoutMs`   | 10 000               | Per HTTP request, body included: an integer, 100 to 60 000.             |
| HTTP client       | the platform's       | Injectable, for tests and proxies.                                      |
| WebSocket client  | the platform's       | Injectable. It SHOULD cap a message at 1 MiB and bound the handshake.   |
| logger            | the platform's       | Warnings only; never given a secret.                                    |
| clock, randomness | system clock, CSPRNG | Injectable for tests only.                                              |

`coingeckoApiKey` is a string of 1 or more visible ASCII characters (U+0021 to U+007E), so that
its HTTP header carries it as it is ([§26](#26-rate-sources)); an empty string is invalid, not
absent. An invalid option fails construction with `invalid_option` naming it (`param`), before any
request.

### Methods

| Method                             | Does                                                                                                                        |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `merchant()`                       | Reads the channel, the Lightning address and the lot: a Merchant.                                                           |
| `createInvoice(order)`             | [§17](#17-creating-an-invoice): an Invoice, with its checkout link ([§30](#30-checkout-links)) when the order asks for one. |
| `getStatus(invoice)`               | [§22](#22-payment-check): a PaymentStatus.                                                                                  |
| `waitForPayment(invoice, options)` | [§23](#23-waiting-for-a-payment): a final PaymentStatus.                                                                    |
| `findInvoices(ref)`                | [§24](#24-finding-an-orders-invoices): DeclaredInvoices, oldest first.                                                      |

Every method takes a cancellation (an `AbortSignal`, a `CancellationToken`, a context…). A cancelled
call stops its requests and fails with the platform's cancellation, not with an error of
[§5](#5-errors).

An implementation whose calls run concurrently (threads, goroutines, tasks) calls what is injected
(the HTTP and WebSocket clients, the logger, the clock, the randomness) from several of them within
one call, and the relays of a publication past its majority ([§13](#13-relays)) may still use the
WebSocket client, the clock and the randomness after their call returned: its documentation says
so, and that what is injected must be safe to call so.

### Functions

| Function               | Does                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `currencyDigits(code)` | The decimals of the currency whose code is exactly `code` in `currencies.json` ([§25](#25-prices-in-a-currency)), an integer; none (`null`) for any other text. Vectors: `fiat.json`. |

It needs no key and reads nothing: a shop asks it, for one, whether it may offer its customers to
pay in its currency, and in how many decimals its prices go to `createInvoice`.

## 5. Errors

Every error an implementation raises, but for a cancellation, is one of these: a base error
(`SattlemeError`) with a stable `code` and `retryable` (whether the same call may succeed
later, unchanged). A message never holds a secret ([§27](#27-security)).

| Code                   | Retryable    | When                                                                                                                                              | Carries                                    |
| ---------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `invalid_key`          | no           | The key is not an integration key ([§8](#8-the-integration-key)).                                                                                 |                                            |
| `invalid_option`       | no           | An option of the client or of a call is invalid.                                                                                                  | `param`                                    |
| `invalid_order`        | no           | A parameter of the order, or a stored invoice, is invalid.                                                                                        | `param`                                    |
| `revoked`              | no           | The merchant removed the integration.                                                                                                             |                                            |
| `channel_not_found`    | unless newer | A majority of the relays answered without the channel.                                                                                            | `newerFormat`                              |
| `network`              | yes          | A relay, the Lightning address, a rate source or an explorer did not answer usably, or fewer than a majority of relays answered or took a record. |                                            |
| `invalid_invoice`      | no           | An invoice, a pay request or a payment answer failed the checks.                                                                                  |                                            |
| `invoice_pending`      | no           | An earlier invoice of the order may still be paid ([§21](#21-one-order-one-invoice-at-a-time)).                                                   | `invoice` (DeclaredInvoice), `checkoutUrl` |
| `order_paid`           | no           | An earlier invoice of the order was paid.                                                                                                         | `invoice`, `status`, `preimage`            |
| `unsupported_currency` | no           | None of the rate sources has a price in the currency.                                                                                             | `currency`                                 |
| `rate`                 | yes          | No usable price: invalid, too old, or a custom source failed ([§26](#26-rate-sources)).                                                           |                                            |
| `checkout_unavailable` | no           | A checkout link was asked, and the merchant's app gives no web app for it ([§30](#30-checkout-links)).                                            |                                            |
| `onchain_unavailable`  | yes          | The order can only be paid on-chain, and no address of the lot could be leased ([§31](#31-on-chain-payments)).                                    |                                            |

`param` is one of: `options`, `rateSource`, `coingeckoApiKey`, `fetch`, `WebSocket`,
`relayTimeoutMs`, `httpTimeoutMs`, `logger`, `now`, `random`, `intervalMs`, `onStatus` (for
`invalid_option`); `order`, `ref`, `sats`, `fiat`, `rateSource`, `durationSeconds`, `note`,
`checkout`, `redirectUrl`, `invoice` (for `invalid_order`). An implementation MAY name its own
options in its idiom. `checkoutUrl` of `invoice_pending` is the URL of a new checkout link to the
pending invoice when the order asked for one and that invoice may still be paid (step 1 of
[§21](#21-one-order-one-invoice-at-a-time)), else null. `status` of `order_paid` is the invoice's
`paid` PaymentStatus; `preimage` its preimage, null when it was paid otherwise than by its own
Lightning invoice (on-chain, or mixed).

## 6. Text

Platforms disagree on string length, trimming and case. Every implementation applies these rules,
not its platform's defaults:

- **Length** is counted in Unicode code points (not bytes, not UTF-16 units).
- **ASCII whitespace** is space, tab, line feed and carriage return (U+0020, U+0009, U+000A,
  U+000D), nothing else.
- **Trimming** removes ASCII whitespace only, and only where a rule says so: a note loses its
  leading and trailing spaces (U+0020); a Lightning address its leading and trailing ASCII
  whitespace; a business name is checked not empty once its ASCII whitespace is trimmed
  ([§14](#14-reading-the-channel), [§30](#30-checkout-links)). Nothing else is trimmed: a value with
  whitespace around it is refused.
- **Case**: only ASCII letters change case (A–Z ↔ a–z). Never Unicode case mapping (it lowers
  U+212A KELVIN SIGN to `k`).
- **UTF-8** is decoded strictly: invalid bytes make the value invalid, never U+FFFD. A byte order
  mark (U+FEFF, the bytes EF BB BF) is a character like any other, kept where it is (JavaScript's
  `TextDecoder` drops a leading one unless `ignoreBOM` is set); only an HTTP body ignores a
  leading one ([§15](#15-http)). Vectors: `integration-keys.json`.
- A text holding a lone surrogate (a code unit from U+D800 to U+DFFF outside a pair) is invalid
  wherever this document checks a text, on every platform: a JSON escape makes one (`"\ud800"`), in
  Python as in JavaScript, Java or C#.

## 7. Numbers

- Amounts are integers: sats, millisatoshis, minor units. No float ever holds an amount.
- Bounds: a BOLT11 amount is at most 21 000 000 BTC (2 100 000 000 000 000 000 msat), which fits a
  signed 64-bit integer; minor units are at most 2^53 − 1 (9 007 199 254 740 991), the largest
  integer every JSON reader holds exactly. An implementation MUST refuse what exceeds them, not wrap
  or round.
- The conversion of a price ([§25](#25-prices-in-a-currency)) needs integers beyond 64 bits:
  arbitrary precision (BigInteger, `bcmath`/`gmp`, Python's `int`).
- A price of one bitcoin is a decimal ([§25](#25-prices-in-a-currency)), never a float in
  arithmetic.

## 8. The integration key

```
sattleme_ck_<team>.<key>.<relays>
```

The prefix is `sattleme` for sattle.me and `ck` for checkout key. A later format of the key will
take another prefix (`sattleme_ck2_`), which an implementation of this version refuses.

- `<team>`: base64url of the team's public key (32 bytes, x-only, BIP-340): the author of the
  channel.
- `<key>`: base64url of the integration's key (32 bytes).
- `<relays>`: base64url of the UTF-8 of the relay hosts **without** `wss://`, joined by `,`. Each
  host `h` is the relay `wss://h`.

Parsing, in this order; any failure is `invalid_key`, and the message never holds the key:

1. The text starts with `sattleme_ck_` (nothing before it, no whitespace).
2. The rest splits on `.` into exactly three parts.
3. Each part decodes as strict base64url ([§2](#2-conventions)).
4. `<team>` and `<key>` are 32 bytes each; `<team>` is the x coordinate of a point of secp256k1
   (BIP-340 `lift_x` succeeds).
5. `<relays>` is not empty, is valid UTF-8, and `wss://` + each host makes a valid relay list
   ([§9](#9-relay-lists)).

The key is a secret ([§27](#27-security)). **One key, one shop**: the merchant creates an
integration for each shop (each system with its own orders' references), and two shops never share a
key. The sale of an order is derived from the key and the order's reference
([§10](#10-key-derivations)): two shops with one key share their references, and an order of one
would be found paid, or pending, with an invoice of the other
([§21](#21-one-order-one-invoice-at-a-time)). The servers of one shop share its key.

## 9. Relay lists

A relay address in its one spelling:

- `wss://` (lowercase), then a host: two labels or more of `a–z 0–9 -` separated by `.`, the last of
  at least two letters `a–z` and not `localhost` (so no IP address, no name of one label such as
  `intranet`, no `localhost` nor a name under it, which RFC 6761 gives the machine's own loopback,
  no upper case), at most 253 characters;
- an optional port `:` followed by 1 to 5 digits, 1 to 65535;
- an optional path: `/` then any characters but whitespace, `?`, `#` and `,`, not ending with `/`.
  Whitespace is ECMAScript's (the merchant's app checks with JavaScript's `\s`): U+0009 to U+000D,
  U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF. Other
  non-ASCII characters are allowed (`wss://relay.example/bücher`);
- 120 code points at most in all (the app counts UTF-16 units, never fewer: whatever it writes is
  read).

A relay list is 1 to 10 such addresses, none twice. A list or an address that is not so is
refused, never repaired. Vectors: `relay-urls.json`, `integration-keys.json`.

## 10. Key derivations

These never change: the merchant's app derives the same keys.

| Name                    | Derivation                                                                          |
| ----------------------- | ----------------------------------------------------------------------------------- |
| channel address (`d`)   | hex(HKDF(integration key, `sattle.me/integration`, `channel/address/v1`))           |
| channel encryption key  | HKDF(integration key, `sattle.me/integration`, `channel/encryption-key/v1`)         |
| taker key               | HKDF(integration key, `sattle.me/integration`, `taker/v1`)                          |
| sale key of `ref`       | HKDF(integration key, `sattle.me/integration`, `sale/<ref>/v1`)                     |
| sale secret             | HKDF(sale key, `sattle.me/sale`, `nostr-secret-key/v1`)                             |
| sale author             | hex(BIP-340 x-only public key of the sale secret)                                   |
| taker tag               | hex(first 16 bytes of HMAC(taker key, bytes of the sale author))                    |
| registry address of `H` | hex(HMAC(registry key, bytes of payment hash `H`))                                  |
| outer key               | HKDF(registry key, `sattle.me/registry-declaration`, `outer/v1/<address>/<author>`) |
| inner key               | NIP-44 v2 conversation key (ECDH) of the sale secret and the registry reader        |

`<ref>`, `<address>` and `<author>` are written in the info as they are (ASCII). The sale secret
is used as a secp256k1 secret key as is (an HKDF output is a valid key but with negligible
probability).

Vectors: [`vectors/app/app.json`](vectors/app/app.json) (made by the merchant's app: key, every
derived value, a channel, a declaration, a real breez.tips invoice) and
[`vectors/app/implementation-declaration.json`](vectors/app/implementation-declaration.json) (a
declaration made by an implementation of this document, read by the app).

## 11. Nostr events

Events are NIP-01 events. An implementation:

- computes an event's `id` as SHA-256 of the UTF-8 of the JSON array
  `[0, pubkey, created_at, kind, tags, content]` serialized as NIP-01 says (no whitespace), its
  numbers written as integers whatever their spelling in what the relay sent ([§2](#2-conventions):
  a `created_at` sent as `1791378000.0` is written `1791378000`), its strings as JavaScript's
  `JSON.stringify` writes them: `"` and `\` as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C and
  U+000D as `\b`, `\t`, `\n`, `\f` and `\r`; any other character below U+0020 as `\u` and four
  lowercase hex digits (`\u001f`); every other character as it is (`/`, `<`, U+007F, U+2028, `é`: no
  escape). NIP-01 names the first seven escapes only; JSON (RFC 8259) escapes every character below
  U+0020. Vectors: `nostr-events.json`;
- signs with BIP-340 Schnorr, with 32 fresh random bytes of auxiliary data;
- **checks** an event from a relay before using it: `id` and `pubkey` hex32, `sig` 128 lowercase
  hex characters, `created_at` a safe integer (≤ 2^53 − 1), `kind` an integer, `content` a string,
  `tags` an array of arrays of strings, no string of `content` or `tags` holding a lone surrogate
  ([§6](#6-text): its UTF-8, which the hash needs, does not exist); then that `id` is the hash above
  and `sig` verifies. An event **checks out** when it passes all of these. A relay is never trusted:
  anything else is ignored.

## 12. Sealed records

Every record (the channel, a declaration, a checkout link, a lot, a lease, a witness, a rest record,
an acceptance record, a merchant's acceptance) is an event of kind 30078 (NIP-78) with a tag `["d",
<address>]` and a NIP-44 v2 content. A checkout link's, a rest record's and an acceptance record's
events also have an `["expiration", <Unix seconds>]` tag (NIP-40, [§30](#30-checkout-links)), a
witness's `["o", …]` tags ([§31](#witnesses)); no other record has more than the `d` tag.

**Sealing**: the plaintext is the JSON `{"t": <type>, "v": <value>}` followed by spaces (U+0020)
up to the next multiple of 256 bytes (none when it is one already), encrypted with NIP-44 v2 under
the record's conversation key, with a fresh random nonce.

**Opening** a value a relay sent, as a record of a type, address, author and key; in this order
(the cheap checks first):

1. `kind` is 30078, `pubkey` is the author, `content` is a string, `tags` holds `["d", <address>]`
   (other tags are ignored).
2. The content decrypts (NIP-44 v2, below). An empty payload, one whose first character is `#`,
   or one whose version byte is not 2, is of a **newer format** once its event checks out (step 4),
   and is ignored otherwise: the record is then authentic but unreadable.
3. The plaintext parses as JSON (the trailing spaces are whitespace), is an object holding `v`,
   and its `t` is the type.
4. The event checks out ([§11](#11-nostr-events)).
5. The value is validated (per record). A value with a `version` number above the one known is of
   a newer format.

Anything that fails is ignored. A record is of a newer format only once its event checks out:
anybody can send an event with the author's `pubkey`, the `d` tag and a content such as `#`, never
with the author's signature. An implementation may decrypt before it checks the event (the cheap
check first), but never counts a newer format before step 4 passed. A record of a newer format is
never used, never written over, and makes the implementation log a warning (update the
implementation). An implementation knows the records the relays that answered its read sent: one
that only relays which did not answer hold may still be written over there, since reads go on at a
majority ([§13](#13-relays)). A newer format keeps the tags of its record as this version writes
them (its `d` tag, a witness's `o` tags, the `expiration` tag), whatever its content: an earlier
implementation reads them of a record it cannot open (where it is, which address a witness names:
[§31](#leasing-an-address), step 3). The leases of deposit addresses, which anybody may write, open
by rules of their own ([§31](#leases)).

**NIP-44 v2** as https://github.com/nostr-protocol/nips/blob/master/44.md, with its official test
vectors. Decryption refuses: a payload shorter than 132 or longer than 87 472 characters; one that
is not strict padded base64; decoded data shorter than 99 or longer than 65 603 bytes; a wrong MAC
(compared in constant time); a wrong padding; a plaintext that is not valid UTF-8. A payload whose
first character is `#`, or whose version byte is not 2, is no refusal here: it is of a newer format
(Opening, step 2). The channel's and the outer declaration's conversation keys are HKDF outputs used
as they are (no ECDH); only the inner declaration uses the ECDH conversation key.

## 13. Relays

NIP-01 and NIP-42 over WebSocket.

- **One connection per relay per call**, opened at its first request and closed when the call is
  done. Every request of the call (channel, declarations page after page, publication) uses it.
  The opening handshake follows no redirect: a redirect (3xx) is a failed connection, as in
  [§15](#15-http) (it would skip the checks of [§9](#9-relay-lists)); it carries the User-Agent
  of [§15](#15-http).
- **Timeouts**: each request (a page of a read, a publication), the wait for the connection
  included, is bounded by `relayTimeoutMs`.
- **Reads**: every relay of the list at once; the read goes on as soon as a majority of them
  answered, or once every relay answered or failed. The others are dropped then: their requests
  end, and they ask nothing more (no page, no authentication). Fewer than a majority is no answer
  (`network`), never an absence.
- **A query**: `["REQ", <id>, <filter>]` with a random subscription id (8 random bytes, hex: it
  names nothing of the integration). The events until `EOSE` are its answer (then `CLOSE`). At most
  1000 events are read for one query: the 1000th ends it (then `CLOSE`), as an `EOSE` would.
  `["CLOSED", <id>, <reason>]` ends it as a failure, unless authentication lifts it (below).
- **Paged reads** (a sale's declarations): the first page with the filter; then, while the last page
  held an event with a string `id` and a safe integer `created_at`, the next page with `until` = the
  oldest `created_at` of those events, minus 1 when none of them was new to the read. These two
  members of an event page the read whatever else it holds (one that does not check out pages it all
  the same); an event without them is not kept. At most 20 pages. Events are kept once per `id`, the
  first of the read. A failure after the first page keeps what was read; a failure of the first page
  is the relay's failure.
- **Complete reads** (the leases of deposit addresses, [§31](#leasing-an-address)): anybody may
  write an event at a lease's `d` tag, so such a read never stops short unnoticed. The filter has
  `"limit": 100`: the first page with it, then the next page with `until` = the oldest `created_at`
  of the last page's events with a string `id` and a safe integer `created_at` (that second may hold
  more events than the page did). A page is **full** when it holds 100 events. A relay's read is
  **complete** at a page that is not full (an empty one included). It stops **incomplete** at a page
  that fails (the first one: the relay failed), that holds more than 100 events (the relay ignored
  the limit), or that is full and holds no event with a string `id` and a safe integer `created_at`,
  or no event with a string `id` not seen before in this read, dated or not (one second holds more
  events than a page), and at a 20th page that is full. The read goes on as soon as a majority of
  the relays read completely, or once every relay's read ended (complete or not) or failed; it is
  **complete** when a majority read completely. Events are kept once per `id`, from every relay
  whose read ended by then, complete or not (the others' are dropped). It relies on relays that
  answer a filter with a `limit` with their newest events, as many as the limit when they hold as
  many (NIP-01 lets a relay send fewer): the merchant's relays are such relays
  ([§27](#27-security)); strfry (up to its `maxFilterLimit`, 500 by default) and nostr-rs-relay are.
- **Reads on every relay** (a lease's confirmation, the witnesses read again and the merchant's
  acceptance, [§31](#31-on-chain-payments); the choice among several invoices of an order,
  [§21](#21-one-order-one-invoice-at-a-time)): the same read, but it does not go on as soon as a
  majority answered (read completely, for a complete read): it goes on once every relay did or
  failed, or `relayTimeoutMs` after a majority did, whichever comes first; a complete one also as
  soon as a majority can no longer read completely (it is then not complete). It keeps, besides the
  events of the relays whose read ended, the pages that a relay still reading had sent by then (the
  pages that ended: of a read that is not paged, nothing of a relay still reading); but only a relay
  whose read ended (complete or not) **answered**: one still reading has not, whatever it sent. A
  relay a request to which ran out of time, or whose connection failed, earlier in the call counts
  as failed at once. Fewer than a majority answered is still `network`; a complete read is still
  complete when a majority read completely. So a relay that hides a record it holds cannot hide it
  from such a read while a relay that holds it answers in time ([§27](#27-security)); a slow relay
  delays such a read by one `relayTimeoutMs` at most, and one that failed is not waited for again in
  the call.
- **Publication**: `["EVENT", <event>]` to every relay of the list at once; a relay took it when
  it answers `["OK", <id>, true, …]`. It succeeds once a majority took it, and fails as soon as a
  majority no longer can. The relays past the majority MAY be awaited, up to their timeout, before
  the connections close, while or after the call returns: each one's request goes on as within the
  call (with NIP-42's one authentication and the one write again, below), and nothing more; a
  single-threaded implementation MAY simply close them.
- **NIP-42**: a relay may send `["AUTH", <challenge>]` at any time; the last challenge counts. When
  a query is `CLOSED`, or a publication refused (`OK` false), with a reason starting with
  `auth-required:`, the implementation authenticates and asks once more. Authentication sends
  `["AUTH", <event>]` (NIP-42's message, never an `EVENT`), its event of kind 22242, `created_at`
  now, tags `[["relay", <relay URL>], ["challenge", <challenge>]]`, content `""`, signed by the key
  of that read or write, and succeeds when the relay answers `["OK", <its id>, true, …]`. One
  authentication per key and challenge per connection. Its wait for that `OK` is part of the
  request's time: a request that runs out of time there ran out of time (Timeouts).
  The key: for the channel, the lot, the leases of the lot's addresses, the witnesses, the
  merchant's acceptance, the rest records and the acceptance records, 32 fresh random bytes (a key
  of that read alone); for a
  sale's declarations and leases (read or write), the sale secret; for a witness's publication,
  the seen secret ([§31](#31-on-chain-payments)); for a checkout link's publication, its author's
  secret ([§30](#30-checkout-links)); for a rest record's or an acceptance record's publication,
  the rest secret ([§31](#the-rest-of-an-underpayment)).
- **Limits**: a message larger than 1 MiB SHOULD be refused by the WebSocket client, which SHOULD
  NOT offer compression (permessage-deflate, RFC 7692): a few compressed bytes unpack into many
  large messages, held at once before reading pauses, and sealed records do not compress. An
  implementation MUST keep of each event only what its read needs, as the event comes: its `id` (one
  longer than 64 characters MAY be kept as its SHA-256: the same `id`, the same hash, and no event
  of such an `id` checks out, [§11](#11-nostr-events)) and its date (to page the read and count each
  event once), and, when it opens ([§12](#12-sealed-records): its event checked out), the event and
  what it opens to, of the event its NIP-01 members only (`id`, `pubkey`, `created_at`, `kind`,
  `tags`, `content`, `sig`: a relay may add any other member to an event that checks out, its `id`
  and `sig` covering none); of a lease, which opens without its signature ([§31](#leases)), only its
  `id`, author, date and signature and what holding needs of its outside (its `end`, or that it is a
  withdrawal or of a newer format), never its tags nor its content; any other event is dropped
  there. Of one relay's answer to a query, the first event of each `id` is the one read: a later one
  of that `id` (a copy, or a forgery) only counts toward the query's 1000 events, nothing of it
  kept, opened or checked. So what a relay sends never piles up, whatever its size: a read keeps a
  bounded count of events (1000 for a query, 20 pages for a paged or complete read) of a few bytes
  each, besides the records that open, one copy of each per relay, which only the holders of their
  keys sign (a copy of a record under an `id` of its own, its signature left as it is, does not
  check out; a copy of a lease opens, and is kept as a lease is). A relay's answer is never cut at a
  size: events that anybody wrote at a lease's `d` tag end a read of leases incomplete, as above,
  never failed. Reading what a relay or a server sends (a message, an answer) MUST cost time linear
  in its size: a JSON reader whose cost grows faster (with the square of a string's escapes, say)
  lets anybody who writes events at a lease's `d` tag make every read of leases run out of time.

## 14. Reading the channel

The channel is a sealed record ([§12](#12-sealed-records)) of type `team-channel`, author the
team, address the channel address, key the channel encryption key ([§10](#10-key-derivations)).

**Lookup on a list**: query `{"kinds": [30078], "authors": [<team>], "#d": [<channel address>]}`
([§13](#13-relays)), not paged. Fewer than a majority answered: unreachable. Then open every event
received (one opening per event `id` that checked out) and keep the newest valid copy: the highest
`created_at`, then the lowest `id` (as relays keep it). If a copy of a newer format is newer than
it, log a warning. No valid copy: not found (with a newer-format flag when one was seen).

**A valid channel value**:

- `version` is 1 (a number above 1: newer format) and `updatedAt` equals the event's
  `created_at`;
- `status: "removed"`: the integration is removed; or
- `status: "active"`, `role: "integration"`, and:
  - `profile` an object, `profile.businessName` a string not empty once ASCII whitespace is
    trimmed, at most 200 code points;
  - `profile.lightningAddress` a valid Lightning address ([§16](#16-lightning-address));
  - `registryKey` hex32; `registryReader` hex32 and the x coordinate of a point of secp256k1;
  - `relays` absent, or a valid relay list ([§9](#9-relay-lists));
  - `checkout` absent, or an object whose `origin` gives the merchant's web app for checkout links
    ([§30](#30-checkout-links)): a `checkout` that is not an object, or whose `origin` is not a
    valid checkout origin, gives none, and leaves the channel valid. The merchant's app writes it
    when its version has a web app;
  - `onchainTolerance` absent, or the merchant's tolerance of on-chain underpayments
    ([§31](#the-merchants-tolerance)): an integer from 0 to 1000 (basis points); absent, or
    anything else, it is 0 (none), and the channel stays valid. The merchant's app writes it when
    the merchant sets one.
  - `bitcoinNode` absent, or the merchant's Bitcoin node ([§31](#the-merchants-bitcoin-node)): an
    object, not an array, whose `url` is a node URL, whose `fallback` is exactly `"mempool"` or
    `"none"` and whose `payers` is a JSON boolean, `true` only for a node of the Internet (its
    other members ignored); absent, or invalid in any way, there is none (the server reads
    mempool.space), and the channel stays valid. The merchant's app writes it when the
    merchant sets one. A reader that does not know it ignores it (below): it is no new version of
    the channel.
- Other fields are the app's own and MUST be ignored (so that a change to them never stops a shop).

**Reading the channel**:

1. Look up on the key's relays. Unreachable: `network`. Not found: `channel_not_found` (with
   `newerFormat`).
2. While the channel is active and names a relay list other than the one read (same addresses in
   the same order is the same list), look up on that list, 3 times at most: unreachable is
   `network`; not found keeps the channel read so far (it was not copied there yet); found replaces
   it.
3. A removed channel: `revoked`. Every call that reads the channel then fails so: making an invoice,
   finding an order's invoices, reading the merchant, and the on-chain part of a check, which reads
   the merchant's relays: the check of an invoice with an address (and the wait for it) is `revoked`
   unless its Lightning invoice is paid ([§22](#22-payment-check)), as for every other failure of
   its on-chain part (`network`, `channel_not_found`): a paid invoice proves itself, and the status
   combines the parts so ([§31](#the-on-chain-payment)). The check of an invoice without an address
   reads no relay and goes on: its verify URL is the Lightning address's, and needs nothing of the
   key. The shop learns nothing more of its on-chain payments from the key: the merchant settles by
   hand the orders still being paid on-chain (their payments reach the wallet as any other).

The merchant's relays, where declarations go, are the channel's `relays`, else the key's.

## 15. HTTP

Every HTTP request is a GET with `Accept: application/json` and
`User-Agent: sattleme-Checkout/1` (to the Lightning address, the rate sources and the
explorers), that User-Agent the same in every implementation and version: CoinGecko refuses a
request without one (HTTP 403), and one naming an implementation's language or version would only
help a server single it out. The opening handshake of a WebSocket (a relay's, [§13](#13-relays);
the explorer's, [§31](#explorers)) carries that User-Agent too, in place of any the WebSocket
client would send: some relays refuse a handshake without one (HTTP 403).

- **No redirect is followed**: every URL is checked before it is asked; a redirect would skip the
  check. A redirect (3xx) is no answer: `network`.
- **An https URL** (a pay URL, a callback, a verify URL, [§16](#16-lightning-address); every
  `verifyUrl`): a string of 1 to 2048 characters, each one a redirect URL may hold
  ([§30](#redirect-urls): `A–Z a–z 0–9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; =`, or `%` followed
  by two hex digits), that is `https://`, a host as in a relay address ([§9](#9-relay-lists)), an
  optional port (`:` then 1 to 5 digits, 1 to 65535), then nothing, or `/`, `?` or `#` followed by
  anything: rule 1 of a redirect URL. So no upper case in the scheme or the host, no user name nor
  password, no IP address, no `localhost` nor a name under it, no whitespace, no `\`; nothing is
  repaired. Its port is 443 when absent. Two https URLs are on the **same host** when their hosts
  and their ports are equal. Vectors: `https-urls.json`.
- **The merchant's Bitcoin node** ([§31](#the-merchants-bitcoin-node)) is asked under every rule of
  this section (no redirect followed, the timeout, the bounds of the head and the body, the
  User-Agent, its WebSocket's handshake included), but for the https URL: its URL follows a rule of
  its own, which allows `http` and an IPv4 address.
- **Timeout**: `httpTimeoutMs` for the whole request, body included.
- **Head**: what the client holds of its status line, its headers, and a chunked body's size
  lines and trailers is bounded too, 10 MiB at most in all, the body's own bytes not counted (they
  have their bound, below); and so is what it holds of the answer to the opening handshake of a
  WebSocket ([§13](#13-relays)), its status line and headers (HTTP libraries bound them so, most far
  lower; a client that holds them without a bound is given one): a larger head is no answer
  (`network`). What a parser reads without holding it (a chunk size's leading zeros, an extension
  it skips) is bounded by the timeout alone.
- **Body**: read up to 1 MiB (1 048 576 bytes); a larger body is no answer (`network`). One
  leading byte order mark (U+FEFF, the bytes EF BB BF) is ignored, as WHATWG's UTF-8 decode (and so
  `fetch`) ignores it. The body is JSON in UTF-8; a body that is not (invalid UTF-8, not JSON) is
  read as "no JSON". One exception: an explorer's height is plain text
  ([§31](#31-on-chain-payments)).
- No answer (connection, TLS, timeout): `network`.

## 16. Lightning address

LUD-16, LUD-06, LUD-12, LUD-21.

**A Lightning address**: the text with its leading and trailing ASCII whitespace
([§6](#6-text)) removed and its ASCII letters lowered must match
`^([a-z0-9\-_.+]+)@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$`, and its pay URL,
`https://<domain>/.well-known/lnurlp/<name>`, must be an https URL ([§15](#15-http)): so its
domain is a host as in a relay address, never an IP address. Vectors: `https-urls.json`.

**An LNURL answer** to a request is classified by its HTTP status and body:

1. the status is 2xx, or 4xx but 408 and 429, and the body is an object whose `status` is a string
   equal to `ERROR` ignoring ASCII case: a **refusal**, with its `reason` (a string, else `""`);
2. else, the status is not 2xx, or the body is not a JSON object: `network`;
3. else: the answer's object.

**The pay request** (GET of the pay URL): a refusal is `network`. Its object MUST have
`tag: "payRequest"`, `callback` an https URL, `minSendable` and `maxSendable` non-negative safe
integers (JSON numbers, millisatoshis, whatever their spelling: `1000.0` and `1e3` are 1000) with
min ≤ max, and `metadata` a string holding no lone surrogate ([§6](#6-text): its UTF-8 is hashed);
else `invalid_invoice`. `commentAllowed` is that number when it is a safe integer at least 0, else 0
(absent, negative, not an integer, not a number). The invoices of this address have the description
hash SHA-256(UTF-8 of `metadata`), `metadata` the string the body's JSON gives: its text, itself
JSON, is never read (an escape in it is hashed as it is written). Vectors: `pay-requests.json`.

**Sendable sats**: `ceil(minSendable / 1000)` to `floor(maxSendable / 1000)`.

## 17. Creating an invoice

### The order

| Parameter         | Rule                                                                                                                                                                                                                                                           |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ref`             | 1 to 64 characters `A–Z a–z 0–9 . _ : -`. One order, one sale: never reused for another order by anything that holds the key (a test copy of the shop, a restored database included), never taken from what the customer sends ([§8](#8-the-integration-key)). |
| `sats`            | A string of 1 to 18 digits (or the platform's integer), from 1 to 2 100 000 000 000 000 (21 000 000 BTC).                                                                                                                                                      |
| `fiat`            | Or `{ "amount": <string>, "currency": <string> }` ([§25](#25-prices-in-a-currency)). Exactly one of the two.                                                                                                                                                   |
| `rateSource`      | Only with `fiat`: this order's rate source, or list of them ([§26](#26-rate-sources)); else the client's.                                                                                                                                                      |
| `durationSeconds` | An integer, 60 to 3600; 900 when absent.                                                                                                                                                                                                                       |
| `note`            | Optional: a string without control characters (U+0000–U+001F, U+007F); its leading and trailing spaces (U+0020) are removed; empty, it is absent. At most 100 code points once trimmed.                                                                        |
| `checkout`        | Optional: a boolean, false when absent. True asks for a checkout link ([§30](#30-checkout-links)).                                                                                                                                                             |
| `redirectUrl`     | Optional, only with `checkout` true: a redirect URL ([§30](#30-checkout-links)). Absent or null: the checkout link sends the customer nowhere.                                                                                                                 |

The **label** is the note, else the reference: the declaration's note, the invoice's comment and
the Invoice's `note`. Every refusal is `invalid_order` naming the parameter: `redirectUrl` given
(not null) while `checkout` is not true is refused, never ignored. Vectors: `order-text.json`,
`fiat.json`, `rate-sources.json`, `redirect-urls.json`.

### The steps

1. Check the order (above), before any request.
2. Read the channel ([§14](#14-reading-the-channel)). With `checkout`: the channel gives no checkout
   origin, `checkout_unavailable`.
3. At the same time: check the earlier invoices of the order
   ([§21](#21-one-order-one-invoice-at-a-time)); ask the pay request
   ([§16](#16-lightning-address)); for `fiat`, ask the rate of its sources ([§26](#26-rate-sources)). An error of
   the earlier invoices' check wins over the other two.
4. The amount: `sats`, or the conversion of `fiat` at the rate ([§25](#25-prices-in-a-currency));
   above 2 100 000 000 000 000, `invalid_order` (`fiat`). Its methods
   ([§31](#31-on-chain-payments)): Lightning, on-chain, or both. Below 1 000 sats and outside the
   sendable sats: `invalid_order` (`sats` or `fiat`).
5. With Lightning, ask the invoice: GET `callback` with the query parameters `amount` = sats × 1000
   and `expiry` = `durationSeconds`, and `comment` = the label when its UTF-8 is at most
   `commentAllowed` bytes (LUD-12 does not say how a comment's length counts: bytes are never fewer
   than characters). The callback's own query parameters are kept, and its fragment (from its first
   `#`) is dropped: the parameters added after it would never reach the server. A refusal is
   `network`. The answer MUST have `pr` and `verify` strings, else `invalid_invoice`.
6. Check the invoice ([§18](#18-invoice-checks)). An invoice whose declaration
   ([§20](#20-the-declaration)) or, with on-chain, whose lease ([§31](#leases): it holds the
   invoice too, sealed twice, as the declaration) does not fit a NIP-44 plaintext (65 535 bytes) is
   `invalid_invoice`, before anything is published. The lease is measured as first published, with
   `"confirmed": false`, the longer of its two forms, and with any deposit address: they are all of
   one length ([§31](#31-on-chain-payments)).
7. With on-chain, lease an address ([§31](#31-on-chain-payments)): its lease ends at the invoice's
   `expiresAt` + 120 (without Lightning, `expiresAt` = now + `durationSeconds`), and holds the
   channel's tolerance ([§31](#the-merchants-tolerance)). No address: Lightning only, or
   `onchain_unavailable` when the order can only be paid on-chain.
8. With `checkout`: publish its checkout link ([§30](#30-checkout-links)) on a majority of the
   merchant's relays, else `network`.
9. With Lightning, declare the invoice ([§20](#20-the-declaration)) on a majority of the merchant's
   relays. Else `network`: the invoice MUST NOT be shown.
10. Return the Invoice: with Lightning, `bolt11` = `pr`, `verifyUrl` = `verify`, `createdAt` = the
    BOLT11 timestamp, `expiresAt` = timestamp + expiry; without, those three null, `createdAt` =
    now (the `created_at` of its lease as first published, not of its mark) and `expiresAt` =
    now + `durationSeconds`. `onchainAddress` the leased address, else null; `paymentUri`
    ([§31](#31-on-chain-payments)). With `checkout`, `checkoutUrl` its link's URL and
    `redirectUrl` the order's (null when absent); without, both null.

An invoice's address is leased before its link and its declaration: when the lease fails, neither
is published. A lease that is not confirmed is withdrawn, and never gives its invoice an address; a
failure after its confirmation (its mark, the link, the declaration) leaves it as it is: it holds
its address until its end ([§31](#leasing-an-address)).
The link is published before the declaration: when the link fails, nothing is declared and the
same order gets a new invoice at once; when the declaration fails, the link's URL was never given
and its keys are forgotten, so nobody can open it. Its URL is given only once both are on a
majority: the customer only ever opens the link of a declared invoice.

Within one client, calls for the same `ref` run one after the other (otherwise two would both pass
step 3, and their records of one address, of one author, would replace each other). Across
processes, the integrator locks the order (in its database) around `createInvoice`. In a store whose
reads may lag behind its writes (an eventually consistent one, as some hosted platforms give), the
lock and what it protects are read with reads that see the latest writes (consistent reads).

## 18. Invoice checks

In this order; the first that fails is `invalid_invoice` (vectors: `invoice-checks.json`, where
each case names its check):

| Check              | Rule                                                                 |
| ------------------ | -------------------------------------------------------------------- |
| `bolt11`           | `pr` decodes ([§19](#19-bolt11)).                                    |
| `network`          | Its network is `bc` (mainnet).                                       |
| `amount`           | Its amount is exactly sats × 1000 msat.                              |
| `description_hash` | Its description hash is SHA-256(`metadata`): it pays this merchant.  |
| `verify_url`       | `verify` is an https URL on the callback's host ([§15](#15-http)).   |
| `duration`         | Its expiry is at most `durationSeconds`.                             |
| `expired`          | Its expiry is above 0.                                               |
| `clock`            | Its timestamp is within 300 s of now (`abs(timestamp − now) ≤ 300`). |
| `expired`          | timestamp + expiry is after now.                                     |

## 19. BOLT11

As https://github.com/lightning/bolts/blob/master/11-payment-encoding.md, decoding what the checks
need. The signature is not verified: the payee is the LNURL server's node, which nothing here can
check; the description hash ties the invoice to the merchant instead.

- Bech32 (BIP-173) without its 90-character limit: US-ASCII characters 33 to 126 alone, either
  all lowercase or all uppercase in ASCII's case (never mixed), nothing around it. Unicode's case
  mapping reads the Kelvin sign (U+212A) as `k`: a text with it is no invoice.
- Human-readable part `ln` + network (`bc`, `tb`, `tbs`, `bcrt`) + an optional amount: digits
  without a leading zero and an optional multiplier `m`, `u`, `n`, `p`. In millisatoshis: no
  multiplier × 10^11, `m` × 10^8, `u` × 10^5, `n` × 10^2, `p` ÷ 10 (refused unless whole). No
  digits: no amount (a multiplier alone is refused). Above 21 000 000 BTC: refused.
- Data: 7 words of timestamp, tagged fields, 104 words of signature. A field is a tag word, two
  words of length (`32 × a + b`), then its data; a field running past the signature is invalid.
- `p` (1, payment hash) and `h` (23, description hash): only a field of 52 words counts; others are
  skipped; **the first** of each counts. `x` (6, expiry): any `x` field of more than 7 words makes
  the invoice invalid; **the last** counts (as the merchant's app reads it). No `p`: invalid. No
  `x`: 3600 s.

Vectors: `bolt11.json`.

## 20. The declaration

So that the payment of the invoice counts for this order's sale and for no other: the merchant's
app counts a payment declared by two sales for neither.

The declaration, JSON:

```json
{
  "version": 1,
  "invoice": "<pr>",
  "verifyUrl": "<verify>",
  "sale": {
    "key": "<sale key, hex>",
    "fiat": { "minor": 2450, "digits": 2, "currency": "CHF" },
    "note": "<label>"
  },
  "taker": "<taker tag>"
}
```

- `fiat`: the order's price, `minor` as a JSON **number**; for an order in sats,
  `{"minor": <sats>, "digits": 0, "currency": "SAT"}`.
- `rest`: only in the declaration of an invoice of the rest of an on-chain underpayment
  ([§31](#the-rest-of-an-underpayment)), after `taker`: the invoice whose rest it is,
  `{"address": <its deposit address>, "expiresAt": <its expiresAt, a JSON number>}` (an address is
  leased again for a later invoice of the order once nothing paid it: the end tells them apart).
  Absent (never `null`) from any other declaration. A reader that does not know it (the merchant's app, which
  counts the payment for the sale either way) ignores it, as any field it does not know; so it is
  no new version of the declaration.
- **Inside**: `sealed` = NIP-44 v2 of that JSON under the inner key ([§10](#10-key-derivations)).
- **Outside**: a sealed record ([§12](#12-sealed-records)) of type `registry-declaration`, value
  `{"sealed": <sealed>}`, address the registry address of the payment hash, key the outer key,
  signed by the sale secret, `created_at` now.

It is published on every relay of the merchant's list ([§13](#13-relays)) and succeeds on a
majority.

**Opening** a declaration of a sale (reading them back, [§21](#21-one-order-one-invoice-at-a-time)):
its `d` tag is hex32; it opens as a record of type `registry-declaration` with the outer key of that
address and the sale author; the outside value holds a string `sealed`, which decrypts with the
inner key into a JSON object; `version` is 1 (above: newer format); `invoice` a string; `verifyUrl`
an https URL; `sale` an object whose `key` is the sale key (hex) and whose `note` is a string;
`sale.fiat` has `minor` a safe integer from 0 to 2^53 − 1, `digits` an integer from 0 to 8,
`currency` three letters `A–Z`; the invoice decodes on network `bc` with an amount above 0 and a
whole number of sats; `rest` absent, or an object whose `address` is a deposit address
([§31](#31-on-chain-payments)) and whose `expiresAt` is a safe integer from 0 (more fields
ignored); and the `d` tag is the registry address of its payment hash.

## 21. One order, one invoice at a time

An order has one invoice that may be paid at a time, checked against the registry, so that it holds
even when the shop lost what it stored.

**The sale's declarations**: query `{"kinds": [30078], "authors": [<sale author>]}`, paged
([§13](#13-relays)), on the merchant's relays; fewer than a majority answered: `network`. Open each
event (one opening per event `id` that checked out) as a declaration ([§20](#20-the-declaration)),
else as the sale's lease ([§31](#31-on-chain-payments), opened as the sale); keep one declaration
per payment hash and one lease per address (the newest record of the sale at its registry address: a
withdrawal, or a record of a newer format, leaves none). A declaration with `rest` is a **rest
invoice** of the invoice whose address and end it names ([§31](#the-rest-of-an-underpayment)), not
an invoice of the order: it gives no DeclaredInvoice, and belongs to the payment check of that
invoice. Each other declaration gives a DeclaredInvoice: `sats` = amount ÷ 1000; `fiat` null when
the currency is `SAT`, else `{amount, currency, minor (string), digits}`; `note` the declared note;
`createdAt`, `expiresAt` from the invoice; `declaredAt` the event's `created_at`; `onchainAddress`
the address of the confirmed lease ([§31](#leases)) whose `invoice` is this invoice (compared
ignoring ASCII case; the newest, should several), else null. Each confirmed lease whose `invoice` is
null gives one too: `bolt11`, `paymentHash` and `verifyUrl` null, `sats`, `createdAt`, `expiresAt`
and the sale's from the lease, `declaredAt` the `created_at` of the lease's event (its mark). A
lease that is not confirmed gives nothing: its `createInvoice` failed before its address was the
order's ([§31](#leasing-an-address)), and it was withdrawn, or holds that address until its end. A
lease naming an invoice that has no declaration is left out: that invoice was never shown. Sort
them by `createdAt`, then payment hash (none first), then address. A declaration or a lease of a
newer format logs a warning. Vectors: `earlier-invoices.json`.

**The check** (step 3 of [§17](#17-creating-an-invoice)):

1. The declared invoices with now < `expiresAt` + 120 may still be paid: check their payments
   ([§22](#22-payment-check), with their rest invoices, at most 4 at a time), even of one alone, so
   that an invoice already paid is never handed out again; each check may ask for a rest invoice
   ([§31](#the-rest-of-an-underpayment)), as any payment check, so that an underpaid one is handed
   out with a rest invoice its checkout links' pages show. Several may still be paid when an earlier
   `createInvoice` failed once a minority of the relays took its last record (its declaration; for
   an invoice paid on-chain only, its lease's event: its mark), and a later one, which did not read
   that record, made another invoice and showed it: then, at the same time, read the sale's records
   again ([above](#21-one-order-one-invoice-at-a-time)), on every relay ([§13](#13-relays)). The
   first that is `paid` gives `order_paid` carrying it and its status, whatever the read (a payment
   proves itself: a preimage, or 3 confirmations); else the first error of their
   checks, if any, is the error (that invoice may have been paid); else, when fewer than a majority
   answered the read, `network`. Else one is handed out: the only one; of several, the one whose
   last record a majority of the list sent (a copy whose `id` is its hash, [§11](#11-nostr-events)):
   the one shown. When not exactly one is (a relay that holds it did not answer), it is the newest
   that received something (`unconfirmed`, or `open` with `received` above 0), else the newest (the
   last in the order above). To hand an invoice out, publish its declaration event and its lease
   event again on a majority of the relays (their first publication may have failed; its lease, when
   it has an address, was confirmed: the address is the order's). Then, with `checkout`, publish a
   new checkout link to it ([§30](#30-checkout-links): its record from the DeclaredInvoice, with
   this order's `redirectUrl`, and with an address its rest fields) on a majority of the relays;
   then fail with `invoice_pending` carrying it, and the new link's URL as `checkoutUrl` (null
   without `checkout`). A shop that lost the Invoice it stored can thus still send its customer to
   pay the pending one.
2. Else check the payment of every declared invoice ([§22](#22-payment-check), with the rest
   invoices of each read above), at most 4 at a time.
   The first (in order) that is `paid`: `order_paid` carrying it and its status. Else the first
   that is `unconfirmed` or `open` (an on-chain payment being confirmed, or a transaction
   undecided): `invoice_pending` carrying it, with `checkoutUrl` null, publishing nothing. Its time
   to be paid is over: the shop keeps the checkout link it got, whose page goes on following the
   payment ([§30](#30-checkout-links)). Else the first error, if any.

## 22. Payment check

The **Lightning part** of an invoice with a `bolt11`: GET its verify URL ([§15](#15-http)) and
classify the answer ([§16](#16-lightning-address)). "Final" means now ≥ `expiresAt` + 120: a payment
of an invoice's last seconds may be reported up to then.

| Answer                                                       | Not final                      | Final             |
| ------------------------------------------------------------ | ------------------------------ | ----------------- |
| A refusal with reason `Not found` (exactly)                  | `open`                         | `expired`         |
| Another refusal                                              | `open`                         | `network`         |
| `pr` not a string                                            | `invalid_invoice`              | `invalid_invoice` |
| `pr` not this invoice (compared ignoring ASCII case)         | `invalid_invoice`              | `invalid_invoice` |
| `settled` not `true`                                         | `open`                         | `expired`         |
| `settled: true`, `preimage` not 64 hex characters (any case) | `invalid_invoice`              | `invalid_invoice` |
| `settled: true`, SHA-256(preimage) ≠ payment hash            | `invalid_invoice`              | `invalid_invoice` |
| `settled: true`, SHA-256(preimage) = payment hash            | `paid` (preimage in lowercase) | same              |

An invoice with an address has an **on-chain part** too ([§31](#31-on-chain-payments)), and a
**rest part**, the Lightning parts of the invoices of the rest of an on-chain underpayment
([§31](#the-rest-of-an-underpayment)); its status combines them as §31 says. Without an address,
the status is the Lightning part's: `paid` with `method: "lightning"` and the preimage, `open`
with the invoice's `expiresAt`, `received` `"0"` and `rest` null, and `expired` with `received`
`"0"`.

Before asking, `getStatus` checks the stored invoice; else `invalid_order` (`invoice`):

- `sats` a string of 1 to 16 digits (`0`–`9`, a leading zero allowed) from 1 to
  2 100 000 000 000 000; `expiresAt` a safe integer;
- `bolt11` null, or it decodes on network `bc` with an amount of exactly `sats` × 1000 msat, its
  payment hash is `paymentHash` (hex32), timestamp + expiry is `expiresAt`, and `verifyUrl` is an
  https URL; without `bolt11`, `paymentHash` and `verifyUrl` are null;
- `onchainAddress` null or absent, or a deposit address
  ([§31](#31-on-chain-payments));
- at least one of `bolt11` and `onchainAddress`;
- with an address, `ref` a reference ([§17](#17-creating-an-invoice)): the witnesses, the lease and
  the rest invoices of the invoice are its order's sale's ([§3](#3-data-model)).

Every member these rules read is there, but `onchainAddress` ([§2](#2-conventions): one left out
is not `null`); the others are not read. The check proves that an invoice is well formed, never who
made it ([§27](#27-security)). Only the order holding an invoice is marked paid with it. Vectors:
`payments.json` (an invoice without an address, and stored invoices checked),
`onchain-payments.json`.

## 23. Waiting for a payment

`waitForPayment(invoice, { intervalMs, onStatus })`: `intervalMs` an integer from 250 to 60 000
(2000 when absent), `onStatus` absent or a function; else `invalid_option`, before any request.
Checks the payment, hands each status to `onStatus`, returns once it is `paid` or `expired`; waits
`intervalMs` between two checks. A `network` error is retried; any other error ends it. With an
address, its on-chain part (with its rest part) is checked when the explorer's WebSocket says
something changed, and its rest invoices every `intervalMs`
([§31](#waiting-for-an-on-chain-payment)). An on-chain payment takes about 30 minutes to be `paid`
once `unconfirmed`: a server that cannot wait that long checks again later with `getStatus`; but it
checks the payment while the customer pays, until the invoice's end and its grace period: a
transaction no check saw by then is late, unless it replaces one a check saw (RBF,
[§31](#31-on-chain-payments)). A failure that each check meets again (an explorer or a Lightning
address that does not answer, a rest invoice that cannot be asked, a witness `none` that cannot be
published) SHOULD be logged once, and again only after it stopped, not at each check. When it
returns (a status, an error, a cancellation), nothing it started runs on: a check still running is
stopped first, as every call closes its connections when it is done
([§1](#1-what-an-integration-does)).

## 24. Finding an order's invoices

`findInvoices(ref)`: checks `ref`, reads the channel, then the sale's declarations
([§21](#21-one-order-one-invoice-at-a-time)): the DeclaredInvoices, oldest first. To find an
order's invoice again after a failure. It publishes nothing: to show an order's invoice again, call
`createInvoice`, whose `invoice_pending` carries the pending invoice once its records are on a
majority of the relays again ([§21](#21-one-order-one-invoice-at-a-time)).

## 25. Prices in a currency

**Currencies**: an order is priced in a currency of [`currencies.json`](currencies.json), by its
upper-case ISO 4217 code: ISO 4217 List One (SIX Group) without funds, precious metals, SDR, test
and "no currency" codes. Each currency's decimals are those the merchant's app uses (CLDR, through
ECMAScript `Intl`), because the app compares a sale's declared decimals with its own and leaves out
the sales that differ: for 13 currencies they are not ISO 4217's minor units (AFN, ALL, IQD, IRR,
KPW, LAK, LBP, MGA, MMK, RSD, SOS, SYP, YER have 0). Implementations MUST use this table, never
their platform's locale data, which differs between platforms and versions. The table changes with
ISO 4217 and with the app.

**The price of an order**: `amount` matches `^([0-9]{1,15})(\.([0-9]{1,15}))?$` (nothing around
it, no sign, no exponent); its fraction, without trailing zeros, has at most the currency's
decimals. `minor` = the amount × 10^digits, from 1 to 2^53 − 1. The Fiat's `amount` is the minor
units written with exactly `digits` decimals. Else `invalid_order` (`fiat`). Vectors: `fiat.json`.

**The price of one bitcoin**, as a source writes it:

- a **string**: matches `^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`, at most 64 characters, an exponent
  of at most 64 either way, strictly positive. Read as its exact decimal value;
- a **JSON number**: read as an IEEE 754 double (as every JSON reader does), then as the shortest
  decimal that reads back as that double; of two such, the nearer to the double; of two as near, the
  one whose last digit is even (`1660867710597813.25` is the double that both `1660867710597813.2`
  and `1660867710597813.3` read back as: `1660867710597813.2`). ECMAScript's
  `Number.prototype.toString`, Python's `repr` and .NET's `"R"` write it so, and PHP's
  `var_export`/`json_encode` with `serialize_precision = -1` (never `(string)`, which keeps 14
  digits). Then as a string.

Anything else is `rate`. The RateInfo's `price` is the decimal written plainly (no exponent), with
no trailing zero in its fraction and no fraction when whole: `69012.5`, `0.00000008`. Vectors:
`prices.json`.

**The conversion**: with the price `p` = `units × 10^-scale`,

```
sats = ceil(minor × 10^8 × 10^scale / (units × 10^digits))
```

on integers, rounded up to the next whole sat: the merchant never receives less than the price.
Example: 24.50 CHF at 69 012 CHF/BTC is `ceil(2450 × 10^8 / 6 901 200)` = 35 502 sats. Vectors:
`conversions.json`.

**Age**: a price its source dates (`time`) MUST be a safe integer, not more than 300 s ahead of now,
and not more than 3600 s old; else `rate`. An undated price cannot be checked.

## 26. Rate sources

A rate source gives the price of one bitcoin in a currency (upper-case ISO 4217). An HTTP answer
([§15](#15-http)) that is not 2xx is `network` for a status from 500 to 599, 408 and 429 (and for a
redirect, [§15](#15-http)), else `rate` (600 and above included); a body that is not a JSON object
is `rate`. A price absent from the answer is `unsupported_currency`; a price
that is neither a string nor a number is `rate`.

| Name        | Request                                                                                                                                                                                        | Price                                                                     | Time                                    |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------- |
| `coingecko` | `https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=<code>&include_last_updated_at=true`, `<code>` in lowercase; header `x-cg-demo-api-key: <coingeckoApiKey>` when given | `bitcoin.<code>` (`bitcoin` an object, else `rate`)                       | `bitcoin.last_updated_at` when a number |
| `mempool`   | `https://mempool.space/api/v1/prices`; only `USD EUR GBP CAD CHF AUD JPY` (others: `unsupported_currency` before any request)                                                                  | `<CODE>`                                                                  | `time`, required (else `rate`)          |
| `opennode`  | `https://api.opennode.com/v1/rates`                                                                                                                                                            | `data.BTC<CODE>.<CODE>` (`data.BTC<CODE>` absent: `unsupported_currency`) | none                                    |
| `coinbase`  | `https://api.coinbase.com/v2/exchange-rates?currency=BTC`                                                                                                                                      | `data.rates.<CODE>`; `data.currency` MUST be `BTC` (else `rate`)          | none                                    |
| `kraken`    | `https://api.kraken.com/0/public/Ticker?pair=XBT<CODE>`                                                                                                                                        | `c[0]` of the only entry of `result` (not exactly one: `rate`)            | none                                    |

Kraken: `error` MUST be an array; an error starting with `EQuery:Unknown asset pair` is
`unsupported_currency`, any other `rate`.

**A custom source**: a function (an interface…) of the integrator, `(currency, cancellation) →
price` where the price is a decimal string or `{ price: <string>, time?: <integer or null> }`;
never a number (it may already have lost digits). It raises `unsupported_currency` when it has no
price in that currency. An error of [§5](#5-errors) it raises goes through as it is; any other
failure of it becomes `rate` (keeping the cause); a cancelled call fails with the cancellation.
Its RateInfo
`source` is `custom`. Any other source (CoinGecko Pro, a self-hosted mempool, several sources
checked against each other) is a custom source.

**`coingeckoApiKey`** is optional: without it, CoinGecko is asked without a key (its keyless API,
limited by IP); with it, the header above is sent to CoinGecko, never to another source.

**Which sources**: `rateSource` is a source (a name above, or a custom source) or a list of 1 or
more sources, asked in the list's order; a name appears at most once. Anything else is
`invalid_option` for the client and `invalid_order` for an order (`rateSource`): an empty list, an
unknown name or one in another case (`CoinGecko`), `custom` (not a name: a custom source is a
function), a name twice, a list inside a list. Absent from the client, it is the **default list**:

```
coingecko, mempool, coinbase, kraken, opennode
```

the dated sources first (their price's age is checked), CoinGecko first for its currencies, then
mempool.space for its 7; then the undated ones, Coinbase and Kraken (two exchanges), and OpenNode.
An order without `rateSource` uses the client's (its list, or the default list).

**A list**: its sources are asked one at a time, in order, the next one only when the previous one
gives no usable price, that is when it fails with `network`, `rate` (an invalid answer or price, a
price too old or too far ahead: [§25](#25-prices-in-a-currency)) or `unsupported_currency`. The
first usable price is the rate, and its RateInfo `source` names the source that gave it. A
cancellation stops the list at once (the call fails with it); any other error a custom source
raises goes through as it is and stops the list. When no source gives a price, the error is
`unsupported_currency` when every source raised it, else the error of the last source that raised
`network` or `rate` (both retryable). A source of one list is asked once, never at the same time as
another: a list of _n_ sources may take _n_ HTTP timeouts. A failure that the next source replaces
SHOULD be logged as a warning (the source and the error's code and message; never a key). A list
of one source is that source alone. Vectors: `rate-sources.json`.

## 27. Security

- **The integration key is a secret**: never in a message, a log, an exception's data or a default
  string or debug representation (JavaScript: a non-enumerable property; Python: `__repr__`; C#:
  `ToString` and `DebuggerDisplay`; PHP: `__debugInfo` and `#[\SensitiveParameter]` on every
  parameter that receives it, so that stack traces leave it out). The same for every key derived
  from it, but the rest keys and rest authors written in checkout links' records
  ([§31](#the-rest-of-an-underpayment)): they only read rest records.
- **Randomness** (NIP-44 nonces, BIP-340 auxiliary data, authentication keys, subscription ids)
  comes from the platform's CSPRNG, never a general-purpose generator.
- **Untrusted input**: relays, the Lightning address, rate sources, the explorers (the merchant's
  Bitcoin node included) and BlockCypher, stored invoices. Everything is validated as this document
  says before it is used; a relay that sends something else is ignored.
- **Stored invoices are the shop's**: the check of a stored invoice ([§22](#22-payment-check))
  proves that it is well formed, never that this integration made it. An invoice that someone
  else wrote, with a Lightning invoice of their own that they paid, reads as paid: the shop checks
  only the invoices it stored itself with their orders, where only it writes (its database), never
  one that comes from the customer (a form, a URL, a cookie).
- MACs are compared in constant time. Signing (BIP-340) and ECDH (NIP-44) handle the secrets too:
  an implementation's README says whether its secp256k1 does them in constant time.
- An invoice is shown only after its declaration is on a majority of relays; an address only after
  its lease is confirmed: on a majority, then no other lease of it in a complete read of a
  majority, then marked confirmed on a majority ([§31](#leasing-an-address)). A lease that is not
  confirmed never gives its invoice an address, and is withdrawn; a confirmed lease never is.
- **Relays** are never trusted with what they send ([§11](#11-nostr-events)); for what they hold,
  majorities answer: any two majorities of one list share a relay, which sends the newest events it
  holds, as many as a filter's limit ([§13](#13-relays)). The merchant's relays are relied on for
  that. A relay may also hide what it holds: the reads that decide that a record is nobody else's (a
  lease's confirmation, the witnesses read again, the choice among several invoices of an order) are
  on every relay ([§13](#13-relays)), so that one relay cannot hide a record from them while a relay
  that holds it answers in time (and did not fail earlier in the call); so is the read of the
  merchant's acceptance, which counts only what a majority of the relays sent (below). A slow relay
  delays each of them by one `relayTimeoutMs` at most. Only when every relay that holds a lease or a
  witness is unreachable can a relay that hides it make two orders hold one address
  ([§31](#leasing-an-address)) or one transaction count for two invoices ([§31](#witnesses)); and
  one that sends a record it does not keep can choose which of several invoices of an order is
  handed out ([§21](#21-one-order-one-invoice-at-a-time)), never one whose address another order
  holds. The other reads go on at a majority: a relay that hides a witness from step 2 of leasing
  can have an address a witness names leased again (the transaction still counts for one invoice at
  most, the read of witnesses on every relay finding it); one that hides an order's invoice from
  [§21](#21-one-order-one-invoice-at-a-time)'s read can have a second invoice made for that order
  (never one of another order); one that hides the newest lot can bring back addresses the app took
  out (one paid is still skipped: the explorer shows it). Anybody can write events at a lease's `d`
  tag (it is public): a read of leases they fill stops incomplete, and the order goes without that
  address, never with one another order holds; only a holder of the registry key makes a record that
  holds an address, of a newer format included. A relay can send copies of a lease under `id`s of
  their own (their signature does not check out): a read keeps a few bytes of each
  ([§13](#13-relays), Limits).
- A Lightning invoice cannot be revoked: an invoice shown stays payable until it expires. An address
  stays payable for ever: a payment broadcast after its lease's end reaches the merchant, but counts
  for no order, nor for the next order that leases the address (it is then paid already, and left
  out). A replacement (RBF) of a payment in time counts for its order, for at most what that
  payment paid: what it pays more is late.
- **Rest invoices** ([§31](#the-rest-of-an-underpayment)) are declared before they are in a status
  or a rest record, as any invoice. A rest record is signed by the rest secret, which only the
  integration key derives: whoever holds a checkout link's URL reads its rest records (the rest key
  is in the link's record) but cannot write one; the page shows only those of the rest author its
  link's record names. The same holds for acceptance records.
- **The merchant's tolerance** ([§31](#the-merchants-tolerance)) is read in the channel and kept in
  the order's lease, which only the order's sale and the merchant read: it is never written in what
  the shop's page or the customer gets (an Invoice, a PaymentStatus, a checkout link's record, a
  rest record, an acceptance record, a log), nor in an error. A customer who knew it could pay
  that much less on purpose. An acceptance record tells a checkout link's page that one payment
  counts, never the tolerance.
- **The merchant's acceptance** ([§31](#the-merchants-acceptance)) is signed by the team: the
  integration key opens it but cannot make one, so neither the shop's server, nor whoever obtains
  its key, nor a customer, can have an order paid for less than its amount by it. A check counts
  only one whose event checks out with the team's key, and that a majority of the merchant's relays
  sent, read on every relay: one that only a minority of the relays holds counts for no check,
  whichever relays answer, and whatever a relay sends to some checks and not to others. The limit: a
  relay that holds it and fails at a check's time (it does not answer in time, failed earlier in the
  call, or hides it) may make that check not count it, when the other relays that hold it are fewer
  than a majority; a later check, which that relay answers, counts it. An underpaid order may then
  read `expired` after the lease's end, then `unconfirmed`. The same holds of a merchant's app that
  breaks its rule (it publishes at or after the invoice's `expiresAt`, or its clock runs behind by
  more than 60 s), and of a relay that stores what it was sent more than a minute after its request:
  the bound on the record's `created_at` sets aside only a record dated after the lease's end. Like
  the tolerance, it reaches the pages of checkout links only through an acceptance record.
- **Third parties**: the explorer ([§31](#explorers)), mempool.space or the merchant's Bitcoin node,
  sees the server's IP address and the addresses it asks about or watches, and their transactions
  (mempool.space too, when the node fails and its `fallback` is `"mempool"`); BlockCypher sees it
  and a transaction, only for one no check saw while its lease ran; never a key. Trust rests on one
  explorer, mempool.space or the node the merchant chose: what it alone shows makes a payment count
  as made ([§31](#explorers)). With `payers` `true` ([§31](#the-merchants-bitcoin-node)), the
  node's URL is in the record of each checkout link (whoever holds the link reads it), and the node
  sees the customer's IP address and the address the page follows.
- **Outbound requests**: besides fixed hosts (the rate sources, mempool.space, BlockCypher), the
  server asks hosts that others choose: the merchant (its Lightning address, its relays, its Bitcoin
  node) and its Lightning address's provider (the callback, the verify URL); no redirect takes a
  request elsewhere ([§13](#13-relays), [§15](#15-http)). Their URLs are checked: no IP address, no
  `localhost` nor a name under it ([§9](#9-relay-lists), [§15](#15-http)), but for the merchant's
  Bitcoin node, whose URL has a rule of its own (below); TLS comes before any request (but to a node
  asked over `http`), so a host whose certificate the server does not trust gets no request. But a
  name may still lead to an address of the server's own network (an internal name, a public name
  resolving to a private address). An integrator whose server holds the keys of several merchants,
  or sits in a network with services of its own, SHOULD restrict what the server can reach to
  public addresses (in its network, or in the HTTP and WebSocket clients it injects,
  [§4](#4-client)). An implementation does not resolve names itself to refuse private addresses: a
  check of a name before the request is bypassed by a name that resolves again (DNS rebinding).
- **The merchant's Bitcoin node** ([§31](#the-merchants-bitcoin-node)): its URL is the merchant's
  choice, and an implementation always follows a valid one. The server sends it GET requests, in
  clear HTTP too to an address of a private network, and to an IPv4 address: at a shared host, whose
  servers hold the keys of several merchants, one merchant could so have the server ask machines of
  that host's own network. What bounds it: GET only, at the paths [§31](#explorers) sets under
  `/api`, and the WebSocket's two messages ([§31](#waiting-for-an-on-chain-payment)); no redirect
  followed, an answer bounded and checked, any answer out of format a failure ([§15](#15-http));
  nothing sent but deposit addresses; never `localhost`, 127.0.0.0/8 nor 0.0.0.0/8; `http` only for
  the local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, names under `.local`).
  An integrator that restricts its server to public addresses (above) leaves such a node
  unreachable: its `fallback` then applies. The node is trusted as mempool.space is: what it shows
  decides whether an order is paid. Over `http`, whoever is on the network between the server and
  the node can change its answers: `http` is allowed for the local ranges only, and is as safe as
  that network.
- **On-chain addresses**: whoever holds the integration key reads the lot, so it knows the
  merchant's unpaid addresses; whoever holds the registry key (the merchant's devices, its payment
  links, its integrations) can lease an address of a lot it knows, which then goes to no other
  order until the lease ends.
- **Checkout links** ([§30](#30-checkout-links)): a link's author secret signs its record and
  authenticates its publication, then is forgotten: never stored, returned nor logged, so that
  nobody, the integrator included, can change a link once published. Whoever holds a
  `checkoutUrl` reads its record (the invoice, the business's name, the note, the redirect URL, the
  merchant's Bitcoin node with `payers` `true`): the shop gives it to the order's customer only.
  Being sent to the redirect URL proves nothing (anyone can open it): the order is marked paid only
  after the payment check ([§22](#22-payment-check)) of the integrator's server.

## 28. Constants

| Constant                               | Value                                                                 |
| -------------------------------------- | --------------------------------------------------------------------- |
| Key prefix                             | `sattleme_ck_`                                                        |
| Record kind / authentication kind      | 30078 / 22242                                                         |
| Record padding                         | 256 bytes                                                             |
| Channel type / version                 | `team-channel` / 1                                                    |
| Declaration type / version             | `registry-declaration` / 1                                            |
| Sats currency                          | `SAT`                                                                 |
| Relay moves followed                   | 3                                                                     |
| Relays per list / relay address length | 1 to 10 / 120 code points                                             |
| Business name                          | 200 code points                                                       |
| Reference                              | 1 to 64 of `A–Z a–z 0–9 . _ : -`                                      |
| Duration                               | 60 to 3600 s, 900 by default                                          |
| Note                                   | 100 code points                                                       |
| Grace period                           | 120 s                                                                 |
| Clock tolerance                        | 300 s                                                                 |
| Rate age                               | 3600 s                                                                |
| Default rate sources, in order         | `coingecko`, `mempool`, `coinbase`, `kraken`, `opennode`              |
| Price text / exponent                  | 64 characters / 64                                                    |
| Events per query / pages               | 1000 / 20                                                             |
| Page of a complete read                | 100 events (`limit`)                                                  |
| Relay message / HTTP body              | 1 MiB / 1 MiB                                                         |
| User-Agent (HTTP, WebSocket handshake) | `sattleme-Checkout/1`                                                 |
| https URL                              | 2048 characters at most                                               |
| Payment checks at once                 | 4                                                                     |
| Timeouts                               | 10 000 ms by default, 100 to 60 000                                   |
| Wait interval                          | 2000 ms by default, 250 to 60 000                                     |
| BOLT11 expiry field                    | 7 words at most                                                       |
| BOLT11 amount                          | 2 100 000 000 000 000 000 msat at most                                |
| Minor units                            | 9 007 199 254 740 991 at most                                         |
| Checkout salt                          | `sattle.me/checkout`                                                  |
| Checkout link type / version / marker  | `checkout` / 1 / `c`                                                  |
| Checkout link life                     | 604 800 s after the invoice's end                                     |
| Checkout path                          | `/pay`                                                                |
| Redirect URL                           | 2048 characters at most                                               |
| Redirect delay (the page)              | 7 s after the payment is proven                                       |
| On-chain floor                         | 1 000 sats                                                            |
| Largest amount                         | 2 100 000 000 000 000 sats                                            |
| Lot type / version / size              | `integration-onchain-lot` / 1 / 100 addresses at most                 |
| Lease type / version                   | `registry-onchain` / 1                                                |
| Lease lookback                         | 7200 s                                                                |
| Addresses tried per order              | 3                                                                     |
| Witness type / version                 | `integration-onchain-seen` / 1                                        |
| Coins a witness keeps                  | the transaction's first 100                                           |
| Explorer's WebSocket                   | `wss://mempool.space/api/v1/ws` or the node's, checked every 60 s too |
| Merchant's Bitcoin node URL            | 200 characters at most                                                |
| Node failed recently                   | 60 s: asked after mempool.space (`fallback` `"mempool"`)              |
| Confirmations                          | 3, on the explorer read                                               |
| When a transaction was received        | BlockCypher, only for one no check saw in time                        |
| Rest type / version                    | `checkout-rest` / 1                                                   |
| Rest invoice                           | asked with 60 s left at least, until the invoice's end                |
| Rest payable on-chain                  | from 1 000 sats (the on-chain floor)                                  |
| Tolerance                              | 0 to 1000 basis points (10 %), 0 by default                           |
| Acceptance record type / version       | `checkout-accepted` / 1                                               |
| Merchant's acceptance type / version   | `integration-onchain-accepted` / 1                                    |

## 29. Conformance vectors

An implementation passes every vector. In [`vectors/`](vectors), each file says what it holds;
an error is written `{"error": <code>}` (with `param` when the error has one).

| File                        | Covers                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `integration-keys.json`     | [§8](#8-the-integration-key): parsed keys, and invalid ones.                                                       |
| `relay-urls.json`           | [§9](#9-relay-lists).                                                                                              |
| `nostr-events.json`         | [§11](#11-nostr-events): event ids, the escapes of their strings.                                                  |
| `relay-reads.json`          | [§13](#13-relays): paged and complete reads, page after page; reads on every relay.                                |
| `https-urls.json`           | [§15](#15-http): https URLs, their hosts, Lightning addresses' pay URLs.                                           |
| `pay-requests.json`         | [§16](#16-lightning-address): pay requests read, their sendable sats and description hash.                         |
| `earlier-invoices.json`     | [§21](#21-one-order-one-invoice-at-a-time): an order's invoices from its records, step 1.                          |
| `bolt11.json`               | [§19](#19-bolt11).                                                                                                 |
| `fiat.json`                 | [§25](#25-prices-in-a-currency): prices of orders; `currencyDigits` ([§4](#4-client)).                             |
| `prices.json`               | [§25](#25-prices-in-a-currency): prices of one bitcoin, text and JSON numbers.                                     |
| `conversions.json`          | [§25](#25-prices-in-a-currency): sats of a price.                                                                  |
| `rate-sources.json`         | [§26](#26-rate-sources): `rateSource`, the default list, lists in order, HTTP statuses.                            |
| `order-text.json`           | [§17](#17-creating-an-invoice): references, notes, comments.                                                       |
| `invoice-checks.json`       | [§18](#18-invoice-checks).                                                                                         |
| `payments.json`             | [§22](#22-payment-check): answers of the verify URL, stored invoices checked.                                      |
| `redirect-urls.json`        | [§30](#30-checkout-links): redirect URLs accepted (with what is shown), refused.                                   |
| `checkout-links.json`       | [§30](#30-checkout-links): origins, derivations, URLs, fragments, records.                                         |
| `payment-methods.json`      | [§31](#31-on-chain-payments): the methods of an order by its amount.                                               |
| `onchain-addresses.json`    | [§31](#31-on-chain-payments): deposit addresses, registry addresses, URIs.                                         |
| `onchain-leases.json`       | [§31](#31-on-chain-payments): leases, their tolerance, addresses leased, leases confirmed.                         |
| `onchain-witnesses.json`    | [§31](#31-on-chain-payments): witnesses' keys, addresses and tags, opened.                                         |
| `onchain-replacements.json` | [§31](#31-on-chain-payments): the parts of replaced transactions (RBF).                                            |
| `onchain-tolerances.json`   | [§31](#the-merchants-tolerance): tolerances read, least amounts accepted.                                          |
| `bitcoin-nodes.json`        | [§31](#the-merchants-bitcoin-node): node URLs, the channel's `bitcoinNode`, `fallback`, checkout records' node.    |
| `onchain-payments.json`     | [§31](#31-on-chain-payments): on-chain parts, rest parts, statuses, acceptance records and merchant's acceptances. |
| `onchain-rests.json`        | [§31](#the-rest-of-an-underpayment): rest keys, records, acceptance records, declarations, asking.                 |
| `../currencies.json`        | [§25](#25-prices-in-a-currency): the currency table.                                                               |

And, made elsewhere, each with its `source`:

- [`vectors/app/app.json`](vectors/app/app.json): the key, every derivation, a channel and a
  declaration made by the merchant's app, a real breez.tips invoice
  ([§10](#10-key-derivations)). An implementation derives every value, opens the channel and the
  declaration, and makes a declaration that opens with the vector's keys.
- [`vectors/app/implementation-declaration.json`](vectors/app/implementation-declaration.json): a
  declaration made by an implementation of this document with fixed random bytes, which the app
  reads.
- [`vectors/app/checkout-link.json`](vectors/app/checkout-link.json): a checkout link made by an
  implementation of this document (`createInvoice`, end to end) with fixed random bytes: its keys,
  record, event and URL, which the merchant's web app reads, and what `createInvoice` was answered
  (the pay request, a price of one bitcoin). An implementation makes the same record value for the
  same order, and its event opens with the vector's keys.
- [`vectors/app/onchain-lot.json`](vectors/app/onchain-lot.json): an integration's lot of
  addresses made by the merchant's app ([§31](#31-on-chain-payments)), which an implementation
  opens with the vector's key.
- [`vectors/app/merchant-acceptance.json`](vectors/app/merchant-acceptance.json): the merchant's
  acceptances of invoices of the integration of `onchain-lot.json`, made by the merchant's app
  ([§31](#the-merchants-acceptance)): their addresses, and records an implementation opens with the
  vector's key, or ignores (another author, another address, a value it does not count, a newer
  format); and, in `made`, records this repository's `scripts/recompute.mjs` made for a team of its
  own, which the app is not asked to make (a damaged signature, an `id` that is not its hash, kind
  1, a content of a newer NIP-44 version, another integration's seal, `received` spelled `3e4` or
  `30000.0`, `version` spelled `1.0` (1: counted) or `1.5` (above 1: a newer format)).
- [`vectors/app/checkout-rest.json`](vectors/app/checkout-rest.json): a checkout link to an
  invoice with an address, and the rest record of the Lightning invoice of its underpayment's
  rest, made by an implementation of this document (`createInvoice`, then a payment check, end to
  end) with fixed random bytes, which the merchant's web app reads
  ([§31](#the-rest-of-an-underpayment)), with the pay request both invoices were made for. Its
  records' random bytes follow every draw made before them, in the order of the implementation that
  made it (among them, each read's key as the read starts, of the two reads at the same time of a
  payment check the witnesses' before the merchant's acceptance's, and each query's subscription id
  as it is sent): it is made again whenever these calls draw random bytes otherwise (a read with a
  key of its own added to a payment check). An implementation that draws in that order makes it
  again byte for byte. One that draws otherwise, which [§13](#13-relays) allows (a read's key drawn
  only when a relay asks authentication, two reads at the same time drawing in either order), makes
  other keys and events from the same random bytes, and checks the file by what it holds, not by its
  bytes: every value that no random byte decides is the vector's (the invoice, the link's `value`,
  the rest keys `restKey`, `restAuthor`, `encryptionKey` and the rest record's `address`, its tags
  and `value`, the status), its own link and rest record check out and open, with the keys of its
  URL and the rest keys, to those values, and the vector's `link.event` and `rest.event` open with
  the vector's keys as the merchant's web app opens them. The link's keys, author, address and URL,
  and the `content`, `id` and `sig` of both events, follow the draws.
- [`vectors/nip44/nip44.vectors.json`](vectors/nip44/nip44.vectors.json): the official NIP-44
  vectors ([§12](#12-sealed-records)).

What vectors cannot cover (relays, timing) is covered by each implementation's own tests, against
a local relay and fakes of the Lightning address and of the rate sources
([PORTING.md](PORTING.md#steps)).

## 30. Checkout links

A checkout link sends the order's customer to the merchant's web app, whose page `/pay` reads the
invoice from the merchant's relays, shows it, checks its payment from the customer's browser and,
once it is paid, sends the customer to the order's redirect URL: the shop's confirmation page, or
its app. The integrator asks for one per order (`checkout`, [§17](#17-creating-an-invoice)).
Nothing else changes: the invoice is declared before its link is given, and the order is marked
paid by the payment check of the integrator's server ([§22](#22-payment-check)), never by the
redirection.

### The web app's origin

A **checkout origin** is `https://`, a host as in a relay address ([§9](#9-relay-lists): labels of
`a–z 0–9 -` separated by `.`, the last of at least two letters and not `localhost`, at most 253
characters) and an optional port (`:` then 1 to 5 digits, 1 to 65535), then nothing: no path, no
`/`. The channel's `checkout.origin` gives it ([§14](#14-reading-the-channel)). A channel without
one gives no checkout link: `checkout_unavailable`. The merchant's app writes it when its version
has a web app. Vectors: `checkout-links.json`, `origins`.

### Keys

For each link, from the CSPRNG ([§27](#27-security)):

- the **link key**: 32 bytes;
- the **link author's secret**: 32 bytes, drawn again until they are a valid secp256k1 secret key
  (from 1 to the curve's order minus 1). The **author** is its BIP-340 x-only public key.

| Name                | Derivation                                                |
| ------------------- | --------------------------------------------------------- |
| link address (`d`)  | hex(HKDF(link key, `sattle.me/checkout`, `address/v1`))   |
| link encryption key | HKDF(link key, `sattle.me/checkout`, `encryption-key/v1`) |

The link encryption key is the record's NIP-44 conversation key, used as it is (no ECDH). The
author's secret signs the record and answers the relays' authentication when it is published
([§13](#13-relays)), then is forgotten: nobody can change a link once it is published. Vectors:
`checkout-links.json`, `derivations`.

### The record

A sealed record ([§12](#12-sealed-records)) of type `checkout`, address the link address, key the
link encryption key, signed by the author, `created_at` now, with the tags
`[["d", <address>], ["expiration", <expiresAt + 604800, decimal>]]`: relays that honor NIP-40
drop it a week after the invoice's end. Its value, for an invoice without an address (version 1):

```json
{
  "version": 1,
  "businessName": "<the channel's profile.businessName>",
  "invoice": "<pr>",
  "verifyUrl": "<verify>",
  "fiat": { "minor": 2450, "digits": 2, "currency": "CHF" },
  "note": "<label>",
  "redirectUrl": "<the order's redirect URL>"
}
```

- `fiat`: the order's price as the declaration has it ([§20](#20-the-declaration), `minor` a JSON
  number); `null` for an order in sats.
- `note`: the label ([§17](#17-creating-an-invoice)). The customer sees it.
- `redirectUrl`: `null` when the order has none.
- The amount in sats, the payment hash and the end (`expiresAt`) are the invoice's own: they are
  read from it, never written twice.

For an invoice with an address ([§31](#31-on-chain-payments)), version 2:

```json
{
  "version": 2,
  "businessName": "<the channel's profile.businessName>",
  "invoice": "<pr>",
  "verifyUrl": "<verify>",
  "onchainAddress": "<the leased address>",
  "sats": 49000,
  "createdAt": 1791378280,
  "expiresAt": 1791379180,
  "fiat": { "minor": 2450, "digits": 2, "currency": "CHF" },
  "note": "<label>",
  "redirectUrl": "<the order's redirect URL>",
  "restAuthor": "<the rest author of the invoice, hex>",
  "restKey": "<the rest key of the invoice, hex>"
}
```

- `invoice` and `verifyUrl`: `null` for an order paid on-chain only;
- `sats` (a JSON number), `createdAt` and `expiresAt`: the Invoice's. With an invoice, they are its
  amount, its timestamp and its end: written twice, so that the page needs no invoice to watch the
  address;
- `restAuthor` and `restKey`: the rest author and the rest key of the invoice (the order's `ref`,
  the address and `expiresAt`, [§31](#the-rest-of-an-underpayment)), with which the page reads the
  Lightning invoices of the rest of an underpayment (a page that does not know them ignores them,
  and shows the rest on-chain only); both or neither, absent rather than `null`; never the rest
  secret;
- `bitcoinNode`: `{"url": <url>, "fallback": <fallback>}`, copied as they are from the channel
  read by `createInvoice` when its `bitcoinNode` is valid with `payers` `true`
  ([§31](#the-merchants-bitcoin-node)), without `payers`; absent (never `null`) when `payers` is
  `false` or the channel names no node. The page then reads the chain from that node (below). A
  page that does not know it ignores it (other fields are ignored): it is no new version of the
  record. Never in version 1. Rest records and acceptance records do not carry it: the page takes
  the node of the link's record. Vectors: `bitcoin-nodes.json`, `writes`.

It is published on every relay of the merchant's list (the channel's `relays`, else the key's)
and succeeds on a majority ([§13](#13-relays)).

**Reading** a record: it opens as a record of type `checkout` with the link encryption key, the
link address and the author of the URL ([§12](#12-sealed-records)), and its value is valid:

- an object whose `version` is 1 or 2 (a number above 2: a newer format);
- `businessName` a string, not empty once ASCII whitespace is trimmed, at most 200 code points;
- version 1: `invoice` a string that decodes ([§19](#19-bolt11)) on network `bc`, with an amount
  above 0 and a whole number of sats; `verifyUrl` an https URL;
- version 2: `onchainAddress` a deposit address ([§31](#31-on-chain-payments)); `sats` a safe
  integer from 1 to 2 100 000 000 000 000; `createdAt` and `expiresAt` safe integers, `createdAt` <
  `expiresAt`; `invoice` and `verifyUrl` both `null`, or as in version 1 with an amount of exactly
  `sats` × 1000 msat, its timestamp `createdAt` and timestamp + expiry `expiresAt`; `restAuthor` and
  `restKey` both absent (no rest invoice is shown), or `restAuthor` hex32 and the x coordinate of a
  point of secp256k1 (BIP-340 `lift_x`) and `restKey` hex32; `bitcoinNode` absent, or the node the
  page reads: an object whose `url` is a node URL of a node of the Internet and whose `fallback` is
  exactly `"mempool"` or `"none"` ([§31](#the-merchants-bitcoin-node), its other members
  ignored); any other `bitcoinNode` (`null` included) is set aside, the page reading mempool.space,
  and leaves the record valid. In version 1, `bitcoinNode` is ignored. Vectors:
  `bitcoin-nodes.json`, `records`;
- `fiat` null, or an object with `minor` a safe integer from 1 to 2^53 − 1, `digits` an integer
  from 0 to 8 and `currency` three letters `A–Z` other than `SAT`;
- `note` a string of 1 to 100 code points without control characters (U+0000–U+001F, U+007F);
- `redirectUrl` null, or a valid redirect URL (below);
- other fields are ignored.

Anything else is an invalid link: nothing of it is shown. Vectors: `checkout-links.json`,
`records`.

### The URL

```
<origin>/pay#c.<author>.<key>.<relays>
```

- `<origin>`: the checkout origin; `/pay`: the page;
- `c`: a checkout link of this version;
- `<author>`, `<key>`: base64url of the author (32 bytes, x-only) and of the link key;
- `<relays>`: the merchant's list the record was published on, as the integration key writes it
  ([§8](#8-the-integration-key)): base64url of the UTF-8 of the hosts without `wss://`, joined by
  `,`.

Browsers never send the fragment (after `#`) to the web app's host: it sees neither the key nor
the relays.

**Reading the fragment** (the part after `#`), split on `.`:

1. A first part of 1 to 8 characters `a–z 0–9` other than `c`: a link of a newer format.
2. A first part `c`: exactly three more parts, each strict base64url ([§2](#2-conventions)):
   `<author>` 32 bytes and the x coordinate of a point of secp256k1 (BIP-340 `lift_x`), `<key>` 32
   bytes, `<relays>` a valid list (as step 5 of [§8](#8-the-integration-key)). Anything else is
   invalid.
3. Any other first part: not a checkout link (the merchant's other links on that page have a first
   part longer than 8 characters).

Vectors: `checkout-links.json`, `urls` and `fragments`.

### Redirect URLs

A **redirect URL** is a string of 1 to 2048 characters, each one of
`A–Z a–z 0–9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; =`, or `%` followed by two hex digits
(`0–9 A–F a–f`); so no whitespace, no control character, no `\` and nothing else (a host is
written in punycode, anything else percent-encoded). And it is one of:

1. **https**: `https://`, a host as in a relay address ([§9](#9-relay-lists)), an optional port
   (`:` then 1 to 5 digits, 1 to 65535), then nothing, or `/`, `?` or `#` followed by anything. So
   no user name nor password (`https://user:pass@host` does not match), no IP address, no
   `localhost`, no upper case in the host. Universal links (iOS) and App Links (Android) are such
   URLs.
2. **An app's link**: a scheme of 1 to 32 characters, `a–z` then `a–z 0–9 + . -`, then `://`, then
   anything; the scheme is not `https` (rule 1 only), nor one of these:
   - the browser's own, files and scripts: `about`, `blob`, `chrome`, `chrome-extension`,
     `content`, `data`, `file`, `filesystem`, `javascript`, `moz-extension`, `resource`,
     `safari-extension`, `vbscript`, `view-source`;
   - other browsers, which open any web page given in the rest of the link, whose host the page
     would not show: `brave`, `com-apple-mobilesafari-tab`, `ddgquicklink`, `firefox`,
     `firefox-focus`, `googlechrome`, `googlechrome-x-callback`, `googlechromes`,
     `microsoft-edge`, `microsoft-edge-http`, `microsoft-edge-https`, `onionbrowser`,
     `onionbrowsers`, `opera-http`, `opera-https`, `x-safari-http`, `x-safari-https`;
   - other transports, unencrypted ones: `ftp`, `http`, `ws`, `wss`;
   - any Android activity, with its extras: `android-app`, `intent`;
   - payments, which would open the customer's wallet on a second invoice right after the first:
     `bitcoin`, `keyauth`, `lightning`, `liquidnetwork`, `lnurl`, `lnurlc`, `lnurlp`, `lnurlw`;
   - calls and messages: `callto`, `facetime`, `facetime-audio`, `mailto`, `sip`, `sms`, `tel`;
   - installing software, running system tools: `itms-services`, `ms-msdt`, `search-ms`.

A list cannot name every browser's scheme: a web page is an `https` URL (rule 1), whose host the
page shows; rule 2 is for apps. Nothing is repaired: an upper-case host or scheme, a space, a
missing `://` is refused. `createInvoice` refuses it (`invalid_order`, `redirectUrl`); the page
refuses a record holding one. `\` is refused because a browser reads it as `/` in a URL of the
`https` scheme, where RFC 3986 does not: `https://a.example\@b.example` names two different hosts.

**What the page shows** of it: for rule 1, the host and the port as written (`shop.example`,
`shop.example:8443`); for rule 2, the scheme and `://` (`myshop://`). Vectors: `redirect-urls.json`.

### What the page does

The merchant's web app, for implementations to know what their customers see:

1. It reads the record on the URL's relays, `{"kinds": [30078], "authors": [<author>], "#d":
[<link address>]}`, and shows the first valid copy a relay sends (its author's secret is gone:
   every valid copy is the same record). A link of a newer format, or a record of a newer
   version, asks the customer to update the page.
2. It shows the invoice: the price (else the sats), the business's name, the note, its QR code
   (the record's payment URI, [§31](#31-on-chain-payments)), a button opening the customer's
   wallet, the time left until its end.
3. It checks the payment from the customer's browser as [§22](#22-payment-check) says: paid only
   with the preimage of the payment hash, from an answer about this invoice, or on-chain as
   [§31](#31-on-chain-payments) says (3 confirmations on the explorer it reads: the node of the
   link's record, else mempool.space). It reads the address on that node with its `fallback`, as
   the server does ([§31](#the-merchants-bitcoin-node)): with `"mempool"`, mempool.space when the
   node does not answer; with `"none"`, never mempool.space for the address, and while the node
   does not answer it judges nothing on-chain: it shows that it is checking the payment, then,
   after its usual delay, the code to pay. The time a transaction was sent, as the page shows it,
   stays mempool.space's and BlockCypher's, and the history of replacements mempool.space's,
   whatever the node. It cannot read the witnesses: a transaction it saw while the lease ran came in
   time; one it first sees later (a customer who comes back) is told by BlockCypher's time, as the
   integrator's server tells it (one BlockCypher does not know yet is late: expired, never waited
   for), asked only while what came in time is not enough (in the lease's last seconds, a page that
   saw a transaction and a server that did not may judge it apart: BlockCypher may receive it a few
   seconds after the end). A replacement of a transaction it saw in time counts as
   [Replacements](#replacements) says, from the transactions it saw (their order: when it first
   saw them). Past the lease's end, the page also asks mempool.space's history of the replacements
   (`GET https://mempool.space/api/v1/tx/<txid>/rbf`) of each transaction listed it did not see in
   time (one it saw then counts from then): a transaction it names that BlockCypher keeps counts,
   with BlockCypher's time, where it shares a coin with the replacement (a customer who bumped the
   fee, then came back). mempool.space forgets a chain a day after it was mined; then a
   replacement of a transaction the page did not see is told by BlockCypher's time alone, where the
   server, which reads the witnesses, may count it: the page then shows less than the order got,
   never more. A server needs none of this: it watches the
   payment while the customer pays ([§23](#23-waiting-for-a-payment)). With `restAuthor`, it also
   reads the link's rest records ([§31](#the-rest-of-an-underpayment)) on the URL's relays, and
   keeps listening (the subscription stays open past `EOSE`: the server publishes a rest invoice as
   soon as it sees an underpayment), and checks the payment of each valid one as the invoice's
   (LUD-21, the preimage of its payment hash): what they paid counts with what came on-chain in
   time. It shows nothing but a payment (being confirmed, paid) before a majority of the URL's
   relays sent the rest records they hold: the server publishes each on a majority of the
   merchant's relays (any two majorities share a relay), so one already paid could be missing. It
   reads the link's acceptance records with them ([§31](#acceptance-records)): with one, what came
   in time is enough from the least of its `received` and the amount on, something counting
   on-chain (the merchant's tolerance or the merchant's acceptance accepted it,
   [§31](#the-merchants-acceptance); the page knows neither). Enough in time: being confirmed, then
   paid (the on-chain part 3 deep for what the rest invoices did not pay of that, at once when they
   alone pay the amount). Less than the amount in time:
   underpaid, with what was received and the rest, payable until the invoice's end: in Lightning
   with the latest rest invoice (by date, then payment hash) of exactly that rest, told neither
   paid nor expired, not ended, and on-chain to the same
   address from 1 000 sats (one code, `bitcoin:` with `lightning=`, as a Payment URI of
   [§31](#payment-uris)); below 1 000 sats in Lightning only, nothing to pay while no rest
   invoice of that rest came; without `restAuthor`, on-chain only. Past the invoice's end,
   underpaid for good, with each transaction received in time and the rest invoices paid. Expired
   only once every part is final (the rest invoices included); anything else is asked again, never
   shown as unpaid.
4. Paid, with a redirect URL: a button showing "Redirecting to" (in the page's language) and what it shows of the URL,
   which goes there on its own 7 s after the payment is proven, or at once when tapped. It goes
   there on its own once per browser tab: a customer who comes back sees the receipt, and the
   button. A browser may refuse to open an app without a tap (Chrome on Android refuses one
   opened by a timer): the button stays. Expired, or not proven: no redirection.

## 31. On-chain payments

An order may also be paid on-chain, to a deposit address of the merchant's wallet: a Bitcoin
transaction instead of a Lightning payment, or for amounts Lightning does not take. The integrator's
server has no wallet and cannot make an address: the merchant's app gives each integration a **lot**
of addresses of its wallet, and fills it again whenever the merchant opens the app. An order
**leases** one address of the lot for the time of its invoice, in the merchant's registry: its
customer may pay it until the lease ends, and the address goes back to the lot unless it was paid
on-chain. The integration records each transaction it sees paying an address of its lot
(**witnesses**): whether it came while a lease ran, and for which invoice of which order, so that
every reader, the merchant's app included, tells the same order paid, and one transaction pays one
invoice at most; no order leases an address a witness names again, and the merchant's app takes
those addresses out of the lot. A transaction replaced by another (RBF) keeps its order: the
replacement counts at the time of the payment it replaces, for at most what that payment paid
(**replacements**). When less than the amount came on-chain, the rest is payable in Lightning too,
with an invoice the server asks for as soon as it sees the underpayment (**the rest**), unless it is
short by no more than the merchant's **tolerance**, or the merchant accepted what came (**the
merchant's acceptance**): the order is then paid. Whether the merchant's
own point of sale takes on-chain payments (the channel's `profile.onchain`) plays no part: an
integration takes them whatever that setting.

### Methods by amount

The methods of an order, from its amount (`sats`, [§17](#17-creating-an-invoice) step 4) and the
Lightning address's sendable sats ([§16](#16-lightning-address): from `minSendable` to
`maxSendable`, as its pay request gives them):

- **Lightning**: when the amount is within the sendable sats;
- **on-chain**: when the amount is 1 000 sats or more, and an address could be leased (below).

So an order below 1 000 sats is Lightning only; from 1 000 sats on, it is both, or on-chain only
above the Lightning address's `maxSendable` (or below its `minSendable`), or Lightning only when no
address could be leased. An order with no method fails:

- below 1 000 sats and outside the sendable sats: `invalid_order` (`sats` or `fiat`);
- 1 000 sats or more, outside the sendable sats, and no address leased: `onchain_unavailable`
  (retryable: the lot is filled again when the merchant opens the app), or `network` when the
  explorer did not answer.

Nothing is repaired: an amount is never split between the two methods, nor moved into the
sendable sats. Vectors: `payment-methods.json`.

### Deposit addresses

A **deposit address** is a taproot address of Bitcoin's main network (BIP-341), as the merchant's
wallet hands them out: the bech32m encoding (BIP-350) of the human-readable part `bc`, witness
version 1 and a 32-byte program, in lowercase: `bc1p` and 58 more characters, 62 in all. Anything
else (another network, another witness version or length, bech32 instead of bech32m, upper case,
a padding with bits that are not zero) is not one. Vectors: `onchain-addresses.json`, `addresses`.

### The lot

A sealed record ([§12](#12-sealed-records)) of type `integration-onchain-lot`, author the team, key
the channel encryption key ([§10](#10-key-derivations)), address the **lot address**:

| Name              | Derivation                                                                    |
| ----------------- | ----------------------------------------------------------------------------- |
| lot address (`d`) | hex(HKDF(integration key, `sattle.me/integration`, `onchain-lot/address/v1`)) |

**Reading the lot**: query `{"kinds": [30078], "authors": [<team>], "#d": [<lot address>]}` on the
merchant's relays ([§14](#14-reading-the-channel)), not paged, with a key of that read alone for
NIP-42 ([§13](#13-relays)); fewer than a majority answered: `network`. Keep the newest valid copy,
as for the channel. Its value is valid when:

- `version` is 1 (a number above 1: newer format, logged as a warning, and the lot is empty);
- `updatedAt` equals the event's `created_at`;
- `addresses` is an array of 0 to 100 deposit addresses, none twice;
- other fields are ignored.

No valid copy, or an invalid one: the lot is empty, and the integration takes no on-chain payment
until the merchant opens the app. The order of `addresses` means nothing. The merchant's app
writes it: it takes out the addresses a witness names (below), and adds new ones up to 100.

### Leases

An order leases an address with a sealed record of type `registry-onchain`, in the merchant's
registry, signed by the sale's secret ([§10](#10-key-derivations)), `created_at` now:

| Name                                  | Derivation                                                              |
| ------------------------------------- | ----------------------------------------------------------------------- |
| registry address of a deposit address | hex(HMAC(registry key, UTF-8 of `onchain/v1/` followed by the address)) |
| outer key                             | as a declaration's ([§10](#10-key-derivations)), with this address      |
| inner key                             | as a declaration's: the sale secret and the registry reader (ECDH)      |

The record's value (outside) is one of:

- a **lease**: `{"version": 1, "end": <integer>, "sealed": <string>}`, where `sealed` is the NIP-44
  v2 encryption of the lease's JSON (below) under the inner key, and `end` when the lease ends: its
  invoice's `expiresAt` + 120 (the grace period of [§22](#22-payment-check));
- a **withdrawal**, which replaces the sale's own lease of that address (same author, same `d`,
  `created_at` strictly after it): `{"version": 1, "withdrawn": true}`. Only a lease that was not
  confirmed is withdrawn ([Leasing an address](#leasing-an-address)).

The lease's JSON (inside), which only the sale and the merchant read:

```json
{
  "version": 1,
  "address": "<the deposit address>",
  "sats": 49000,
  "invoice": "<pr>",
  "verifyUrl": "<verify>",
  "createdAt": 1791378280,
  "expiresAt": 1791379180,
  "sale": {
    "key": "<sale key, hex>",
    "fiat": { "minor": 2450, "digits": 2, "currency": "CHF" },
    "note": "<label>"
  },
  "taker": "<taker tag>"
}
```

- `sats`: the amount, a JSON number; `invoice` and `verifyUrl`: the order's Lightning invoice and
  its verify URL, both `null` for an order paid on-chain only; `createdAt` and `expiresAt`: the
  Invoice's ([§3](#3-data-model)); `sale` and `taker` as in a declaration
  ([§20](#20-the-declaration)).
- `tolerance`: the order's tolerance ([below](#the-merchants-tolerance)), the channel's
  `onchainTolerance` when `createInvoice` read it, a JSON number after `taker`; only when it is
  above 0, absent otherwise (never `null`). A reader that does not know it ignores it (it then
  judges the payment without tolerance, never more leniently), so it is no new version of the
  lease.
- `confirmed`: `false` in the lease as first published, `true` in the same lease published again
  once confirmed ([Leasing an address](#leasing-an-address), step 3.4), after `taker` and
  `tolerance`. Only the sale reads it ([§21](#21-one-order-one-invoice-at-a-time)); a reader that
  does not know it ignores it, so it is no new version of the lease either.

**Opening a lease** of an address, as anyone holding the registry key (the outside only), whatever
its author: the event's `id` is checked first (it is its hash, [§11](#11-nostr-events); one that is
not is ignored, and hides no other event of that `id`); then it opens as a record of type
`registry-onchain` ([§12](#12-sealed-records)) with the outer key of that address and of the event's
author, at the registry address of the address, but for two steps, since anybody can write an
event at that `d` tag: a content of a newer NIP-44 version (step 2 of [§12](#12-sealed-records)) is
ignored there, never a record of a newer format (only a value of a newer version, which the outer
key seals, is one); and its signature is checked only where it decides whether the address is
leased (below). Its value is an object whose `version` is 1 (a number above 1: newer format) and
that is either a withdrawal (`withdrawn` is `true`), or a lease whose `end` is a safe integer and
`sealed` a string. Anything else is ignored. A later format of the lease keeps an outside that this
version opens (NIP-44 v2 under the outer key, a `version` above 1): every reader of this version
then leaves its address alone. Anybody can send copies of a lease under `id`s of their own (another
tag, another date, its content and signature left as they are): each opens as the lease does, and
its signature does not check out. A read of leases keeps of each record only what holding and its
signature need ([§13](#13-relays), Limits).

**Opening it as the sale** (its own leases, [§21](#21-one-order-one-invoice-at-a-time)) or as the
merchant: `sealed` decrypts with the inner key into a JSON object; `version` is 1 (above: newer
format); `address` is the deposit address whose registry address is the `d` tag; `sats` a safe
integer from 1 to 2 100 000 000 000 000; `invoice` and `verifyUrl` both `null`, or `invoice` a
string that decodes ([§19](#19-bolt11)) on network `bc` with an amount of exactly `sats` × 1000 msat
and `verifyUrl` an https URL; `createdAt` and `expiresAt` safe integers with `createdAt` <
`expiresAt`, and, with an invoice, its timestamp and its timestamp + expiry; the outside's `end`
equals `expiresAt` + 120; `sale` as a declaration's ([§20](#20-the-declaration)); `taker` ignored
when it is not a taker tag; `tolerance` read as 0 when it is absent or not a tolerance
([below](#the-merchants-tolerance)). The lease is **confirmed** when `confirmed` is `true`,
not confirmed otherwise.

A record **holds** its address at a time `t` when it is a lease whose `end` ≥ `t` − 300 (the clock
tolerance: another server's clock may be behind), or of a newer format (an unreadable lease is never
written over); a withdrawal, or a lease that ended, holds nothing. An address is **leased** at `t`
when one author of its records holds it. Of each author, walk its records from the newest (the
highest `created_at`, then the lowest `id`, as relays keep them): one that holds the address makes
it leased; one that holds nothing ends the walk, unless an older record of the author holds the
address and the signature of this one does not check out ([§11](#11-nostr-events)): this one is then
passed over. So the signature of a record that holds is never checked (only a holder of the registry
key seals one, and [§27](#27-security) lets it lease the address); only that of a record that would
end an older one's hold is, a withdrawal forged by such a holder included. Leases never end
otherwise: like a declaration, a lease stays, so that a payment of its address in its time is the
order's for good. Vectors: `onchain-leases.json`, `leased` (with the signatures each case checks).

### Leasing an address

Step 7 of [§17](#17-creating-an-invoice), for an order whose amount allows on-chain:

1. Read the lot (above). Empty: no address.
2. Read the leases of its addresses and their witnesses, at once, on the merchant's relays, each
   with a key of that read alone for NIP-42 (leases are authored by sales the integration does not
   know); fewer than a majority answered either: `network`. The leases: query
   `{"kinds": [30078], "#d": [<registry addresses>], "since": <now − 7200>, "limit": 100}` with the
   registry address of each address of the lot, a complete read ([§13](#13-relays)), complete or
   not (step 3.3 decides). A lease ends at most 4 320 s after its `created_at` (a BOLT11 timestamp
   up to 300 s ahead, 3600 s, the grace period, the clock tolerance): 7200 s keep every lease that
   may still hold its address. The witnesses: query
   `{"kinds": [30078], "authors": [<seen author>], "#o": [<address tags>]}` with the address tag
   of each address of the lot ([Witnesses](#witnesses)), not paged.
3. The **free** addresses: those of the lot not leased now, as far as step 2 read, that no
   witness names (an event of the seen author that checks out, [§11](#11-nostr-events), with an
   address's tag as an `o` tag names that address, whatever its content: one that does not open as a
   witness, or of a newer format, included; vectors: `onchain-witnesses.json`, `names`), and where
   step 2 read no record of the sale whose signature checks out (an earlier call of the order tried
   it: a new lease could be of the second of that call's withdrawal, and either replace the other;
   so the order does without the addresses its earlier calls tried, for 7200 s). In a random order
   (a shuffle from the CSPRNG, so that two servers rarely try the same one), try at most 3 of them,
   one at a time:
   1. Ask the explorer ([below](#explorers)) for the address's transactions. Any transaction
      paying it: it was paid on-chain already; publish a witness `none` of each such transaction
      (below; a failure only logged as a warning), so that the merchant's app takes it out of the
      lot, and try the next one. The explorer fails: stop, no address (`network` for an order
      paid on-chain only).
   2. Publish the lease ([§13](#13-relays), `confirmed` false) on every relay of the merchant's
      list, signed and authenticated with the sale secret; fewer than a majority took it: withdraw
      it (below), then `network`.
   3. **Confirm** the lease: read the address's leases again (as in 2, its registry address alone),
      on every relay ([§13](#13-relays)). It is confirmed when a majority answered, the read is
      complete ([§13](#13-relays)), shows it, shows it as the newest record of its author there (no
      record of the sale is newer; its signature is not checked: one forged by a holder of the
      registry key only keeps the address from the order), and no other author's records lease the
      address now (the walk [above](#leases)). Not confirmed: withdraw it (below), unless the read
      shows another record of the sale there whose signature checks out (another call of the order,
      at once, made it: that one is not this call's to end, [§17](#17-creating-an-invoice)); then
      try the next one, or `network` when fewer than a majority answered.
   4. **Mark** it confirmed: publish the same lease again, `confirmed` true, with `created_at` the
      later of now and the lease's `created_at` + 1 (it replaces the lease), on a majority, else
      `network`.
   5. Else the address is the order's.

**Withdrawing** a lease that was not confirmed: publish its withdrawal ([above](#leases)),
`created_at` the lease's `created_at` + 1 (it replaces the lease, and no later record of the sale),
on every relay of the merchant's list, signed and authenticated with the sale secret; a failure is
only logged as a warning.

No address once the 3 tries or the free addresses are spent. Two servers that lease one address at
once cannot both keep it: each confirms after its own lease is on a majority, so the later of the
two reads sees both (any two majorities share a relay, which sends what it holds:
[§27](#27-security)), and withdraws its own. A lease that is not confirmed never gives its invoice
an address ([§21](#21-one-order-one-invoice-at-a-time)): the address is the order's only once its
lease is marked. So its withdrawal is safe even when only some relays take it: it frees the address
there, which the order never had. A lease that was confirmed is never withdrawn, whatever fails
after its confirmation (its mark, the checkout link, the declaration): it holds its address until
its end, since a withdrawal that only some relays took would leave them disagreeing on whether an
address that may be the order's is held. Vectors: `onchain-leases.json`, `confirmed`.

### Payment URIs

The Invoice's `paymentUri` is what the shop's page shows as one QR code:

- with an address: `bitcoin:<address>?amount=<BTC>`, followed by `&lightning=<pr>` when there is
  a Lightning invoice (BIP-21, the "unified QR" wallets read);
- without one: `lightning:<pr>`.

`<BTC>` is the amount in bitcoins, exact, with no trailing zero in its fraction and no fraction
when whole: 49 000 sats is `0.00049`, 100 000 000 sats is `1`. The address and the invoice are
written as they are (lowercase). Vectors: `onchain-addresses.json`, `uris`.

### Explorers

What the blockchain shows comes from one explorer of the Esplora API, **the explorer**:
mempool.space, or the merchant's Bitcoin node when the channel names one
([below](#the-merchants-bitcoin-node)), asked over HTTP ([§15](#15-http)), and from its WebSocket
while `waitForPayment` waits ([below](#waiting-for-an-on-chain-payment)), mempool.space answering
in its place when the node fails and its `fallback` is `"mempool"`; when a transaction was received,
only when no check saw it in time, from BlockCypher:

| Name                      | URL                                       |
| ------------------------- | ----------------------------------------- |
| mempool.space             | `https://mempool.space/api`               |
| mempool.space's WebSocket | `wss://mempool.space/api/v1/ws`           |
| BlockCypher               | `https://api.blockcypher.com/v1/btc/main` |

`<explorer>` is the URL of the explorer asked: mempool.space's, or the node's
([below](#the-merchants-bitcoin-node)).

- **An address's transactions**: GET `<explorer>/address/<address>/txs`, its first answer (a deposit
  address is paid a few times at most). The answer is an array of transactions; each is an object
  with `txid` (64 lowercase hex characters), `vin` an array of objects each with `is_coinbase`
  `true`, or with `txid` (64 lowercase hex characters) and `vout` an integer from 0 to 4 294 967
  295, `vout` an array of objects whose `value` is a non-negative safe integer (sats), all of them
  together at most 2 100 000 000 000 000 (every bitcoin there will ever be: a transaction that pays
  more is none), and `scriptpubkey_address` a string when present, and `status` an object with
  `confirmed` a boolean and, when it is true, `block_height` a non-negative safe integer. A
  transaction **pays** the address the sum of the `value` of its outputs whose
  `scriptpubkey_address` is the address; those paying it nothing are left out. The **coins** it
  spends: `<txid>:<vout>` (the `vout` in decimal, without leading zeros) of each object of its `vin`
  that is not a coinbase input, in their order. Anything else in the answer is a failure
  (`network`).
- **The chain's height**: GET `<explorer>/blocks/tip/height`: a body of 1 to 9 digits (the only
  plain-text answer of this document: not JSON).
- **Confirmations** of a transaction at height `h`: 0 when not confirmed; else `h` − its
  `block_height` + 1, and at least 1.
- **When a transaction was received**: GET `<BlockCypher>/txs/<txid>?limit=1&includeHex=false`.
  HTTP 404: BlockCypher does not know it yet (it receives it later). Else an object
  whose `hash` is the txid asked and whose `received` is the time BlockCypher first saw the
  transaction, which never changes, as BlockCypher writes it: UTC, matching
  `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`
  (`2026-10-10T13:05:12.345Z`, `2026-10-10T13:05:12.91Z`), a real date and time (a month of 01 to
  12, a day of that month, hours 00 to 23, minutes and seconds 00 to 59: no leap second), read in
  Unix milliseconds (the fraction past milliseconds dropped, never rounded), above 0. Anything else
  is a failure (`network`): another spelling of RFC 3339 is not BlockCypher's. Without a token,
  BlockCypher takes 100 requests an hour from an IP address: it is asked only as below.

The explorer is a third party, and the only one asked what the blockchain shows: a payment counts
as made on what it alone shows ([§27](#27-security)), mempool.space or the node the merchant chose.
It does not say when a transaction was broadcast (mempool.space's first-seen times are 0 for
confirmed transactions): that a transaction came in time is known from a check that saw it then,
which records it (witnesses, below), and otherwise from BlockCypher's time, the same for every
reader; never from an explorer's first-seen time.

### The merchant's Bitcoin node

The merchant may have the server read the blockchain from a node of its own that serves
mempool.space's API (an Umbrel, a server of its own) rather than from mempool.space: the channel's
`bitcoinNode` ([§14](#14-reading-the-channel)), which the merchant's app writes:

```json
{ "url": "http://192.168.1.10:3006", "fallback": "mempool", "payers": false }
```

It is **valid** when it is an object, not an array, whose `url` is a node URL (below), whose
`fallback` is exactly `"mempool"` or `"none"`, and whose `payers` is a JSON boolean, `true` only
when the node is a node of the Internet (below); its other members are ignored. Absent, or invalid
in any way (a string, an array, `null`, a `url` that is not a node URL, a `fallback` absent, `null`
or of another spelling, `"Mempool"`, a `payers` absent or not a boolean, `"true"`, `1`, a `payers`
`true` for a node that is not of the Internet): there is none, the explorer is mempool.space, and
the channel stays valid. Nothing is repaired. Vectors: `bitcoin-nodes.json`, `channels`.

`payers` says whether the pages of checkout links read the chain from the node, as the server does
([§30](#30-checkout-links)): with `true`, the server writes the node in each link's record. A
**node of the Internet** is one whose URL is `https://` and whose host is a name (never an IPv4
address) whose last label is not `local`: a customer's browser is not on the merchant's network,
and a link must never make the browser of each customer probe its own local network. With `false`,
any node URL is valid, `http` to a local host included, and only the server reads the node.

**A node URL**, in its one spelling: `<scheme>://<host>`, then an optional `:<port>`, then an
optional path, 200 characters at most in all (ASCII, by these rules):

- the scheme: `https`, or `http` when the host is local (below);
- the host, in lowercase, either:
  - an IPv4 address: 4 decimal numbers from 0 to 255 separated by `.`, none with a leading zero
    (`0` alone is one), never in 0.0.0.0/8 nor 127.0.0.0/8;
  - or a name: 2 labels or more separated by `.`, each of 1 to 63 characters `a–z 0–9 -`, neither
    starting nor ending with `-`, the last starting with a letter `a–z`; 253 characters at most;
    never `localhost` nor a name ending with `.localhost`. So no trailing dot and no empty label;
- a **local** host: an IPv4 address of 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10
  (the shared address space of RFC 6598, which Tailscale uses), or a name whose last label is
  `local` (mDNS);
- the port: 1 to 5 digits, without a leading zero, from 1 to 65535;
- the path: `/` followed by 0 or more characters from U+0021 to U+007E but `?`, `#`, `@` and `\`,
  not ending with `/` (so `/` alone is not one: the root is written without a path), nor with
  `/api` compared ignoring ASCII case (`/api`, `/API`, `/x/api`: the node's URL, not its API's).

So no user name nor password, no query, no fragment, no IPv6 address, no whitespace. Vectors:
`bitcoin-nodes.json`, `urls`.

**Where the node is read**: its API is mempool.space's, at the same paths.

- REST: `<url>/api` is the `<explorer>` of [Explorers](#explorers);
- WebSocket: `<url>` with its leading `http` made `ws` (`ws://` for `http://`, `wss://` for
  `https://`), followed by `/api/v1/ws`.

`http://192.168.1.10:3006` is read at `http://192.168.1.10:3006/api` and
`ws://192.168.1.10:3006/api/v1/ws`. Everything the server asks mempool.space to follow an address
and confirm its payments, it asks the node (and mempool.space only as `fallback` says, below): an
address's transactions when an address is leased (so an address the node shows paid is skipped, step
3.1 of [Leasing an address](#leasing-an-address)), and in the on-chain part of a check, with the
chain's height ([The on-chain payment](#the-on-chain-payment)); and the WebSocket while
`waitForPayment` waits. BlockCypher is asked as without a node, and the rate source `mempool`
([§26](#26-rate-sources)) is mempool.space's. The node asked is the one the channel read by the call
names ([§14](#14-reading-the-channel)). The rules of [§15](#15-http) hold for the node, but for the
https URL: its URL follows its own rule, above.

**`fallback`**, when the node does not answer a read (no answer, a status that is not 2xx, a
redirect, an answer out of format: whatever is a failure of the explorer):

- `"mempool"`: the same read, of mempool.space. Both failing: `network`. A node that failed a read
  less than 60 s ago, in the same call, SHOULD be asked after mempool.space, so that a node that
  does not answer does not make each read wait for its timeout: mempool.space first, the node
  only when mempool.space fails.
- `"none"`: never mempool.space. While the node does not answer, the on-chain part fails
  (`network`), and so does leasing an address (no address: `network` for an order paid on-chain
  only): nothing is judged on-chain for want of an answer, never final underpaid nor `expired`.
  The order waits until the node answers.

Each read follows this rule on its own, but for the two reads of step 1 of [The on-chain
payment](#the-on-chain-payment): an address's transactions and the chain's height come from one
explorer, never one from each, since the confirmations of a transaction compare its `block_height`
with that explorer's height. They are then one read, which fails when either fails: with
`"mempool"`, both are asked again of mempool.space. The WebSocket follows the rule too: with
`"mempool"`, a connection to the node that fails, or is lost before any message, goes to
mempool.space's WebSocket instead, a node that failed less than 60 s ago being tried after it; with
`"none"`, only the node's, connected again as [below](#waiting-for-an-on-chain-payment). Vectors:
`bitcoin-nodes.json`, `reads`.

A node on the merchant's own network, in `http` (`http://192.168.1.10:3006`,
`http://umbrel.local`), is reachable only by a server on that network (a shop the merchant hosts,
or one that joined it, by Tailscale for one). Any other server fails every read of it, and its
`fallback` applies: with `"none"`, no address is leased and no on-chain payment is judged.
[§27](#27-security) says what a node's URL lets a merchant reach.

### Replacements

A payer whose transaction is slow to confirm may broadcast another one in its place, with a higher
fee (RBF): the replacement has another txid, explorers forget the first one (`GET
<explorer>/tx/<txid>` answers HTTP 404 once it left the mempool), and none of them keeps for long
which transaction replaced which. Both spend one coin at least of the same: two transactions that
spend a common coin are alternatives, at most one of them is ever mined. A replacement keeps the
time of the payment it replaces, for at most what that payment paid the address: what it pays more
was added after, and counts at the replacement's own time, as any other payment would. So a fee
bump after the lease's end still pays the order, and a payment of 1 sat in time cannot become a
whole one later.

The **parts** of transactions, from a list of transactions, each with its txid, the sats it pays
the address, its coins (or those recorded of it), an order (when it was seen; or unknown) and
whether the explorer lists it now:

1. A txid given twice is taken once, its first entry. Sort the transactions by their order (an
   unknown one after every known one), then by txid (ascending).
2. In that order, the **roots** of each transaction: the transactions before it that spend one of
   its coins; when there is none, its roots are itself, else the roots of each of those, put
   together (each once, in the order of step 1).
3. Each root has its sats to give. In the order of step 1, each transaction the explorer lists:
   when its roots are itself, one part, all its sats, of its own, which leaves it nothing to give;
   else, for each of its roots in the order of step 1, a part of the least of what it still pays
   and what that root still has to give, of that root (when above 0), taken from both; what it
   still pays then is a part of its own.

A part of a root counts as that root would: at its time, as a payment in time when it came in time.
A transaction that spends no recorded coin of the payment it replaces is a payment of its own: a
witness keeps the first 100 coins of a transaction (below). Vectors: `onchain-replacements.json`.

### Witnesses

A **witness** says that the integration saw a transaction paying an address of its lot, and when:
during the lease of an invoice of an order (that order's sale, and the invoice's `expiresAt`), or
at no lease's time (`none`). Only the integration writes them; the merchant's app reads them.

| Name                       | Derivation                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| seen secret                | HKDF(integration key, `sattle.me/integration`, `onchain-seen/nostr-secret-key/v1`)         |
| seen author                | hex(BIP-340 x-only public key of the seen secret)                                          |
| seen address key           | HKDF(integration key, `sattle.me/integration`, `onchain-seen/address-key/v1`)              |
| witness address of A, T, S | hex(HMAC(seen address key, UTF-8 of `<A>/<T>/<S>`)), `<S>` the sale author (hex) or `none` |
| order tag of A, S          | hex(HMAC(seen address key, UTF-8 of `order/<A>/<S>`)), `<S>` as above                      |
| address tag of A           | hex(HMAC(seen address key, UTF-8 of `address/<A>`))                                        |

(`A` the address, `T` the transaction's id, both lowercase.) A witness is a sealed record
([§12](#12-sealed-records)) of type `integration-onchain-seen`, author the seen author, key the
channel encryption key, at the witness address of its `A`, `T` and `S`, with the tags
`["o", <order tag of its A and S>]` and `["o", <address tag of its A>]` (after the `d` tag, in
this order), `created_at` when it was seen. Its value:

```json
{
  "version": 1,
  "address": "<A>",
  "txid": "<T>",
  "sale": "<S, or null for none>",
  "sats": 49000,
  "inputs": ["<txid>:<vout>"],
  "replacement": false,
  "expiresAt": 1791379180
}
```

- `sats`: what `T` pays `A`, a JSON number from 1 to 2 100 000 000 000 000;
- `inputs`: the coins `T` spends ([Explorers](#explorers)), its first 100 in their order (0 for a
  coinbase transaction);
- `replacement`: `true` when the witness holds `T` for the sale only as a replacement, for what it
  takes of the payments in time it replaces: `T` itself came after the lease's end. `false` for
  any other witness, `none` included;
- `expiresAt`: the `expiresAt` of the invoice whose lease `T` came in, or stands for as a
  replacement, a JSON number; `null` for `none`. An address is leased again for a later invoice of
  the order once nothing paid it ([§20](#20-the-declaration)): `expiresAt` tells which invoice a
  transaction pays.

Opening one: the event opens as such a record; `version` is 1 (a number above 1: newer format);
`address` is a deposit address, `txid` 64 lowercase hex characters, `sale` null or 64 lowercase hex
characters, `sats` a safe integer from 1 to 2 100 000 000 000 000, `inputs` an array of at most
100 distinct coins as written above, `replacement` a boolean, `false` when `sale` is null,
`expiresAt` null when `sale` is null and a safe integer otherwise (more fields ignored); the `d` tag
is the witness address of `address`, `txid` and `sale`, an `o` tag the order tag of `address` and
`sale`, and an `o` tag the address tag of `address`. A witness at the address of `S` and one at the
address of `none` never replace each other; a later witness of the same `A`, `T` and `S` replaces
an earlier one (the relays keep the newest), whatever its `expiresAt`.

A witness of `S` with the `expiresAt` of an invoice is **of that invoice**; a witness of another
sale, or of `S` with another `expiresAt`, is **of another invoice**; a witness `none` is of no
invoice.

**Reading the witnesses of an invoice** with an address `A`, for its order's sale `S`: query
`{"kinds": [30078], "authors": [<seen author>], "#o": [<order tag of A, S>, <order tag of A, none>, <address tag of A>]}`
on the merchant's relays, not paged, with a key of that read alone for NIP-42; fewer than a majority
answered: `network`. It finds every witness of `S` and of `none` at `A`, and every one of another
sale that names `A` with the address tag. Of each witness address, the newest event that opens is
the witness; one of a newer format (its event checked out, [§12](#12-sealed-records): a relay cannot
forge one) is kept as such (what it names cannot be read, but its `d` tag can be told). A witness
that holds none of the read's `o` tags, or whose `address` is not `A`, is of no invoice of this read
and is ignored, of a newer format or not (its tags can be read when its value cannot): only a relay
that does not keep to the filter sends one. A transaction may pay the addresses of two orders (a
batch of withdrawals): the witnesses at each address tell its own order.

**Publishing a witness**: on every relay of the merchant's list ([§13](#13-relays)), signed and
authenticated with the seen secret, with both tags and its `expiresAt`: of a sale, that of the
invoice whose check saw it; `null` for `none` (a witness without it does not open). A witness of a
sale is published on a majority, else `network`: it is what proves later that the transaction came
in time. A witness `none` is published for the merchant's app only: a failure is logged as a
warning. Vectors: `onchain-witnesses.json`.

### The merchant's tolerance

The merchant may accept an on-chain payment a little short of the amount as paying the order in
full (its **tolerance**, set in the merchant's app for its point of sale and its integrations
alike): an order whose payment in time is short of its amount by no more than that share is paid
(being confirmed first, as any on-chain payment). One short by more is underpaid, as without
tolerance: its whole rest is asked, never only what the tolerance would leave.

A **tolerance** is an integer of basis points (hundredths of a percent) from 0 to 1000 (10 %):
anything else (a fraction, a string, a negative number, above 1000) is read as 0, none. The
channel's `onchainTolerance` gives the merchant's ([§14](#14-reading-the-channel)); an order takes
the one of the channel `createInvoice` read, which its lease keeps ([Leases](#leases), `tolerance`):
its payment is judged with that one whatever the merchant sets later, by every check of its server
and by the merchant's app. An invoice whose order's lease is not found among the sale's records, or
names other terms (`sats`, `expiresAt`), is judged without tolerance.

For an amount `sats` and a tolerance `T`, the **least accepted** is
`sats − floor(sats × T / 10000)`: the amount the order's payments in time (on-chain, and by its
rest invoices, [below](#the-rest-of-an-underpayment)) must reach, on integers. Example: 49 000 sats
at 500 (5 %): 2 450 sats may be missing, 46 550 sats pay the order. Lightning alone never pays less
than an invoice's amount: the tolerance applies only when something counts on-chain (step 4
below). Vectors: `onchain-tolerances.json`.

The tolerance is the merchant's: it is never written where the shop's page or the customer reads
([§27](#27-security)). Only an acceptance record tells the pages of an order's checkout links that
its payment counts ([Acceptance records](#acceptance-records)).

### The merchant's acceptance

The merchant may also accept by hand, in its app, what an order received as paying it in full: an
order underpaid by more than its tolerance, whose customer could still pay the rest, and which the
merchant would rather settle at what came. The app then publishes the **merchant's acceptance** of
the invoice, a record of the team: what the order had received when the merchant accepted it. Every
check that counts it judges the order's payment against that amount, when it is less than the least
the order's tolerance accepts (step 4 of [The on-chain payment](#the-on-chain-payment)): what came
in time then pays the order (being confirmed first, as any on-chain payment), and its status is
`unconfirmed`, then `paid`, with `received` below `sats`, as with the tolerance. Unlike the
tolerance, it needs no lease: its address names the order's sale, the invoice's address and its
`expiresAt`, and an order whose lease is not found counts it all the same.

Its address, from the integration key, the sale author `S` of the order's `ref`
([§10](#10-key-derivations)), the invoice's address `A` and its `expiresAt` `E` (written in the
info as they are, `E` in decimal):

| Name                          | Derivation                                                                             |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| merchant's acceptance address | hex(HKDF(integration key, `sattle.me/integration`, `onchain-accepted/<S>/<A>/<E>/v1`)) |

A sealed record ([§12](#12-sealed-records)) of type `integration-onchain-accepted`, author the team,
key the channel encryption key ([§10](#10-key-derivations)), at the merchant's acceptance address,
`created_at` when the merchant accepted. Its value:

```json
{ "version": 1, "received": 30000 }
```

`received`: what the order had received in time when the merchant accepted it (on-chain, and by its
rest invoices, [below](#the-rest-of-an-underpayment)), a JSON number, from 1 and below `sats`.

**Publishing it** (the merchant's app). Only the merchant writes it: it is signed by the team, whose
secret no integration key holds ([§27](#27-security)). The merchant's app MUST:

1. publish it on every relay of the merchant's list, and send it again (the same event) to the
   relays that did not take it, only while now < `E` by its clock, synchronized as a server's
   ([§2](#2-conventions)), each request bounded as a server's relay request ([§13](#13-relays):
   60 s at most); never at or after `E`. What it sends reaches the relays by `E` + 60, before the
   lease's end (`E` + 120), after which a check may give `expired`;
2. make one per invoice, never withdrawn nor replaced;
3. when fewer than a majority of the merchant's relays took it before `E`, tell the merchant that
   the acceptance is not made: the order is judged without it, and the merchant settles it by hand.

**Reading it**: a check of an invoice with an address reads it, when some transaction pays `A`, at
the same time as the witnesses (step 1 of [The on-chain payment](#the-on-chain-payment)): query
`{"kinds": [30078], "authors": [<team>], "#d": [<merchant's acceptance address>]}` on the merchant's
relays, not paged, on every relay ([§13](#13-relays)), with a key of that read alone; fewer than a
majority answered: `network`. It is a request of the check's call as any other: a relay whose
request in it ran out of time, or whose connection failed, counts as failed at once for the
witnesses read again later in the check (step 3 of [The on-chain payment](#the-on-chain-payment),
[§13](#13-relays)). Each event opens as a record of type `integration-onchain-accepted`, author the
team (the integration key's `<team>`, [§8](#8-the-integration-key)), key the channel encryption
key, at the merchant's acceptance address; its value is valid when it is an object whose `version`
is 1 and whose `received` is a safe integer from 1, below `sats` (more fields ignored); a `version`
above 1 is a newer format. Both are read by their value, whatever their spelling
([§2](#2-conventions)): a `received` of `3e4` is 30000, a `version` of `1.0` is 1, and one of `1.5`
is above 1. Anything else is ignored, and so is a record whose `created_at` is after the lease's end
(`E` + 120), of a newer format or not. A record of a newer format logs a warning, whatever its date
and however many relays sent it. Its `created_at` is not compared with now.

**Counting it**: the majority of the merchant's relays holds the truth. A record counts only when a
majority of the merchant's relays sent it (a copy that checks out, [§11](#11-nostr-events): its
`id` is its hash and its `sig` verifies), as for the choice among an order's invoices
([§21](#21-one-order-one-invoice-at-a-time)): one that fewer than a majority sent does not count,
whichever relays sent it. A relay sent what its answer held when its read ended; one still reading
when the read goes on sent nothing, whatever events of its answer had come (the read is not paged,
[§13](#13-relays)). Of the records that count (valid, or of a newer format), the newest (the
highest `created_at`, then the lowest `id`, as relays keep it) decides: a valid one is the
merchant's acceptance; one of a newer format leaves the order without one (a check never judges more
leniently than it can read: a newer format may say less). With none, the order has none. A check
publishes none of them again.

So every check judges with the record a majority holds, and none with one only a minority holds:
the status never depends on which relays answer while those that hold it answer in time
([§27](#27-security) says what one that fails does). Nothing is published at or after `E` (rule 1):
what a majority holds at the lease's end stays so, and an `expired` status, given only after that
end, stays final, but for the exception [§3](#3-data-model) names: a relay that holds the
acceptance and fails at a check ([§27](#27-security)).

The bound on `created_at` is a safety net, not the guarantee. An app that keeps rule 1 signs a
`created_at` before `E` by its own clock, however wrong that clock is: the bound never sets its
records aside, and sets aside only a record dated after the lease's end, which only an app that
breaks rule 1 makes. The risk is a clock that runs behind: an app whose clock is `d` seconds behind
publishes up to `E` + `d`, its record still dated before `E`; with `d` above 60 s, what it sends may
reach a majority after the lease's end, after a check gave `expired`, and a later check counts it:
hence rule 1's synchronized clock ([§27](#27-security)).

Vectors: [`vectors/app/merchant-acceptance.json`](vectors/app/merchant-acceptance.json) (addresses
and records made by the merchant's app, opened or not; in `made`, records made here that the app is
not asked to make), `onchain-payments.json` (statuses with them,
`merchantAccepted`, each with how many relays sent it).

### The on-chain payment

The on-chain part of an invoice with an address `A`, `sats` and `expiresAt`, for its order's sale
`S` (the sale author of its `ref`, [§10](#10-key-derivations)), checked at time `now` (Unix
seconds, the server's synchronized clock, read once the explorer answered step 1, never before:
what it lists was broadcast by then), with `end` = `expiresAt` + 120 (its lease's end):

1. Ask the explorer for `A`'s transactions and the chain's height, both of one explorer
   ([`fallback`](#the-merchants-bitcoin-node)). When some pay `A`, read the witnesses of the invoice
   ([above](#witnesses)): those of this invoice, of other invoices, of `none`, and those of a newer
   format; and, at the same time, the merchant's acceptance, on every relay
   ([above](#the-merchants-acceptance)). Either read failing fails the check (`network`),
   whatever the other gives: the check may fail as soon as one fails (the other's requests then
   ending, or going on until the call is done), or once both ended; it is `network` either way.
2. **The parts** of the transactions paying `A` ([Replacements](#replacements)), from the witnesses
   of this invoice and of other invoices (each its `txid`, `sats`, `inputs`, its `created_at` as
   its order, listed when the explorer lists its `txid`) and the transactions paying `A` no such
   witness names (their sats and coins as the explorer gives them, their order unknown): a
   replacement of another invoice's payment stands for that one.
3. Each transaction `T` paying `A`, in the explorer's order, is **in time** (it came while the
   lease ran), a **replacement** (it came after, and stands for payments it replaces), **late** (it
   came after, and stands for none), **another's** (another invoice's) or **undecided**:
   1. a witness of another invoice names it, or one of its parts is of a root one names:
      another's, whatever else names it; nothing is published nor asked for it;
   2. else, a witness of this invoice names it with `replacement` false: in time;
   3. else, a witness of a newer format at the witness address of `A`, `T`, `S`: undecided;
   4. else, when `now` ≤ `end` (listed now, it was broadcast by now): in time; publish its witness
      of this invoice (`replacement` false; on a majority, else `network`);
   5. else, when a witness of this invoice names it with `replacement` true: a replacement (an
      earlier check found it so, and BlockCypher's time of it late);
   6. else no check saw it in time. When all its parts are of roots other than itself: a
      replacement, nothing to ask. Else ask BlockCypher when it was received
      ([Explorers](#explorers)), whatever witness `none` names it (one made when leasing another
      order, or by a check that knew less):
      - received at or before `end` (its milliseconds at most `end` × 1000): in time; publish its
        witness of this invoice (`replacement` false; on a majority, else `network`);
      - received after, or not known to BlockCypher yet (HTTP 404: it will be received after
        `now`, so after `end`): a replacement when one of its parts is of a root other than itself,
        else late;
      - it fails: `network`.

   A replacement of step 6 is undecided instead when a witness of a newer format names no
   transaction the explorer lists (it may be of a payment it replaces), and so is a late one; else
   publish the witness of this invoice of a replacement (`replacement` true; on a majority, else
   `network`),
   so that the merchant's app tells its order and a later replacement of it is told too. A late
   one: its payment reaches the merchant's wallet, but no order, and nothing waits for BlockCypher;
   when no witness `none` names it, publish one, so that the merchant's app takes the address out
   of the lot; but not over a witness of a newer format at the witness address of `A`, `T` and
   `none` ([§12](#12-sealed-records): it is never written over).

   When this check published a witness of this invoice, it reads the witnesses again once they are
   all on a majority, on every relay ([§13](#13-relays); as in step 1, fewer than a majority
   answered: `network`), and applies step 3.1 again with them (with the parts of step 2 made again
   from them, for this rule only): a transaction it now makes another's is another's. Of two checks
   that publish witnesses of one transaction at once for two sales, the later reader sees both (the
   other's witness is on a majority, and this read waits for every relay). Two invoices of one sale
   at one address write theirs at one witness address, where the newer replaces the other: both may
   then count it, for the same order.

4. A part **counts** when its root is in time: a transaction paying `A` in time (step 3), or one the
   explorer no longer lists whose witness of this invoice has `replacement` false. Every other part
   counts for nothing, and every part of an undecided or another's transaction. `received` = the sum
   of the parts that count; the **order's transactions**: those paying `A` with a part that counts,
   in the explorer's order. When the invoice's rest invoices ([below](#the-rest-of-an-underpayment):
   the rest part, checked at the same time as steps 1 to 3) paid `sats` or more, nothing is due
   on-chain (they pay the order, step 2 below). Else what is **due** on-chain is
   max(1, min(`L`, `M`) − `R`), on integers: `L` the least accepted of `sats` with the order's
   tolerance ([above](#the-merchants-tolerance); `sats` without one, or while the sale's records
   are not read), `M` the `received` of the merchant's acceptance
   ([above](#the-merchants-acceptance); `sats` without one), `R` what the rest invoices paid. `R`
   is taken once from the lesser of `L` and `M`, whichever it is (`M`, what the order had received
   when the merchant accepted, counts the rest invoices paid by then, as `L` counts every payment).
   At least 1 sat: something counts on-chain for the tolerance or the merchant's acceptance to
   apply. Example: 49 000 sats, no tolerance, a merchant's acceptance of 30 000, a rest invoice of
   9 000 paid: 21 000 sats are due on-chain; with 30 000 paid by rests, 1 sat.
   - `received` < due: **underpaid**, final once `now` > `end` and no transaction is undecided.
   - else, `confirmations` = the least confirmations of the order's transactions, `txids` their
     ids. Below 3: **unconfirmed**. At 3 or more: **paid**, with these txids.

An overpayment is paid (the difference reaches the merchant with the rest), and so is a payment the
order's tolerance or the merchant's acceptance accepts (`received` then below `sats`). A failure of
the explorer, of the relays or of a witness's publication is `network`. A transaction may be
replaced (RBF) or dropped: the explorer's list is the truth at each check, so `received` may go
down, and a replacement counts for the payment it replaces. What a transaction pays an address
counts for one invoice at most: one that witnesses of two invoices at that address name counts there
for neither (the merchant's app counts it for no order); a transaction that pays the addresses of
two orders pays each what it pays that order's address. A check never publishes a witness of its
invoice for a transaction a witness of another invoice names (it would replace that of another
invoice of the order: same `A`, `T` and `S`). A payment seen by no check before the lease's end is
told by BlockCypher's time: BlockCypher is asked only then, and the witness it leads to spares every
later reader the question. Vectors: `onchain-payments.json` (with the transactions each check asks
BlockCypher about).

The status of an invoice ([§22](#22-payment-check)) combines its parts: the Lightning part of its
own invoice, its on-chain part and its rest part ([below](#the-rest-of-an-underpayment)); `paid by
rests` is what its rest invoices paid:

1. its Lightning invoice paid ([§22](#22-payment-check)): `paid` with `method: "lightning"`;
2. else paid by rests at least `sats` (its rest invoices alone pay it): `paid` with
   `method: "mixed"`, `txids` empty (the on-chain part needs nothing more);
3. else its on-chain part paid: `paid` with `method: "onchain"` when no rest invoice was paid, else
   `method: "mixed"`;
4. else its on-chain part unconfirmed: `unconfirmed`;
5. else an error of a part: that error (the Lightning part's first, then the rest part's, then the
   on-chain part's);
6. else, when the Lightning part is final (`expired`, or no Lightning invoice), the on-chain part
   is final underpaid (or no address) and the rest part is final: `expired`; else `open`, with its
   `rest` ([below](#the-rest-of-an-underpayment)).

All parts are asked at once. `received` is the on-chain part's `received` (0 when it failed, in 2)
plus paid by rests, `"0"` without an address: an `expired` invoice with `received` above 0 was
underpaid, and the merchant received that sum (the integrator settles it with the customer).
`preimages` (of `mixed`) are those of the rest invoices paid, in the order of the rest invoices.

### The rest of an underpayment

When less than the amount came on-chain in time, the rest is payable in Lightning too: the server
asks the merchant's Lightning address for an invoice of the rest as soon as a payment check sees
the underpayment, declares it for the order's sale, and publishes it for the pages of the order's
checkout links, which show it at once. From 1 000 sats (the on-chain floor), the rest is payable
on-chain to the same address as well; below, in Lightning only. Until the invoice's end: nothing
moves the end of an order.

**Rest invoices**: the declarations of the order's sale whose `rest` names the invoice: its address
`A` and its `expiresAt` ([§20](#20-the-declaration), read as
[§21](#21-one-order-one-invoice-at-a-time) says; another invoice of the order that leased `A` has
rest invoices of its own), sorted by their invoice's timestamp, then payment hash.

**The rest part** of an invoice with an address: each of its rest invoices checked as a Lightning
part ([§22](#22-payment-check), its end its own timestamp + expiry). **Paid by rests**: the sum of
the amounts of those paid. The rest part is final when each of them is `expired` or paid; its
error is the first error of one of them (one that fails counts as not paid). A check of an invoice
with an address reads the sale's declarations ([§21](#21-one-order-one-invoice-at-a-time)) for
them, at the same time as the explorer; fewer than a majority of the relays answering is
`network`. A rest invoice whose declaration fewer than a majority of the merchant's relays sent
(its publication may have reached a minority only, when asking for it failed: a later read could
miss it) is published again on a majority before it is checked, shown or recorded, as an order's
pending invoice ([§21](#21-one-order-one-invoice-at-a-time)); that failing, the rest part's error
is `network`.

**The status's `rest`** ([§3](#3-data-model)): when the status is `open`, its `received` `T` is
above 0, and now < `expiresAt`:

- `sats`: `sats` − `T`;
- `bolt11`: the latest of the rest invoices whose amount is exactly that, not paid, with now < its
  timestamp + expiry, whose rest record is on a majority of the relays (below); null when there is
  none;
- `paymentUri`: from 1 000 sats, `bitcoin:<A>?amount=<BTC>`, followed by `&lightning=<bolt11>` with
  one (as a [payment URI](#payment-uris)); below, `lightning:<bolt11>`, null without one.

Else `rest` is null.

**Asking for a rest invoice**: a payment check (`getStatus`, `waitForPayment`, and the check of each
of an order's earlier invoices that may still be paid, one alone or several: step 1 of
[§21](#21-one-order-one-invoice-at-a-time)) whose status is `open` with a `rest`, and that has no
rest invoice of exactly that rest, not paid, with now < its timestamp + expiry (whether its rest
record is known on a majority or not: that is published again, below), asks for one when:

1. now + 60 ≤ `expiresAt`: a rest invoice is asked with 60 s left at least;
2. the sale's lease of `A` ([§21](#21-one-order-one-invoice-at-a-time), opened as the sale) has the
   invoice's `sats` and `expiresAt`: it gives the declaration's price and note;
3. the rest is within the Lightning address's sendable sats ([§16](#16-lightning-address), its pay
   request asked then).

`now` here is read when the check decides, once its turn to ask came (after the rest invoices were
read again, below), never earlier: a check that waited for another one has less time left.

Then, in this order: GET `callback` with `amount` = the rest × 1000, `expiry` = `expiresAt` − now
and `comment` = the lease's note when it fits ([§17](#17-creating-an-invoice), step 5); check the
answer ([§18](#18-invoice-checks), with the rest as the amount and the expiry asked as
`durationSeconds`); declare it ([§20](#20-the-declaration)) with the lease's price and note and
`rest` = `{"address": A, "expiresAt": expiresAt}`, on a majority of the merchant's relays; publish
its rest record (below) on a majority. It is then the status's `bolt11`. A failure of any of these
steps (`network`, `invalid_invoice`, a refusal of the Lightning address) is logged as a warning,
never the check's error: `bolt11` stays null and the next check asks again; a cancellation stops the
check. Within one client, the checks of one invoice ask one at a time, each after the rest invoices
were read again: a rest invoice of exactly the rest declared meanwhile (by another check) and not
ended is taken instead, checked as any rest invoice; when it is paid, the on-chain part is checked
again with what is now paid by rests. Two servers may still ask two invoices of one rest: either
pays it, both pay more.

**Rest records**: a rest record shows a rest invoice to the pages of the order's checkout links,
which cannot read the registry. Its keys, from the integration key, the order's `ref`, `A` and the
invoice's `expiresAt` `E` (written in the info as they are, `E` in decimal):

| Name                       | Derivation                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------- |
| rest key                   | HKDF(integration key, `sattle.me/integration`, `checkout-rest/<ref>/<A>/<E>/key/v1`)              |
| rest secret                | HKDF(integration key, `sattle.me/integration`, `checkout-rest/<ref>/<A>/<E>/nostr-secret-key/v1`) |
| rest author                | hex(BIP-340 x-only public key of the rest secret)                                                 |
| rest encryption key        | HKDF(rest key, `sattle.me/checkout`, `rest/encryption-key/v1`)                                    |
| rest record address of `H` | hex(HKDF(rest key, `sattle.me/checkout`, `rest/address/<H>/v1`)), `H` the payment hash (hex)      |

A checkout link's record of an invoice with an address carries its rest author and rest key
([§30](#30-checkout-links)), never the rest secret: whoever holds the link reads its rest records,
only the integration key writes one. A rest record is a sealed record ([§12](#12-sealed-records))
of type `checkout-rest`, author the rest author, key the rest encryption key, at the rest record
address of its invoice's payment hash, with the tags `[["d", <address>], ["expiration",
<expiresAt + 604800, decimal>]]` (`expiresAt` the order's invoice's, as its checkout links'),
`created_at` now. Its value:

```json
{ "version": 1, "invoice": "<pr>", "verifyUrl": "<verify>" }
```

It is published on every relay of the merchant's list, signed and authenticated with the rest
secret, and succeeds on a majority ([§13](#13-relays)). A check that finds rest invoices of the
invoice, before the end of its grace period (now < `expiresAt` + 120), reads its rest records
(`{"kinds": [30078], "authors": [<rest author>]}`, not paged, with a key of that read alone) and,
when a majority of the relays answered, publishes again the record of each of them that fewer than a
majority of the relays sent (their first publication may have failed), a failure logged; but not one
whose rest record address holds a record of a newer format that a relay sent
([§12](#12-sealed-records): its event checked out): a newer version recorded it, never written over,
and it counts as known. When fewer than a majority answered, it publishes none again: such a read
decides nothing ([§13](#13-relays)), and what the other relays hold is never written over unseen. A
rest invoice whose record is not known on a majority (not sent by a majority, nor taken by one now,
nor held by a record of a newer format; when fewer than a majority answered, all of them but those a
majority took now) is never the status's `bolt11`: a checkout link's page could not see its payment.
The page reads the relays its link names, the merchant's list when the link was made: a merchant who
changes the list while an invoice runs may leave its links' pages without its rest records: they
then offer the rest on-chain only, and do not see what rest invoices paid (the server's status
holds).

**Reading a rest record** (the page): it opens as a record of type `checkout-rest` with the rest
encryption key, at its own `d` tag, by the rest author its link's record names; its value is an
object whose `version` is 1 (a number above 1: a newer format, left aside), `invoice` a string that
decodes ([§19](#19-bolt11)) on network `bc` with an amount above 0, a whole number of sats, below
the link's `sats`, a timestamp at least the link's `createdAt` − 300 and a timestamp + expiry at
most its `expiresAt` + 300, `verifyUrl` an https URL; and its `d` tag is the rest record address of
the invoice's payment hash. An event at the link's acceptance record address
([Acceptance records](#acceptance-records), by the same author, which the read of rest records
also returns) is no rest record, of a newer format or not. Anything else is ignored.

**The merchant's app** counts a rest invoice's payment for the order's sale by its declaration, as
any Lightning payment; an order whose on-chain payment in time and rest invoices paid reach its
amount (or its least accepted, [above](#the-merchants-tolerance), or what the merchant accepted,
[above](#the-merchants-acceptance), as step 4 of [The on-chain payment](#the-on-chain-payment)
says) is paid ("mixed"), being confirmed until its on-chain part is 3 confirmations deep.

Vectors: `onchain-rests.json` (keys, records, declarations, when a check asks for an invoice and
which), `onchain-payments.json` (statuses with rest invoices),
[`vectors/app/checkout-rest.json`](vectors/app/checkout-rest.json) (a link and its rest record, end
to end).

### Acceptance records

The page of a checkout link cannot know the merchant's tolerance ([§27](#27-security)) nor read the
merchant's acceptance ([above](#the-merchants-acceptance)): an order whose tolerance or merchant's
acceptance accepted less than its amount would read underpaid there, its customer asked for the rest
and never sent back to the shop. An **acceptance record** tells it that this payment counts:
what was received when the server accepted it, never the tolerance.

Its address, from the rest key of the invoice ([Rest records](#the-rest-of-an-underpayment)):

| Name                      | Derivation                                                    |
| ------------------------- | ------------------------------------------------------------- |
| acceptance record address | hex(HKDF(rest key, `sattle.me/checkout`, `rest/accepted/v1`)) |

A sealed record ([§12](#12-sealed-records)) of type `checkout-accepted`, author the rest author,
key the rest encryption key, at the acceptance record address, with the tags `[["d", <address>],
["expiration", <expiresAt + 604800, decimal>]]` (as a rest record's), `created_at` now. Its value:

```json
{ "version": 1, "received": 46600 }
```

`received`: the status's `received` (a JSON number) when it was published.

**Publishing it**: a check (`getStatus`, `waitForPayment`, and the check of an order's earlier
invoices) of an invoice with an address whose status is `unconfirmed`, or `paid` with `txids` not
empty, with `received` below `sats` (the order's tolerance or the merchant's acceptance accepted
it), before `expiresAt` + 604800 (the life of its links), reads the invoice's acceptance records
(`{"kinds": [30078], "authors": [<rest author>], "#d": [<acceptance record address>]}`, not paged,
with a key of that read alone). Unless a majority of the merchant's relays each sent a valid one
(opened as below, without the link's bound: `received` from 1, below `sats`) whose `received` is at
most the status's (the newest each sent), or a relay sent one of a newer format (its event checked
out; never written over, [§12](#12-sealed-records)), it publishes one with the status's `received`
on every relay of the merchant's list, signed and authenticated with the rest secret, on a majority.
When fewer than a majority answered the read, it publishes none: such a read decides nothing
([§13](#13-relays)), and what the other relays hold, of a newer format perhaps, is never written
over unseen. Either failure (fewer than a majority answering, or taking it) is logged as a warning,
never the check's error: the next check reads and publishes again. A replacement (RBF) that lowers
what counts and leaves the order accepted publishes a newer record of less; one that leaves it
underpaid publishes none, and the page, which then counts less than the record says, shows the
underpayment.

**Reading an acceptance record** (the page): it opens as a record of type `checkout-accepted` with
the rest encryption key, at the acceptance record address, by the rest author its link's record
names; its value is an object whose `version` is 1 (a number above 1: a newer format, left aside)
and whose `received` is a safe integer from 1, below the link's `sats` (more fields ignored).
Anything else is ignored. Of several, the newest counts (`created_at`, then the lowest `id`, as
relays keep it). With one, what came in time (on-chain, and by the rest invoices paid) is enough
from the least of its `received` and the link's `sats` on, provided something counts on-chain: the
page shows the payment being confirmed, then paid (on-chain 3 confirmations deep on the explorer it
reads, the node of the link's record, else mempool.space, for that least, less what the rest
invoices paid), and sends the customer back to the shop as for any payment. The page counts less
than the server, never more ([§30](#30-checkout-links)): a payment it did not see in time may leave
it underpaid there while the server's status is paid.

Vectors: `onchain-rests.json` (the acceptance record address of each invoice, records opened),
`onchain-payments.json` (the acceptance record a check publishes, `acceptance`; the one the relays
hold, `accepted`).

### Waiting for an on-chain payment

`waitForPayment` ([§23](#23-waiting-for-a-payment)) of an invoice with an address checks its
Lightning part every `intervalMs` as for any invoice, and its on-chain part when the explorer's
WebSocket ([Explorers](#explorers): mempool.space's, or the merchant's Bitcoin node's) says
something changed, rather than every `intervalMs`:

- once connected, it sends `{"action": "want", "data": ["blocks"]}` and
  `{"track-address": <address>}`;
- it checks the on-chain part at each connection (what happened before was not pushed), at each
  message holding `address-transactions`, `block-transactions` or `address-removed-transactions`
  (transactions of the address entering the mempool, confirmed, or leaving it unconfirmed) or
  `block` (a new block: one more confirmation), and every 60 s at least (a socket may go quiet
  without closing);
- the socket lost, it connects again after 1 s, doubled at each failure up to 30 s: a connection
  lost before it received a message is a failure (each connection starts a check: a server that
  accepts and drops every connection is not connected to every second), one that received a
  message sets the delay back to 1 s; meanwhile the on-chain part is checked every 60 s. With a
  node whose `fallback` is `"mempool"`, a connection to the node that fails goes to mempool.space's
  WebSocket at once ([The merchant's Bitcoin node](#the-merchants-bitcoin-node)): the delay
  follows a failure of that one;
- the rest invoices the last check found, not final, are checked every `intervalMs`, as the
  Lightning part; when one of them is paid, the on-chain part (and its rest part) is checked again
  at once, and no status is given before that check ended: the on-chain part was judged against
  what was due before (it may read final underpaid, and the status `expired`, with the rest paid);
- a merchant's acceptance ([above](#the-merchants-acceptance)) comes with no transaction and no
  message of the explorer: the wait sees it at its next check of the on-chain part, within 60 s,
  and meanwhile still gives the status's `rest` (the page may still offer the rest that long);
- each status combines the last result of the parts ([above](#the-on-chain-payment)); each check
  of the on-chain part publishes an acceptance record when its status calls for one
  ([above](#acceptance-records)).

`getStatus` never opens the WebSocket: one check of each part (it may ask for a rest invoice, and
publish an acceptance record).

### The merchant's side

The merchant's app attributes what a transaction of its wallet pays each of its addresses (a deposit
names a transaction, not an address: the app takes the transaction's outputs to each address) to the
order whose sale a witness of that transaction at that address names: it reads the witnesses of its
integrations (by their seen authors). A witness with `replacement` false names a transaction of the
order; one with `replacement` true, when one of the transaction's parts
([Replacements](#replacements): from the witnesses of that sale at that address, ordered by
`created_at`, the transaction alone listed) is of a root whose witness of that sale has
`replacement` false. Then the lease of that sale at that address (it holds the registry key and the
reading key): the lease's `sale` and `taker` show the sale as for a Lightning payment, paid when the
witness of that root was seen (its `created_at`, at the latest the lease's `end`). Whether what came
in time pays the order is judged with the lease's `tolerance` and the merchant's acceptance of that
invoice ([above](#the-merchants-acceptance): only when a majority of the merchant's relays hold it),
as its server judges it. What a transaction pays an address that no witness of a sale at that
address names, or two of different sales, is no order's; an implementation never counts it for two
invoices either ([The on-chain payment](#the-on-chain-payment)). A witness's `expiresAt` tells which
invoice of the order: that of the lease of the sale at the address whose `end` is `expiresAt` +
120, when it is still there (a later lease of the sale at that address replaces it; the witness
alone then tells the order). The app takes out of each lot the addresses a witness names.
