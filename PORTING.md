# Implementing the specification in a language

How to write an implementation of [SPEC.md](SPEC.md) in a language (TypeScript, PHP, C#, Python,
Java, Go…), each in its own repository: a **port**. Written for developers and for coding agents. Three rules hold throughout: amounts are
exact (integers, never floating-point), no secret ever goes into a repository, and only a
maintainer publishes a release.

## Definition of done

A port is done when, in its own repository and with its own tooling:

1. it passes **every** conformance vector of its pinned copy of this repository
   ([below](#the-pinned-copy-of-the-specification)): [`vectors/`](vectors), the app's vectors
   ([`vectors/app/`](vectors/app)) and the official NIP-44 vectors
   ([`vectors/nip44/`](vectors/nip44)), and its currency table is
   [`currencies.json`](currencies.json);
2. a declaration it makes for the order of [`vectors/app/app.json`](vectors/app/app.json)
   (`declaration`: same reference, invoice, verify URL, price, note and `created_at`) is a valid
   event of kind 30078 by the sale author, with the `d` tag of the vector, whose outside opens with
   the vector's `outerKey` (a plaintext of a multiple of 256 bytes, type `registry-declaration`)
   and whose inside opens with its `innerConversationKey` into exactly the JSON of the app's
   declaration (the vector's `event`, opened the same way);
3. a checkout link it makes for the order of
   [`vectors/app/checkout-link.json`](vectors/app/checkout-link.json) (same channel origin, relays,
   business's name, pay request, price, invoice and verify URL) holds exactly the vector's `value`,
   in a valid event of kind 30078 signed by its own author, with the tags of
   [SPEC.md §30](SPEC.md#30-checkout-links), whose content opens with the encryption key its URL's
   link key derives (a plaintext of a multiple of 256 bytes, type `checkout`);
4. its integration tests cover the cases of [Steps](#steps), 5, against a local relay and fakes
   of the Lightning address, of the rate sources and of the explorers (mempool.space and a
   merchant's Bitcoin node, REST and WebSocket; BlockCypher): never the network;
5. the invoices it stores are the JSON of [SPEC.md §3](SPEC.md#3-data-model), with the same field
   names: an invoice stored by another implementation is checked by the port, and the other way
   round;
6. its CI runs on every pull request and every push to its default branch
   ([Continuous integration](#continuous-integration));
7. it has a README (English), a CHANGELOG, a LICENSE (MIT) and a SECURITY.md (private reporting
   of vulnerabilities).

## The repository

- One repository per language: `sattleme/checkout-<language>`, with its own package
  manifest and committed lockfile. It holds the SDK only: no copy of another SDK, no plugin.
- The README says which version of this specification the port implements (the `version` of its
  `PIN.json`, below).

## The pinned copy of the specification

A port reads the specification and the vectors from a **copy** of this repository's files, pinned
to one commit and checked file by file, so that it never changes under the port's feet and never
drifts unnoticed:

- [`manifest.json`](https://github.com/sattleme/checkout-spec/blob/main/manifest.json)
  gives this repository's `version`, the `protocol` version and the SHA-256 (lowercase hex, of the
  file's bytes) of every file a port copies: `SPEC.md`, `PORTING.md`, `currencies.json` and
  everything under `vectors/`.
- The port copies those files, unchanged and at the same relative paths, into one directory of its
  own (`spec/` is the convention), from a commit of this repository's default branch, a tagged
  version when there is one. Next to them, `PIN.json`:

  ```json
  {
    "repository": "https://github.com/sattleme/checkout-spec",
    "commit": "<the 40-character commit the files come from>",
    "version": "<manifest.json's version>",
    "protocol": 1,
    "files": { "SPEC.md": "<sha-256>", "...": "..." }
  }
  ```

  `files` is `manifest.json`'s, exactly.

- A test of the port (run by its CI) fails unless every file of `files` is in the copy with that
  SHA-256, and the copy holds no other file but `PIN.json`. The tests read the vectors from the
  copy only, never from the network.
- The copy is never edited by hand. A disagreement with the specification, or a wrong vector, is
  reported to this repository ([SECURITY.md](https://github.com/sattleme/checkout-spec/blob/main/SECURITY.md)
  for anything that could cost a merchant money or leak a key); the copy changes only by taking a
  newer version of this repository.
- To follow a new version: replace the copy and `PIN.json` together, in one pull request with the
  code that passes the new vectors;
  [CHANGELOG.md](https://github.com/sattleme/checkout-spec/blob/main/CHANGELOG.md) says what changed.

## Steps

1. **Read** [SPEC.md](SPEC.md) in full: it alone is authoritative. Where it is unclear, or a vector
   disagrees with it, stop and report it (an issue on this repository).
2. **Choose the dependencies, then ask the maintainers before adding them.** A port needs: SHA-256,
   HMAC-SHA256 and HKDF-SHA256; secp256k1 with BIP-340 Schnorr signatures, x-only public keys and
   ECDH; ChaCha20 (the IETF variant, 12-byte nonce); a WebSocket client that follows no redirect,
   offers no compression and lets the handshake carry the User-Agent of SPEC.md §15; an HTTP client
   with timeouts, no redirects and a bounded body; arbitrary-precision integers. Prefer the standard
   library. For secp256k1, a maintained implementation audited for BIP-340: never write the curve
   yourself. Pin every version exactly, commit the lockfile, and check that NIP-44 passes its
   official vectors with the chosen ChaCha20 and HKDF.
3. **Implement part by part**, each with its vectors before the next:

   | Part                                            | SPEC.md      |
   | ----------------------------------------------- | ------------ |
   | every constant                                  | §28          |
   | text rules, JSON, strict base64                 | §2, §6       |
   | the integration key, relay lists                | §8, §9       |
   | key derivations, a sale's keys                  | §10          |
   | Nostr events, NIP-44 v2, sealed records         | §11, §12     |
   | the relay client (NIP-01, NIP-42), quorum       | §13          |
   | reading the channel                             | §14          |
   | HTTP, Lightning address, invoice checks, LUD-21 | §15–§18, §22 |
   | bech32, BOLT11                                  | §19          |
   | declarations, an order's earlier invoices       | §20, §21     |
   | currencies, prices, conversion, rate sources    | §25, §26     |
   | the order's checks, the client, its errors      | §4, §5, §17  |
   | checkout links, redirect URLs                   | §30          |
   | the merchant's Bitcoin node (the channel's)     | §14, §31     |
   | deposit addresses, the lot, leases, on-chain    | §31          |

4. **Run the vectors** from the first module on: a test runner that reads each vector file of the
   pinned copy and checks the port against it. Each file says what it holds (`description`); an
   error is written `{"error": <code>}`, with `param` when the error has one. A runner calls the
   port's own code, the functions its client calls, never a copy of the rule in the test: the cases
   of `relay-reads.json` that give what each relay's read is (`lists`, `onEveryRelay`) go through
   the function that decides what the read gives, and run again end to end against local relays
   (step 5), where a relay still reading, one whose read failed and one whose read ended are told
   apart by the relay pool itself (a relay still reading that the read waits for is, end to end, one
   that fails at its timeout, as `relay-reads.json` says). Likewise the merchant's acceptances:
   `vectors/app/merchant-acceptance.json`'s `records` (with its `secretKey`) and `made.records`
   (with `made.secretKey`, a team of the vector's own) go through the port's reading of one record;
   the `merchantAccepted` cases of `onchain-payments.json` go through its payment check, then run
   again end to end against 3 local relays, each record held by `sentBy` of them (all 3 when
   absent), the check reading them on every relay. The vector gives each record opened, not its
   event (the app's team secret is in no vector): the port makes the events with its own sealing,
   as the app does, at the merchant's acceptance address of the vector's invoice for the sale of
   `vectors/app/app.json`'s declaration (the same integration key), signed by
   `merchant-acceptance.json`'s `made.teamSecret` and read with `made.secretKey`'s team: of
   `{"version": 1, "received": <received>}` (the vector's string of digits written as a JSON number,
   whatever its value), or of `version` 2 for one `newer`, dated `createdAt`. Two records whose
   `id`s the vector gives (of one date) are made again, with other random bytes, until their ids
   sort as the vector's (the lowest counts).
   Without the relays, each relay of the list answers with the records it holds (each on the first
   `sentBy` of the 3); end to end, each local relay stores the events it holds as they are, several
   at one address included (the relay of step 5 keeps only the newest of an address, so that the
   check's own choice of the newest would never run), and the first, which holds every record,
   answers late: a read that went on with the first majority to answer would miss what it holds.
   `"unreadable"`: 2 of the 3 never answer the read. `vectors/app/checkout-rest.json` follows the
   order in which the implementation that made it draws its random bytes (SPEC.md §29): a port
   that draws in that order compares the file whole, byte for byte; one that draws otherwise (a
   read's key only when a relay asks authentication, reads at the same time drawing in either
   order) compares what no random byte decides (the invoice, the link's `value`, the rest keys and
   the rest record's address, tags and `value`, the status), checks that its own link and rest
   record check out and open to those values, and opens the vector's `link.event` and `rest.event`
   with the vector's keys: never the link's keys, URL, or the `content`, `id` and `sig` of either
   event. `bitcoin-nodes.json` goes through the port's own functions: its `urls` through the
   check of a node URL and the URLs the node is read at, its `channels` through the reading of the
   channel (an otherwise valid channel whose `bitcoinNode` is the case's `value`, absent when the
   case has none: the channel valid either way), its `reads` through the function that decides
   which explorers a read asks, and in what order, its `writes` through the making of a checkout
   link's record, and its `records` through the port's reading of a record, as a page reads it;
   then end to end (step 5).
5. **Write the integration tests**: a local relay (it keeps the newest event of each address, and
   can refuse an event, require NIP-42 authentication, cap its answers, honor a filter's `limit` or
   answer one without it oldest first, hide events, stay mute or answer late), a fake Lightning
   address, fake rate sources and fake explorers (REST and WebSocket, BlockCypher). Cover: an order
   in sats and in a currency; every invoice check; a declaration on a majority of the relays, and
   none without one; every HTTP request and every WebSocket handshake with the User-Agent of SPEC.md
   §15; one order, one invoice at a time (pending, its payment checked first, its rest invoice asked
   when underpaid as §31 says; paid, declared again; of several that may still be paid, their
   payments checked first, then the one a majority of the relays holds handed out); relay moves; a
   removed integration; a mute relay that slows nothing (but the reads on every relay, §13: a
   lease's confirmation, the witnesses read again, the choice among several invoices that may still
   be paid: one timeout at most each, a relay that failed waited for once per call); a relay that
   hides a lease or a witness while another one that holds it answers late (the read on every relay
   still sees it); a relay that redirects its handshake (a failed connection), one that sends many
   large events (nothing piles up; a read of leases ends incomplete, never failed), one that sends
   one record many times, each copy with members of its own added (read once, kept without them),
   one that sends records of a newer format without the author's signature (ignored), one that sends
   copies of a lease or of a record under `id`s of their own, with large tags (a few bytes kept of
   each copy of a lease, none of a record), one that accepts compression (none offered); every rate
   source's answers and failures, a list of sources asked in order (the default list included); the
   payment states; a checkout link published before the declaration (and nothing declared when fewer
   than a majority take it), a channel without a checkout origin, a new link with `invoice_pending`;
   the methods of an order by its amount, a lot read and an address leased (confirmed, then marked),
   two servers leasing one address at once (one keeps it, the other withdraws its lease), a paid
   address skipped (and its witness), an address a witness names skipped, an empty lot, leases read
   among many records anybody wrote (a read that cannot be complete leaves the order without that
   address, never with one another order holds), a lease withdrawn when not confirmed and never
   giving its invoice an address then, a confirmed lease never withdrawn whatever fails after (its
   mark, the link, the declaration), two calls of one order at once never withdrawing each other's
   lease, the witnesses written and read, a transaction another invoice's witness names counting for
   nothing, a transaction paying the addresses of two orders paying each its part, the on-chain
   statuses (unconfirmed, paid at 3 confirmations, underpaid, late, told by BlockCypher after the
   lease's end), an order paid on-chain found by `invoice_pending` and `order_paid`,
   `waitForPayment` woken by the WebSocket, the rest of an underpayment asked, declared and
   published (and not asked again, nor without time left, outside the sendable sats or when the
   Lightning address fails), a mixed payment; the merchant's tolerance kept in the lease, a payment
   within it paid (its acceptance record published once, again of less after a replacement, a
   failure only logged), one short by more asking its whole rest, a tolerance changed after the
   order changing nothing for it; the merchant's acceptance (the team's record) read on every relay
   with the witnesses: an order short by more than its tolerance paid down to it, its acceptance
   record (the server's, for the pages) published; one that a majority of the relays holds counted
   whichever majority answers, one that only a minority holds never counted, before the invoice's
   end and after the lease's; a relay that holds it and answers late waited for, one that fails
   leaving it uncounted when the others that hold it are fewer than a majority; one combined with
   rest invoices paid (paid, mixed); one dated at the lease's end counted, a second later not; one
   of a newer format newer than a valid one leaving the order without one; of another author, of
   another invoice, or with a damaged signature, not counted; fewer than a majority answering:
   `network`; the merchant's Bitcoin node (SPEC.md §31): every read of an address and of the
   chain's height, and `waitForPayment`'s WebSocket, asked of the node (its `ws://` or `wss://`
   URL) and never of mempool.space while it answers, with the User-Agent of SPEC.md §15 and no
   redirect followed; a node that does not answer, with `fallback` `"mempool"`: the same reads of
   mempool.space, its WebSocket when a connection to the node fails or is lost before any message,
   the node asked after mempool.space for 60 s once it failed, a check's transactions and height
   always of one explorer (the node failing either, both asked of mempool.space), `network` when
   both fail; with `"none"`: `network`, never `expired` nor final underpaid however long the node is
   down, no address leased, mempool.space never asked, and the order paid once the node answers
   again; an invalid `bitcoinNode` (an `http` URL to a public host, a `fallback` of another
   spelling, a `payers` absent or not a boolean, a `payers` `true` for a node that is not of the
   Internet) reading mempool.space, the channel still valid; the record of a checkout link to an
   order with an address holding the node's `url` and `fallback` (never `payers`) with `payers`
   `true`, and no `bitcoinNode` with `payers` `false`, without a node, or for an order without an
   address (version 1), the link made again by `invoice_pending` included.
6. **Add its CI** ([below](#continuous-integration)) and its release workflow
   ([below](#releases)).
7. **Document**: the README (English: installing, the key as a secret, a quick start, prices in a
   currency and `currencyDigits`, the errors, what a removed integration stops
   ([SPEC.md §14](SPEC.md#14-reading-the-channel)), and, when its calls run concurrently, that what
   is injected is called so ([SPEC.md §4](SPEC.md#4-client))), the CHANGELOG, and the version of
   this specification it implements.

## Continuous integration

- `.github/workflows/ci.yml`, on `pull_request` and on `push` to the default branch.
- `permissions: contents: read` at the top of every workflow; a job that needs more asks for it
  alone.
- Every action pinned by its full commit SHA, its version in a comment
  (`actions/checkout@<sha> # vX.Y.Z`), and `persist-credentials: false` on checkout.
- Every tool and dependency pinned exactly; the lockfile installed as it is, never upgraded by the
  CI.
- Steps: the pinned copy's check, the linter and formatter, the type checker when the language has
  one, the tests on every supported version of the language.
- Dependabot (`.github/dependabot.yml`) keeps the actions and the dependencies up to date, as pull
  requests.
- Nothing internal in a workflow, its logs or its commit messages: once the repository is public,
  its whole history and every run's logs are public too.

## Releases

Releases are the maintainers'. Never publish to a registry (Packagist, PyPI, NuGet, npm…), never
push a tag, never create a release from a development or agent session.

- A release is a tag `vX.Y.Z` that a maintainer pushes on a commit of the default branch, equal to
  the version the package declares (where its manifest declares one).
- `.github/workflows/release.yml`, on that tag: runs the CI again, checks that the tag matches the
  version and that its commit is on the default branch, then publishes in a job bound to a
  **protected environment** (required reviewers: a maintainer approves each release), which alone
  holds the registry's credentials. Prefer the registry's trusted publishing (OIDC from the
  workflow, no stored token) where it offers it; a token, otherwise, scoped to this package only.
- Where the registry reads the repository itself (Packagist reads a public repository's tags; Go
  modules too), the tag is the release: protect the `v*` tags (a ruleset) so that only maintainers
  create them, and keep the same checks in a workflow on the tag, which reports a bad tag at once.
- Propose the workflow; the maintainers create the registry account, the environment and its
  credentials.

## Packages that depend on an SDK

Plugins of e-commerce platforms never implement the protocol themselves: they call the SDK of
their language, at a pinned version, and get its conformance from it.

- **A plugin of a platform that installs no dependency of a plugin** ships its dependencies in its
  archive. It embeds the SDK with the namespaces of its embedded dependencies **prefixed** (the
  SDK's and its own dependencies'), so that two plugins carrying two versions of the SDK never
  collide; its lockfile pins the SDK exactly, and its CI builds the archive and runs its tests
  against the prefixed copy.
- **A module of a platform that installs its packages' dependencies** declares the SDK as a
  dependency of its package (a version constraint that follows the SDK's semantic versioning): the
  shop installs it, unprefixed, once.
- In every plugin: the integration key lives in the shop's server-side settings only (never sent
  to the browser, never logged), the customer's page gets the invoice and its address alone, and the order is
  locked in the shop's database around `createInvoice` (SPEC.md
  [§17](SPEC.md#17-creating-an-invoice)).
- A plugin keeps no copy of this repository unless it tests the protocol itself; the SDK version it
  pins says which version of the specification it follows.

## Readers first, writers second

A newer format of anything the app and the implementations exchange (the channel, a declaration,
the integration key: a higher `version`, a new prefix) is written only once the readers that
understand it are released:

1. this repository specifies the new format and its vectors, readable alongside the old one;
2. every SDK releases a version that reads it (until then, an SDK that meets it reports a newer
   format: SPEC.md [§12](SPEC.md#12-sealed-records), `channel_not_found` with `newerFormat`);
3. only then does the writer write it: the merchant's app for the channel and the key, the SDKs for
   a declaration and a checkout link (which the merchant's app and its web app read: their release
   comes first).

An older format stays readable as long as data written in it may still be read.

## Pitfalls the vectors catch, and how to avoid them

Every rule is in SPEC.md §6 and §7; these are where platforms differ from it.

- **Length**: count code points. PHP `strlen` counts bytes (use `mb_strlen`); C# `string.Length`
  and Java `String.length()` count UTF-16 units (count runes or code points); Python `len` counts
  code points.
- **Trimming and case**: write your own ASCII-only trim and lowering. `trim()`, `strip()`,
  `Trim()`, `lower()`, `ToLower*()` and `strtolower` each follow their own, different rules: some
  lower the Kelvin sign (U+212A) to `k`, so that a bech32 text that is no invoice would decode
  (`bolt11.json`).
- **Base64**: most decoders are lenient (whitespace, the other alphabet, padding, non-zero
  trailing bits). Check the alphabet yourself, decode, then encode again and compare with the
  input: only the canonical spelling is accepted.
- **UTF-8**: decode strictly (PHP: `mb_check_encoding`; Python: `bytes.decode("utf-8")`, never
  `errors="replace"`; .NET: `new UTF8Encoding(false, true)`).
- **JSON** is read as JavaScript's `JSON.parse` reads it, 64 levels of arrays and objects at most
  (SPEC.md §2), which no parser tested does as it is. An integer of 5 000 digits is refused by
  Python's `json` (its 4 300-digit limit), Go's `encoding/json` (1.27) and Rust's `serde_json`
  (1.0.154), and read as an Integer, not a double, by Ruby's `JSON` (2.7.2); `1e400` is refused by
  `encoding/json` and `serde_json`; a member name that starts with U+0000 by PHP's `json_decode`
  into objects (8.3); a lone surrogate by `json_decode`, `serde_json` and Ruby's `JSON`, replaced
  with U+FFFD by `encoding/json`, refused by .NET's `JsonElement.GetString` (10). Count the depth
  yourself (outside strings) before parsing: .NET's `System.Text.Json` refuses beyond 64 as it is,
  the others go deeper or exhaust their stack. The bodies of `payments.json` test all of these.
- **Prices as JSON numbers**: read them as doubles, then write the shortest decimal that reads
  back as that double (SPEC.md §25). Do not keep more digits than a double (Python's
  `json.loads(parse_float=Decimal)` would differ from every other implementation), nor fewer
  (PHP's `(string)$float` keeps 14 digits: use `json_encode` with `serialize_precision = -1`).
- **Integers**: amounts fit 64 bits, but the conversion of a price does not: use arbitrary
  precision (PHP: GMP or BCMath; .NET: `BigInteger`; Python: `int`). Refuse what is out of bounds,
  never wrap: C# `long` arithmetic is unchecked by default.
- **JSON field names**: keep the names of SPEC.md §3 in the stored JSON even where the language
  names its properties otherwise; in C#, a property cannot be named like its class (CS0542), which
  is why the invoice's field is `bolt11`.
- **Secrets**: the key and every derived key stay out of logs, messages and default string or
  debug representations; in PHP, mark every parameter that receives the key
  `#[\SensitiveParameter]` (PHP 8.2+) so that stack traces leave it out. Random bytes come from the
  CSPRNG (`random_bytes`, `secrets`, `RandomNumberGenerator`); MACs are compared in constant time
  (`hash_equals`, `hmac.compare_digest`, `CryptographicOperations.FixedTimeEquals`).
- **Concurrency**: reads and writes go to every relay at once and go on at a majority (SPEC.md
  §13). A synchronous language may do it with non-blocking sockets or an event loop; a port MAY
  close the relays past the majority instead of waiting for them, never wait for every relay
  before going on.
- **Cancellation** is the language's own (a `CancellationToken`, a context, a timeout): a cancelled
  call fails with it, never with an error of SPEC.md §5.

## When the protocol changes

The specification and its vectors change together: the vectors are made and checked by the
merchant's app and by an implementation of this specification, then published here as a new version
([CHANGELOG.md](https://github.com/sattleme/checkout-spec/blob/main/CHANGELOG.md)). Each port then
takes the new version into its pinned copy; its CI fails on the new vectors until its code follows:
that is how ports stay in step.

A field added to what the merchant's app writes, which a reader that does not know it ignores, is no
newer format: the app may write it before every port follows it. The channel's `bitcoinNode`, the
merchant's Bitcoin node (SPEC.md §31), is one. A port that does not follow it yet goes on working,
but reads mempool.space where the merchant chose its own node, and writes no node in its checkout
links' records (their pages then read mempool.space), even with `fallback` `"none"`, which the
merchant set so that mempool.space is never asked: until it follows the change, its README and its
CHANGELOG say so, and it follows the change in its next version.
