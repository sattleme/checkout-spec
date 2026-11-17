# Security

This repository specifies how a shop's server takes Lightning and on-chain payments for a sattle.me
merchant. A flaw here could let an attacker be paid instead of the merchant, mark an order paid
that is not, or learn a key: please report it **privately**, never in a public issue, pull request
or discussion.

## How to report

- On GitHub: **Security** tab of this repository → **Report a vulnerability** (private
  vulnerability reporting).
- Or by email: security@sattle.me, subject starting with `[security] checkout-spec`.

Please include what you found, the section of `SPEC.md` or the vector concerned, and, when you
can, the steps or the input that show it. Do not test against real merchants' funds or keys.

## What is in scope

- `SPEC.md`, `PORTING.md`, `currencies.json` and the vectors: a rule that, followed as written,
  lets an implementation accept a wrong invoice, a wrong payment (Lightning or on-chain), a forged
  record, or leak a key.
- A flaw in an implementation goes to that implementation's repository (through the same
  channels as above when it has none of its own).

We will acknowledge your report, keep you informed, and credit you when the fix is published,
unless you prefer otherwise.
