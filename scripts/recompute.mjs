// Computes part of the vectors again, from SPEC.md alone, with @noble directly: not with the code
// that made them, so that a mistake both the merchant's app and an implementation make is still
// caught here.
//
// - vectors/nip44/: NIP-44 v2 (https://github.com/nostr-protocol/nips/blob/master/44.md), every case.
// - vectors/app/app.json: the key, every derivation (SPEC.md §10), the channel and the declaration
//   opened and checked field by field (§11, §12, §14, §20), the real invoice's preimage.
// - vectors/app/implementation-declaration.json: an implementation's declaration, opened the same way.
// - vectors/integration-keys.json (§8), every case, in the order of its parsing.
// - vectors/conversions.json and the valid cases of vectors/fiat.json (§25), on integers, and its
//   currencyDigits cases (§4).
// - vectors/redirect-urls.json, the origins, derivations, URLs and fragments of
//   vectors/checkout-links.json, and vectors/app/checkout-link.json opened field by field (§30),
//   with a parser of their own; vectors/https-urls.json (§15, §16) with the same parser; the pay
//   requests and the price of vectors/app/checkout-link.json and vectors/app/checkout-rest.json
//   (§16 to §18, §25).
// - vectors/relay-urls.json (§9), vectors/bolt11.json (§19), vectors/invoice-checks.json (§18)
//   and the records of vectors/checkout-links.json (§30, Reading a record), with a BOLT11 decoder
//   of their own.
// - vectors/onchain-addresses.json, payment-methods.json, onchain-leases.json (each lease opened,
//   addresses leased with the signatures checked, leases confirmed), onchain-witnesses.json,
//   onchain-replacements.json and onchain-payments.json (§31), with a bech32m decoder of their own.
// - vectors/onchain-rests.json and vectors/app/checkout-rest.json (§31, the rest of an
//   underpayment): the rest keys, the rest records, the acceptance records and the declarations
//   opened, when a check asks for a rest invoice, with a BOLT11 decoder of their own.
// - vectors/onchain-tolerances.json (§31, the merchant's tolerance): tolerances read, the least
//   amounts accepted, what is due on-chain.
// - vectors/bitcoin-nodes.json (§14, §30, §31, the merchant's Bitcoin node): node URLs and where
//   they are read, the channel's `bitcoinNode`, the explorers a read asks, the node a checkout
//   link's record holds (written, then read by its page).
// - vectors/app/merchant-acceptance.json (§31, the merchant's acceptance): its addresses, and each
//   record read as a check reads it; in vectors/onchain-payments.json, what one changes.
// - vectors/relay-reads.json (§13, paged and complete reads): the pages asked, and how each read
//   ends; reads on every relay, which relays answered.
// - vectors/rate-sources.json (§26): the default list, `rateSource`, lists, HTTP statuses.
// - The stored invoices of vectors/payments.json (§22), with a BOLT11 decoder of their own.
// - vectors/earlier-invoices.json (§21): an order's invoices from its records, and step 1 of the
//   check.
// - vectors/nostr-events.json (§11): event ids, with a serializer of its own (not JSON.stringify).
// - vectors/pay-requests.json (§15, §16): pay requests read from the answers of their pay URLs.
import { deepStrictEqual } from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { chacha20 } from "@noble/ciphers/chacha.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const ROOT = join(import.meta.dirname, "..");
const read = (file) => JSON.parse(readFileSync(join(ROOT, file), "utf8"));

let checks = 0;
const failures = [];
function check(name, run) {
  checks++;
  try {
    run();
  } catch (error) {
    failures.push(`${name}: ${error instanceof Error ? error.message : error}`);
  }
}
function expect(actual, expected) {
  deepStrictEqual(actual, expected);
}
function expectThrow(run) {
  let threw = false;
  try {
    run();
  } catch {
    threw = true;
  }
  if (!threw) throw new Error("expected a refusal");
}

// ---- NIP-44 v2 ---------------------------------------------------------------------------------

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Strict base64 (RFC 4648 §4, padded): only the canonical spelling. */
function base64Strict(text) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new Error("base64");
  const bytes = new Uint8Array(Buffer.from(text, "base64"));
  if (Buffer.from(bytes).toString("base64") !== text) throw new Error("base64");
  return bytes;
}

function conversationKey(secretKey, publicKeyHex) {
  const shared = secp256k1.getSharedSecret(secretKey, hexToBytes(`02${publicKeyHex}`));
  return extract(sha256, shared.subarray(1, 33), utf8ToBytes("nip44-v2"));
}

function messageKeys(key, nonce) {
  const keys = expand(sha256, key, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76)
  };
}

function paddedLength(length) {
  if (length <= 32) return 32;
  const next = 1 << (Math.floor(Math.log2(length - 1)) + 1);
  const chunk = next <= 256 ? 32 : next / 8;
  return chunk * (Math.floor((length - 1) / chunk) + 1);
}

function encrypt(plaintext, key, nonce) {
  const bytes = utf8ToBytes(plaintext);
  if (bytes.length < 1 || bytes.length > 65535) throw new Error("plaintext length");
  const padded = new Uint8Array(2 + paddedLength(bytes.length));
  padded[0] = bytes.length >> 8;
  padded[1] = bytes.length & 0xff;
  padded.set(bytes, 2);
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(key, nonce);
  const ciphertext = chacha20(chachaKey, chachaNonce, padded);
  const mac = hmac(sha256, hmacKey, concatBytes(nonce, ciphertext));
  return Buffer.from(concatBytes(new Uint8Array([2]), nonce, ciphertext, mac)).toString("base64");
}

/** NIP-44: a payload of a version other than 2 (empty, `#`, another version byte), §12 step 2. */
class UnknownVersion extends Error {
  constructor() {
    super("unknown version");
  }
}

function decrypt(payload, key) {
  if (payload.length === 0 || payload[0] === "#") throw new UnknownVersion();
  if (payload.length < 132 || payload.length > 87472) throw new Error("payload length");
  const data = base64Strict(payload);
  if (data.length < 99 || data.length > 65603) throw new Error("data length");
  if (data[0] !== 2) throw new UnknownVersion();
  const nonce = data.subarray(1, 33);
  const ciphertext = data.subarray(33, data.length - 32);
  const mac = data.subarray(data.length - 32);
  const { chachaKey, chachaNonce, hmacKey } = messageKeys(key, nonce);
  if (!timingSafeEqual(hmac(sha256, hmacKey, concatBytes(nonce, ciphertext)), mac)) {
    throw new Error("MAC");
  }
  const padded = chacha20(chachaKey, chachaNonce, ciphertext);
  const length = (padded[0] << 8) | padded[1];
  if (length < 1 || padded.length !== 2 + paddedLength(length)) throw new Error("padding");
  return utf8.decode(padded.subarray(2, 2 + length));
}

/**
 * §12 steps 2 and 3, for an event that checked out (§11): the record its content opens to (an
 * object holding `v`, padded to a multiple of 256 bytes), "newer" for a content of a newer NIP-44
 * version, or null.
 */
function openContent(event, key) {
  let plaintext;
  try {
    plaintext = decrypt(event.content, key);
  } catch (error) {
    return error instanceof UnknownVersion ? "newer" : null;
  }
  if (utf8ToBytes(plaintext).length % 256 !== 0) return null;
  let record;
  try {
    record = JSON.parse(plaintext);
  } catch {
    return null;
  }
  return record !== null && typeof record === "object" && "v" in record ? record : null;
}

const nip44 = read("vectors/nip44/nip44.vectors.json");
for (const [length, padded] of nip44.calc_padded_len) {
  check(`nip44 calc_padded_len ${length}`, () => expect(paddedLength(length), padded));
}
for (const v of nip44.get_conversation_key) {
  check(`nip44 get_conversation_key ${v.pub2}`, () =>
    expect(bytesToHex(conversationKey(hexToBytes(v.sec1), v.pub2)), v.conversation_key)
  );
}
for (const v of nip44.invalid_get_conversation_key) {
  check(`nip44 invalid_get_conversation_key (${v.note})`, () =>
    expectThrow(() => conversationKey(hexToBytes(v.sec1), v.pub2))
  );
}
for (const v of nip44.get_message_keys.keys) {
  check(`nip44 get_message_keys ${v.nonce}`, () => {
    const keys = messageKeys(
      hexToBytes(nip44.get_message_keys.conversation_key),
      hexToBytes(v.nonce)
    );
    expect(
      [bytesToHex(keys.chachaKey), bytesToHex(keys.chachaNonce), bytesToHex(keys.hmacKey)],
      [v.chacha_key, v.chacha_nonce, v.hmac_key]
    );
  });
}
for (const v of nip44.encrypt_decrypt) {
  check(`nip44 encrypt_decrypt ${v.nonce}`, () => {
    const key = hexToBytes(v.conversation_key);
    expect(encrypt(v.plaintext, key, hexToBytes(v.nonce)), v.payload);
    expect(decrypt(v.payload, key), v.plaintext);
  });
}
for (const v of nip44.invalid_decrypt) {
  check(`nip44 invalid_decrypt (${v.note})`, () =>
    expectThrow(() => decrypt(v.payload, hexToBytes(v.conversation_key)))
  );
}

// ---- Keys, records, declarations (SPEC.md §8, §10, §11, §12, §14, §20) ----------------------------

const KEY_PREFIX = "sattleme_ck_";
const INTEGRATION_SALT = "sattle.me/integration";
const REGISTRY_DECLARATION_SALT = "sattle.me/registry-declaration";
const derive = (secret, salt, info) =>
  hkdf(sha256, secret, utf8ToBytes(salt), utf8ToBytes(info), 32);

/** §11: no string of the content or the tags holds a lone surrogate (its UTF-8 does not exist). */
const wellFormed = (event) =>
  typeof event.content === "string" &&
  event.content.isWellFormed() &&
  Array.isArray(event.tags) &&
  event.tags.every(
    (tag) =>
      Array.isArray(tag) && tag.every((text) => typeof text === "string" && text.isWellFormed())
  );

/** Lowercase hex of exactly `length` characters. */
const isHex = (text, length) =>
  typeof text === "string" && text.length === length && /^[0-9a-f]*$/.test(text);

/** §11: the hash an event's `id` must be (hex), or null when it has none (a lone surrogate). */
function eventHash(event) {
  if (!wellFormed(event)) return null;
  const { pubkey, created_at, kind, tags, content } = event;
  const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, content]);
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

/** §11: the event checks out: its fields' types, its id is its hash, its signature verifies. */
function checkEvent(event) {
  if (
    !isHex(event.id, 64) ||
    !isHex(event.pubkey, 64) ||
    !isHex(event.sig, 128) ||
    !Number.isSafeInteger(event.created_at) ||
    !Number.isInteger(event.kind)
  ) {
    throw new Error("event fields");
  }
  const id = eventHash(event);
  if (id === null) throw new Error("content or tags: not well-formed strings");
  expect(id, event.id);
  if (!schnorr.verify(hexToBytes(event.sig), hexToBytes(id), hexToBytes(event.pubkey))) {
    throw new Error("signature");
  }
}

/** §12: opens a sealed record; its plaintext is padded with spaces to a multiple of 256 bytes. */
function openRecord(event, { type, address, author, key }) {
  checkEvent(event);
  expect([event.kind, event.pubkey, event.tags], [30078, author, [["d", address]]]);
  const plaintext = decrypt(event.content, key);
  const bytes = utf8ToBytes(plaintext).length;
  if (bytes % 256 !== 0) throw new Error("record padding");
  const record = JSON.parse(plaintext);
  expect(record.t, type);
  return { value: record.v, bytes };
}

/** §10: a sale's keys and what its declarations are made with. */
function sale(integrationKey, registry, ref) {
  const key = derive(integrationKey, INTEGRATION_SALT, `sale/${ref}/v1`);
  const secret = derive(key, "sattle.me/sale", "nostr-secret-key/v1");
  const author = bytesToHex(schnorr.getPublicKey(secret));
  const takerKey = derive(integrationKey, INTEGRATION_SALT, "taker/v1");
  return {
    key: bytesToHex(key),
    secret: bytesToHex(secret),
    author,
    taker: bytesToHex(hmac(sha256, takerKey, hexToBytes(author)).subarray(0, 16)),
    inner: conversationKey(secret, registry.reader)
  };
}

/** §20: opens a declaration of `s` for payment hash `paymentHash`; returns its inside. */
function openDeclaration(event, registry, s, paymentHash) {
  const address = bytesToHex(hmac(sha256, registry.key, hexToBytes(paymentHash)));
  const outer = derive(registry.key, REGISTRY_DECLARATION_SALT, `outer/v1/${address}/${s.author}`);
  const { value, bytes } = openRecord(event, {
    type: "registry-declaration",
    address,
    author: s.author,
    key: outer
  });
  expect(Object.keys(value), ["sealed"]);
  return { inside: JSON.parse(decrypt(value.sealed, s.inner)), address, outer, bytes };
}

const app = read("vectors/app/app.json");

/** §8: the key's three parts. */
function parseKey(text) {
  const match = /^sattleme_ck_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(text);
  if (!match) throw new Error("not a key");
  const part = (b64) => {
    const bytes = new Uint8Array(Buffer.from(b64, "base64url"));
    if (Buffer.from(bytes).toString("base64url") !== b64) throw new Error("base64url");
    return bytes;
  };
  const team = part(match[1]);
  const key = part(match[2]);
  if (team.length !== 32 || key.length !== 32) throw new Error("length");
  schnorr.utils.lift_x(BigInt(`0x${bytesToHex(team)}`));
  return {
    team: bytesToHex(team),
    integrationKey: bytesToHex(key),
    relays: utf8
      .decode(part(match[3]))
      .split(",")
      .map((host) => `wss://${host}`)
  };
}

check("app: the key", () => expect(parseKey(app.secretKey), app.parsed));
const integrationKey = hexToBytes(app.parsed.integrationKey);

check("app: derivations", () =>
  expect(
    {
      channelAddress: bytesToHex(derive(integrationKey, INTEGRATION_SALT, "channel/address/v1")),
      channelEncryptionKey: bytesToHex(
        derive(integrationKey, INTEGRATION_SALT, "channel/encryption-key/v1")
      ),
      takerKey: bytesToHex(derive(integrationKey, INTEGRATION_SALT, "taker/v1"))
    },
    app.derived
  )
);

check("app: the channel", () => {
  const { value } = openRecord(app.channel.event, {
    type: "team-channel",
    address: app.derived.channelAddress,
    author: app.parsed.team,
    key: hexToBytes(app.derived.channelEncryptionKey)
  });
  expect(value, app.channel.value.v);
  expect(value.updatedAt, app.channel.event.created_at);
});

const registry = {
  key: hexToBytes(app.channel.value.v.registryKey),
  reader: app.channel.value.v.registryReader
};

check("app: the declaration's keys and contents", () => {
  const d = app.declaration;
  const s = sale(integrationKey, registry, d.ref);
  expect(
    { saleKey: s.key, saleSecret: s.secret, saleAuthor: s.author, taker: s.taker },
    { saleKey: d.saleKey, saleSecret: d.saleSecret, saleAuthor: d.saleAuthor, taker: d.taker }
  );
  expect(bytesToHex(s.inner), d.innerConversationKey);
  const opened = openDeclaration(d.event, registry, s, d.paymentHash);
  expect(
    { address: opened.address, outerKey: bytesToHex(opened.outer), outsideBytes: opened.bytes },
    { address: d.address, outerKey: d.outerKey, outsideBytes: d.outsideBytes }
  );
  expect(opened.inside, {
    version: 1,
    invoice: d.invoice,
    verifyUrl: d.verifyUrl,
    sale: { key: d.saleKey, fiat: d.fiat, note: d.note },
    taker: d.taker
  });
});

check("app: the real invoice's preimage", () =>
  expect(bytesToHex(sha256(hexToBytes(app.realInvoice.preimage))), app.realInvoice.paymentHash)
);

check("implementation: the declaration the app reads", () => {
  const p = read("vectors/app/implementation-declaration.json");
  const s = sale(integrationKey, registry, p.ref);
  expect({ saleAuthor: s.author, taker: s.taker }, { saleAuthor: p.saleAuthor, taker: p.taker });
  expect(openDeclaration(p.event, registry, s, p.paymentHash).inside, {
    version: 1,
    invoice: p.invoice,
    verifyUrl: p.verifyUrl,
    sale: { key: s.key, fiat: p.fiat, note: p.note },
    taker: p.taker
  });
});

// ---- Checkout links (SPEC.md §30) --------------------------------------------------------------

const CHECKOUT_SALT = "sattle.me/checkout";
const URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Strict base64url without padding: decoded, then encoded again, the same text. */
function base64UrlStrict(text) {
  if ([...text].some((char) => !URL_SAFE.includes(char)) || text.length % 4 === 1) {
    throw new Error("base64url");
  }
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  if (Buffer.from(bytes).toString("base64url") !== text) throw new Error("base64url");
  return bytes;
}

const isLower = (c) => c >= "a" && c <= "z";
const isDigit = (c) => c >= "0" && c <= "9";

/** §9: a host, label by label; the last of at least two letters, not `localhost`. */
function isHost(host) {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => label.length === 0)) return false;
  if (!labels.every((label) => [...label].every((c) => isLower(c) || isDigit(c) || c === "-"))) {
    return false;
  }
  const last = labels.at(-1);
  // RFC 6761: a name under `localhost` is the machine's own loopback.
  return last.length >= 2 && [...last].every(isLower) && last !== "localhost";
}

/** §9: an optional port, 1 to 5 digits, 1 to 65535. */
function isPort(port) {
  return (
    port === undefined ||
    (port.length >= 1 &&
      port.length <= 5 &&
      [...port].every(isDigit) &&
      +port >= 1 &&
      +port <= 65535)
  );
}

/** Splits `https://<authority><rest>`: the authority ends at the first `/`, `?` or `#`. */
function splitHttps(url) {
  const after = url.slice("https://".length);
  const end = [...after].findIndex((c) => c === "/" || c === "?" || c === "#");
  const authority = end < 0 ? after : after.slice(0, end);
  const colon = authority.indexOf(":");
  return colon < 0
    ? { host: authority, port: undefined, rest: end < 0 ? "" : after.slice(end) }
    : {
        host: authority.slice(0, colon),
        port: authority.slice(colon + 1),
        rest: end < 0 ? "" : after.slice(end)
      };
}

const ALLOWED = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
);
const REFUSED_SCHEMES = new Set(
  (
    "about blob chrome chrome-extension content data file filesystem javascript moz-extension " +
    "resource safari-extension vbscript view-source brave com-apple-mobilesafari-tab ddgquicklink " +
    "firefox firefox-focus googlechrome googlechrome-x-callback googlechromes microsoft-edge " +
    "microsoft-edge-http microsoft-edge-https onionbrowser onionbrowsers opera-http opera-https " +
    "x-safari-http x-safari-https ftp http ws wss android-app intent bitcoin " +
    "keyauth lightning liquidnetwork lnurl lnurlc lnurlp lnurlw callto facetime facetime-audio " +
    "mailto sip sms tel itms-services ms-msdt search-ms"
  ).split(" ")
);

/** §30 "Redirect URLs": what the page shows, or null when refused. */
function redirectShown(url) {
  if (url.length < 1 || url.length > 2048) return null;
  for (let i = 0; i < url.length; i++) {
    const c = url[i];
    if (c === "%") {
      if (!/^[0-9A-Fa-f]{2}$/.test(url.slice(i + 1, i + 3))) return null;
      i += 2;
    } else if (!ALLOWED.has(c)) {
      return null;
    }
  }
  if (url.startsWith("https://")) {
    const { host, port } = splitHttps(url);
    if (!isHost(host) || !isPort(port)) return null;
    return port === undefined ? host : `${host}:${port}`;
  }
  const separator = url.indexOf("://");
  if (separator < 1 || separator > 32) return null;
  const scheme = url.slice(0, separator);
  if (!isLower(scheme[0])) return null;
  if (![...scheme].every((c) => isLower(c) || isDigit(c) || "+.-".includes(c))) return null;
  if (scheme === "https" || REFUSED_SCHEMES.has(scheme)) return null;
  return `${scheme}://`;
}

for (const c of read("vectors/redirect-urls.json").cases) {
  check(`redirect URL ${JSON.stringify(c.url).slice(0, 80)}`, () => {
    const shown = redirectShown(c.url);
    expect(
      shown === null ? { error: "invalid_order", param: "redirectUrl" } : { shown },
      c.expected
    );
  });
}

/**
 * §15 "An https URL": rule 1 of a redirect URL, not under `localhost`; its host and port (443 when
 * absent), or null.
 */
function httpsUrl(url) {
  if (typeof url !== "string" || !url.startsWith("https://")) return null;
  if (redirectShown(url) === null) return null;
  const { host, port = "443" } = splitHttps(url);
  return { host, port: Number(port) };
}

/** §15: two https URLs (as `httpsUrl` gives them) are on the same host: hosts and ports equal. */
const sameHost = (a, b) => a.host === b.host && a.port === b.port;

/** §6: only ASCII letters change case. */
const asciiLower = (text) => text.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** §6: leading and trailing ASCII whitespace (space, tab, line feed, carriage return) removed. */
const trimAscii = (text) => text.replace(/^[ \t\n\r]+|[ \t\n\r]+$/g, "");

/** §16 "A Lightning address": its pay URL, or null when it is not one. */
function payUrlOf(text) {
  const lowered = asciiLower(trimAscii(text));
  const match = /^([a-z0-9\-_.+]+)@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/.exec(lowered);
  if (!match) return null;
  const url = `https://${match[2]}/.well-known/lnurlp/${match[1]}`;
  return httpsUrl(url) ? url : null;
}

const httpsUrls = read("vectors/https-urls.json");
for (const c of httpsUrls.urls) {
  check(`https URL ${JSON.stringify(c.url).slice(0, 80)}`, () =>
    expect(httpsUrl(c.url), c.expected)
  );
}
for (const c of httpsUrls.sameHost) {
  check(`same host: ${c.a} and ${c.b}`, () => {
    const a = httpsUrl(c.a);
    const b = httpsUrl(c.b);
    if (!a || !b) throw new Error("not https URLs");
    expect(sameHost(a, b), c.expected);
  });
}
for (const c of httpsUrls.lightningAddresses) {
  check(`Lightning address ${JSON.stringify(c.address).slice(0, 80)}`, () =>
    expect(payUrlOf(c.address), c.payUrl)
  );
}

/** §30 "The web app's origin". */
function checkoutOrigin(checkout) {
  if (checkout === null || typeof checkout !== "object" || Array.isArray(checkout)) return null;
  const { origin } = checkout;
  if (typeof origin !== "string" || !origin.startsWith("https://")) return null;
  const { host, port, rest } = splitHttps(origin);
  return rest === "" && isHost(host) && isPort(port) ? origin : null;
}

/** §9: a relay address in its one spelling. */
function isRelayAddress(relay) {
  if (typeof relay !== "string" || !relay.startsWith("wss://")) return false;
  const rest = relay.slice("wss://".length);
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash);
  const colon = authority.indexOf(":");
  const host = colon < 0 ? authority : authority.slice(0, colon);
  const port = colon < 0 ? undefined : authority.slice(colon + 1);
  if (!isHost(host) || !isPort(port) || [...relay].length > 120) return false;
  return !path.endsWith("/") && !/[\s?#,]/u.test(path);
}

/** §9 and §8: a list of relays from a fragment's part. */
function relayList(text) {
  const hosts = utf8.decode(base64UrlStrict(text));
  if (hosts.length === 0) throw new Error("no relay");
  const relays = hosts.split(",").map((host) => `wss://${host}`);
  if (relays.length > 10 || new Set(relays).size !== relays.length) throw new Error("relays");
  if (!relays.every(isRelayAddress)) throw new Error("relay");
  return relays;
}

/** §8 "Parsing", in its order: the parts of a key, or `invalid_key`. */
function parseKeyStrict(text) {
  if (!text.startsWith(KEY_PREFIX)) return { error: "invalid_key" };
  const parts = text.slice(KEY_PREFIX.length).split(".");
  if (parts.length !== 3) return { error: "invalid_key" };
  try {
    const team = base64UrlStrict(parts[0]);
    const key = base64UrlStrict(parts[1]);
    if (team.length !== 32 || key.length !== 32) return { error: "invalid_key" };
    schnorr.utils.lift_x(BigInt(`0x${bytesToHex(team)}`));
    return {
      teamPublicKey: bytesToHex(team),
      integrationKey: bytesToHex(key),
      relays: relayList(parts[2])
    };
  } catch {
    return { error: "invalid_key" };
  }
}

for (const c of read("vectors/integration-keys.json").cases) {
  check(`integration key: ${c.name}`, () => expect(parseKeyStrict(c.key), c.expected));
}

for (const c of read("vectors/relay-urls.json").cases) {
  check(`relay address ${JSON.stringify(c.url).slice(0, 80)}`, () =>
    expect(isRelayAddress(c.url), c.valid)
  );
}

/** §30 "Reading the fragment". */
function readFragment(fragment) {
  const parts = (fragment.startsWith("#") ? fragment.slice(1) : fragment).split(".");
  if (parts[0] !== "c") return /^[a-z0-9]{1,8}$/.test(parts[0]) ? "newer" : "other";
  if (parts.length !== 4) return "invalid";
  try {
    const author = base64UrlStrict(parts[1]);
    const linkKey = base64UrlStrict(parts[2]);
    if (author.length !== 32 || linkKey.length !== 32) return "invalid";
    schnorr.utils.lift_x(BigInt(`0x${bytesToHex(author)}`));
    return {
      author: bytesToHex(author),
      linkKey: bytesToHex(linkKey),
      relays: relayList(parts[3])
    };
  } catch {
    return "invalid";
  }
}

const links = read("vectors/checkout-links.json");
for (const c of links.origins) {
  check(`checkout origin ${JSON.stringify(c.checkout)}`, () =>
    expect(checkoutOrigin(c.checkout), c.expected)
  );
}
const checkoutKeys = (linkKey) => ({
  address: bytesToHex(derive(linkKey, CHECKOUT_SALT, "address/v1")),
  encryptionKey: bytesToHex(derive(linkKey, CHECKOUT_SALT, "encryption-key/v1"))
});
for (const c of links.derivations) {
  check(`checkout derivations ${c.linkKey}`, () =>
    expect(checkoutKeys(hexToBytes(c.linkKey)), {
      address: c.address,
      encryptionKey: c.encryptionKey
    })
  );
}
const checkoutUrl = (origin, author, linkKey, relays) =>
  `${origin}/pay#c.${Buffer.from(hexToBytes(author)).toString("base64url")}.${Buffer.from(
    hexToBytes(linkKey)
  ).toString("base64url")}.${Buffer.from(
    utf8ToBytes(relays.map((relay) => relay.slice("wss://".length)).join(","))
  ).toString("base64url")}`;
for (const c of links.urls) {
  check(`checkout URL ${c.url}`, () =>
    expect(checkoutUrl(c.origin, c.author, c.linkKey, c.relays), c.url)
  );
}
for (const c of links.fragments) {
  check(`checkout fragment: ${c.name}`, () => expect(readFragment(c.fragment), c.expected));
}

check("implementation: the checkout link the web app reads", () => {
  const v = read("vectors/app/checkout-link.json");
  const linkKey = hexToBytes(v.linkKey);
  expect(checkoutKeys(linkKey), { address: v.address, encryptionKey: v.encryptionKey });
  expect(readFragment(v.url.slice(v.url.indexOf("#"))), {
    author: v.author,
    linkKey: v.linkKey,
    relays: v.relays
  });
  expect(checkoutUrl(v.origin, v.author, v.linkKey, v.relays), v.url);
  const { event } = v;
  checkEvent(event);
  expect(
    [event.kind, event.pubkey, event.tags],
    [
      30078,
      v.author,
      [
        ["d", v.address],
        ["expiration", String(v.expiresAt + 604800)]
      ]
    ]
  );
  const plaintext = decrypt(event.content, hexToBytes(v.encryptionKey));
  if (utf8ToBytes(plaintext).length % 256 !== 0) throw new Error("record padding");
  const record = JSON.parse(plaintext);
  expect(record.t, "checkout");
  expect(record.v, {
    version: 1,
    businessName: v.businessName,
    invoice: v.invoice,
    verifyUrl: v.verifyUrl,
    fiat: { minor: 2, digits: 2, currency: "CHF" },
    note: v.order.note,
    redirectUrl: v.order.redirectUrl
  });
  expect(record.v, v.value);
  expect(redirectShown(v.order.redirectUrl), "shop.example");
});

// ---- Prices (SPEC.md §25) ----------------------------------------------------------------------

const { currencies } = read("currencies.json");

/** A plain decimal or a decimal with an exponent, as `units × 10^-scale`. */
function decimal(text) {
  const match = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(text);
  if (!match) throw new Error(`not a decimal: ${text}`);
  const fraction = match[2] ?? "";
  const scale = BigInt(fraction.length) - BigInt(match[3] ?? 0);
  const units = BigInt(match[1] + fraction);
  return scale >= 0n ? { units, scale } : { units: units * 10n ** -scale, scale: 0n };
}

/** §25 "The conversion": the sats of a price `fiat` at `priceText` a bitcoin, rounded up. */
function satsAt(fiat, priceText) {
  const digits = BigInt(currencies[fiat.currency]);
  const amount = decimal(fiat.amount);
  const minor = (amount.units * 10n ** digits) / 10n ** amount.scale;
  const price = decimal(priceText);
  const numerator = minor * 10n ** 8n * 10n ** price.scale;
  const denominator = price.units * 10n ** digits;
  return (numerator + denominator - 1n) / denominator;
}

for (const c of read("vectors/conversions.json").cases) {
  check(`conversion ${c.fiat.amount} ${c.fiat.currency} at ${c.price}`, () =>
    expect(satsAt(c.fiat, c.price).toString(), c.sats)
  );
}

for (const c of read("vectors/fiat.json").cases) {
  if (c.expected.error) continue;
  check(`fiat ${c.input.amount} ${c.input.currency}`, () => {
    const digits = currencies[c.input.currency];
    const amount = decimal(c.input.amount);
    const minor = (amount.units * 10n ** BigInt(digits)) / 10n ** amount.scale;
    const text = minor.toString().padStart(digits + 1, "0");
    expect(c.expected, {
      amount: digits === 0 ? text : `${text.slice(0, -digits)}.${text.slice(-digits)}`,
      minor: minor.toString(),
      digits,
      currency: c.input.currency
    });
  });
}

// §4 Functions: currencyDigits, the decimals of a code of currencies.json exactly, else null.
for (const c of read("vectors/fiat.json").digits) {
  check(`currencyDigits ${JSON.stringify(c.code)}`, () =>
    expect(c.expected, Object.hasOwn(currencies, c.code) ? currencies[c.code] : null)
  );
}

// ---- Rate sources (SPEC.md §26) ---------------------------------------------------------------

const RATE_NAMES = ["coingecko", "mempool", "opennode", "coinbase", "kraken"];
const rateSources = read("vectors/rate-sources.json");

check("the default list of rate sources", () =>
  expect(rateSources.default, ["coingecko", "mempool", "coinbase", "kraken", "opennode"])
);

/** §26 "Which sources": the sources a client's `rateSource` names, in order, or null. */
function sourcesOf(value, absent) {
  if (absent) return rateSources.default;
  if (typeof value === "string") return RATE_NAMES.includes(value) ? [value] : null;
  if (!Array.isArray(value) || value.length === 0) return null;
  if (!value.every((v) => typeof v === "string" && RATE_NAMES.includes(v))) return null;
  return new Set(value).size === value.length ? value : null;
}

for (const c of rateSources.values) {
  check(`rateSource: ${c.name}`, () => {
    const sources = sourcesOf(c.rateSource, !Object.hasOwn(c, "rateSource"));
    expect(c.expected, sources ? { sources } : { error: "invalid_option", param: "rateSource" });
  });
}

/** §26: the error of an answer that is not 2xx; a redirect is no answer (§15). */
const statusError = (status) =>
  (status >= 300 && status <= 399) ||
  (status >= 500 && status <= 599) ||
  status === 408 ||
  status === 429
    ? "network"
    : "rate";
for (const c of rateSources.statuses) {
  check(`rate source answering HTTP ${c.status}`, () =>
    expect(c.expected, { error: statusError(c.status) })
  );
}

/** §25: a source's price string, as the RateInfo writes it, or null when it is not usable. */
function usablePrice({ price, time }, now) {
  if (price.length > 64) return null;
  const match = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(price);
  if (!match || Math.abs(Number(match[3] ?? 0)) > 64) return null;
  if (time !== null && (time > now + 300 || now - time > 3600)) return null;
  const { units, scale } = decimal(price);
  if (units === 0n) return null;
  const digits = units.toString().padStart(Number(scale) + 1, "0");
  const whole = digits.slice(0, digits.length - Number(scale));
  const fraction = digits.slice(digits.length - Number(scale)).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

for (const c of rateSources.lists.cases) {
  check(`rate sources: ${c.name}`, () => {
    const asked = [];
    let failure = null;
    let allUnsupported = true;
    for (const name of c.sources) {
      asked.push(name);
      const answer = c.answers[name];
      if (answer === undefined) throw new Error(`no answer for ${name}`);
      const error =
        typeof answer === "string"
          ? answer
          : usablePrice(answer, rateSources.lists.now)
            ? null
            : "rate";
      if (error === null) {
        return expect(c.expected, {
          source: name,
          price: usablePrice(answer, rateSources.lists.now),
          asked
        });
      }
      if (error !== "unsupported_currency") {
        allUnsupported = false;
        failure = error;
      }
    }
    return expect(c.expected, { error: allUnsupported ? "unsupported_currency" : failure, asked });
  });
}

// ---- Complete reads (SPEC.md §13) --------------------------------------------------------------

const relayReads = read("vectors/relay-reads.json");

/** §13 "Complete reads": what a read asks of one relay, and how it ends. */
function completeRead(pages, limit, maxPages) {
  const kept = new Set();
  const untils = [null];
  for (let index = 0; ; index += 1) {
    const page = pages[index];
    if (page === "fails") {
      return { untils, answered: index > 0, complete: false, kept: kept.size };
    }
    const before = kept.size;
    for (const [id] of page) if (typeof id === "string") kept.add(id);
    const end = (complete) => ({ untils, answered: true, complete, kept: kept.size });
    if (page.length > limit) return end(false);
    if (page.length < limit) return end(true);
    const safe = page
      .filter(([id]) => typeof id === "string")
      .map(([, at]) => at)
      .filter((at) => Number.isSafeInteger(at));
    if (safe.length === 0 || kept.size === before || index + 1 === maxPages) return end(false);
    untils.push(Math.min(...safe));
  }
}
for (const c of relayReads.cases) {
  check(`complete read: ${c.name}`, () =>
    expect(completeRead(c.pages, relayReads.limit, relayReads.pages), c.expected)
  );
}
for (const c of relayReads.lists) {
  check(`complete read of a list: ${c.name}`, () =>
    expect(
      c.relays.filter((relay) => relay === "complete").length >=
        Math.floor(c.relays.length / 2) + 1,
      c.expected
    )
  );
}

/** §13 "Paged reads": what a read asks of one relay, and how many events it keeps. */
function pagedRead(pages, maxPages) {
  const seen = new Set();
  const untils = [null];
  for (let index = 0; index < maxPages; index += 1) {
    const page = pages[index];
    if (page === "fails") return { untils, answered: index > 0, kept: seen.size };
    // An event pages the read, and is kept, by its string id and safe integer created_at alone.
    const dated = page.filter(([id, at]) => typeof id === "string" && Number.isSafeInteger(at));
    if (dated.length === 0) break;
    const fresh = dated.some(([id]) => !seen.has(id));
    for (const [id] of dated) seen.add(id);
    if (index + 1 === maxPages) break;
    const oldest = Math.min(...dated.map(([, at]) => at));
    untils.push(fresh ? oldest : oldest - 1);
  }
  return { untils, answered: true, kept: seen.size };
}
for (const c of relayReads.paged) {
  check(`paged read: ${c.name}`, () => expect(pagedRead(c.pages, relayReads.pages), c.expected));
}
// §13 "Reads on every relay": only a relay whose read ended answered, one still reading has not.
for (const c of relayReads.onEveryRelay) {
  check(`read on every relay: ${c.name}`, () => {
    const majority = Math.floor(c.relays.length / 2) + 1;
    const ended = c.relays.filter((relay) => relay === "complete" || relay === "incomplete");
    const complete = c.relays.filter((relay) => relay === "complete");
    expect(
      { answered: ended.length >= majority, complete: complete.length >= majority },
      c.expected
    );
  });
}

// ---- An order's earlier invoices (SPEC.md §21) -------------------------------------------------

const earlierInvoices = read("vectors/earlier-invoices.json");

/** §21: the DeclaredInvoices of a sale, from its declarations and its records at addresses. */
function declaredInvoices(declarations, records) {
  const later = (a, b) =>
    a.event.createdAt > b.event.createdAt ||
    (a.event.createdAt === b.event.createdAt && a.event.id < b.event.id);
  // Of each address, the newest record: a withdrawal, or one of a newer format, leaves no lease.
  const newest = new Map();
  for (const record of records) {
    const known = newest.get(record.address);
    if (!known || later(record, known)) newest.set(record.address, record);
  }
  // A lease is confirmed when `confirmed` is true.
  const confirmed = [...newest.values()].filter(
    (record) => !record.withdrawn && !record.newer && record.confirmed === true
  );
  const invoices = [];
  for (const declaration of declarations) {
    // A declaration with `rest` is no invoice of the order.
    if (declaration.rest) continue;
    let lease = null;
    for (const record of confirmed) {
      const names =
        record.invoice !== null && asciiLower(record.invoice) === asciiLower(declaration.invoice);
      if (names && (!lease || later(record, lease))) lease = record;
    }
    invoices.push({
      paymentHash: declaration.paymentHash,
      onchainAddress: lease ? lease.address : null,
      createdAt: declaration.createdAt,
      expiresAt: declaration.expiresAt,
      declaredAt: declaration.declaredAt,
      last: declaration
    });
  }
  for (const record of confirmed) {
    if (record.invoice !== null) continue;
    invoices.push({
      paymentHash: null,
      onchainAddress: record.address,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      declaredAt: record.event.createdAt,
      last: record
    });
  }
  // A lease naming an invoice without a declaration gives nothing (above: only declarations do).
  const text = (value) => value ?? "";
  const order = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  return invoices.sort(
    (a, b) =>
      a.createdAt - b.createdAt ||
      order(text(a.paymentHash), text(b.paymentHash)) ||
      order(text(a.onchainAddress), text(b.onchainAddress))
  );
}

/**
 * §21, step 1: what step 1 does with the invoices that may still be paid (`mayBePaid`, indices),
 * whose payments it checks, even of one alone (a paid invoice is never handed out again);
 * `readFails`: fewer than a majority answered the sale's records read again.
 */
function stepOneOutcome(invoices, mayBePaid, statuses, relays, readFails) {
  if (mayBePaid.length === 0) return null;
  const status = (index) => statuses[index];
  const paid = mayBePaid.find((index) => status(index).state === "paid");
  if (paid !== undefined) return { orderPaid: paid };
  const failed = mayBePaid.find((index) => status(index).error !== undefined);
  if (failed !== undefined) return status(failed);
  // One alone is handed out; the sale's records are read again only to choose among several.
  if (mayBePaid.length === 1) return { handOut: mayBePaid[0] };
  // A paid invoice and a check's error decide whatever the read; the hand-out needs the read.
  if (readFails) return { error: "network" };
  // The one whose last record a majority of the list sent: the one shown.
  const held = mayBePaid.filter(
    (index) => (invoices[index].last.sentBy ?? relays) >= Math.floor(relays / 2) + 1
  );
  if (held.length === 1) return { handOut: held[0] };
  // Else the newest that received something, else the newest.
  const received = mayBePaid.filter(
    (index) =>
      status(index).state === "unconfirmed" ||
      (status(index).state === "open" && BigInt(status(index).received ?? "0") > 0n)
  );
  return { handOut: received.length > 0 ? received.at(-1) : mayBePaid.at(-1) };
}

/** §21, step 1: the invoices that may still be paid, those it checks (all of them), what it does. */
function stepOne(invoices, now, statuses, relays, readFails) {
  const mayBePaid = invoices.flatMap((invoice, index) =>
    now < invoice.expiresAt + 120 ? [index] : []
  );
  const outcome = stepOneOutcome(invoices, mayBePaid, statuses, relays, readFails);
  return { mayBePaid, checked: mayBePaid, outcome };
}

for (const c of earlierInvoices.cases) {
  check(`earlier invoices: ${c.name}`, () => {
    const invoices = declaredInvoices(c.declarations, c.records);
    expect(
      invoices.map(({ paymentHash, onchainAddress, createdAt, declaredAt }) => ({
        paymentHash,
        onchainAddress,
        createdAt,
        declaredAt
      })),
      c.expected.invoices
    );
    const { mayBePaid, checked, outcome } = stepOne(
      invoices,
      c.now,
      c.statuses ?? [],
      c.relays ?? earlierInvoices.relays,
      c.readFails === true
    );
    expect(
      { mayBePaid, checked, outcome },
      {
        mayBePaid: c.expected.mayBePaid,
        checked: c.expected.checked,
        outcome: c.expected.outcome
      }
    );
    // Statuses are given when step 1 checks, one per invoice; none otherwise.
    expect(
      c.statuses === undefined ? null : c.statuses.length,
      c.expected.checked.length === 0 ? null : invoices.length
    );
  });
}

// ---- On-chain payments (SPEC.md §31) ----------------------------------------------------------

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;

/** BIP-350: the checksum's polymod over the expanded human-readable part and the data. */
function bech32Polymod(values) {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= generator[i];
  }
  return chk >>> 0;
}

/** §31 "Deposit addresses": lowercase bech32m, `bc`, witness version 1, a 32-byte program. */
function isDepositAddress(text) {
  if (typeof text !== "string" || text.length !== 62 || !text.startsWith("bc1")) return false;
  const words = [];
  for (const char of text.slice(3)) {
    const word = BECH32_CHARSET.indexOf(char);
    if (word < 0) return false;
    words.push(word);
  }
  const hrp = [..."bc"].map((c) => c.charCodeAt(0));
  const expanded = [...hrp.map((c) => c >> 5), 0, ...hrp.map((c) => c & 31), ...words];
  if (bech32Polymod(expanded) !== BECH32M_CONST) return false;
  const data = words.slice(0, -6);
  // Version 1, then 52 words: 32 bytes and 4 bits of padding, which are zeros.
  return data.length === 53 && data[0] === 1 && (data[52] & 0b1111) === 0;
}

const SATS_PER_BTC = 100_000_000n;
const btcOf = (sats) => {
  const whole = sats / SATS_PER_BTC;
  const fraction = (sats % SATS_PER_BTC).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
};
const onchainPlace = (key, address) =>
  bytesToHex(hmac(sha256, key, utf8ToBytes(`onchain/v1/${address}`)));

const addressVectors = read("vectors/onchain-addresses.json");
for (const c of addressVectors.addresses) {
  check(`deposit address: ${c.name}`, () => expect(isDepositAddress(c.address), c.valid));
}
for (const c of addressVectors.registry.cases) {
  check(`registry address of ${c.address}`, () =>
    expect(
      onchainPlace(hexToBytes(addressVectors.registry.registryKey), c.address),
      c.registryAddress
    )
  );
}
for (const c of addressVectors.uris) {
  check(`payment URI: ${c.name}`, () => {
    const uri =
      c.address === null
        ? `lightning:${c.bolt11}`
        : `bitcoin:${c.address}?amount=${btcOf(BigInt(c.sats))}` +
          (c.bolt11 === null ? "" : `&lightning=${c.bolt11}`);
    expect(uri, c.uri);
  });
}
for (const c of addressVectors.amounts) {
  check(`BIP-21 amount of ${c.sats} sats`, () => expect(btcOf(BigInt(c.sats)), c.btc));
}

/** §31 "Methods by amount", for an order in sats. */
function methodsOf({ sats: text, sendable, address }) {
  const sats = BigInt(text);
  if (sats < 1n || sats > 2_100_000_000_000_000n) return { error: "invalid_order", param: "sats" };
  const lightning = sats >= BigInt(sendable.min) && sats <= BigInt(sendable.max);
  if (sats < 1000n)
    return lightning ? { methods: ["lightning"] } : { error: "invalid_order", param: "sats" };
  if (address === "leased") return { methods: lightning ? ["lightning", "onchain"] : ["onchain"] };
  if (lightning) return { methods: ["lightning"] };
  return { error: address === "explorer_failed" ? "network" : "onchain_unavailable" };
}
for (const c of read("vectors/payment-methods.json").cases) {
  check(`methods: ${c.name}`, () => expect(methodsOf(c), c.expected));
}

/** §31 "The merchant's tolerance": an integer from 0 to 1000, else 0. */
const toleranceOf = (value) =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 1000 ? value : 0;

const leases = read("vectors/onchain-leases.json");
const leaseRegistry = hexToBytes(leases.registryKey);
const leaseOuterKey = (place, author) =>
  derive(leaseRegistry, REGISTRY_DECLARATION_SALT, `outer/v1/${place}/${author}`);
check("leases: the sale's inner key", () =>
  expect(
    bytesToHex(conversationKey(hexToBytes(leases.saleSecret), leases.registryReader)),
    leases.innerConversationKey
  )
);
for (const c of leases.derived) {
  check(`leases: the keys of ${c.address}`, () => {
    const place = onchainPlace(leaseRegistry, c.address);
    expect(
      { registryAddress: place, outerKey: bytesToHex(leaseOuterKey(place, leases.saleAuthor)) },
      { registryAddress: c.registryAddress, outerKey: c.outerKey }
    );
  });
}

/** §31 "Opening it as the sale": the inside, or null when it is not valid. */
function leaseInside(outside, place) {
  let inside;
  try {
    inside = JSON.parse(decrypt(outside.sealed, hexToBytes(leases.innerConversationKey)));
  } catch {
    return null;
  }
  const ok =
    inside !== null &&
    typeof inside === "object" &&
    inside.version === 1 &&
    isDepositAddress(inside.address) &&
    onchainPlace(leaseRegistry, inside.address) === place &&
    Number.isSafeInteger(inside.sats) &&
    inside.sats >= 1 &&
    Number.isSafeInteger(inside.createdAt) &&
    Number.isSafeInteger(inside.expiresAt) &&
    inside.createdAt < inside.expiresAt &&
    outside.end === inside.expiresAt + 120;
  if (!ok) return null;
  if (inside.invoice === null) return inside.verifyUrl === null ? inside : null;
  // With an invoice: vectors/app/app.json's real one, of 21 000 msat, its timestamp and expiry.
  const real = app.realInvoice;
  return inside.invoice === real.invoice &&
    BigInt(inside.sats) * 1000n === BigInt(real.amountMsat) &&
    inside.createdAt === real.timestamp &&
    inside.expiresAt === real.timestamp + real.expirySeconds &&
    httpsUrl(inside.verifyUrl) !== null
    ? inside
    : null;
}

/** §11: whether the event's id is its hash (checked before anything else at a lease's place). */
const idIsHash = (event) => {
  const id = eventHash(event);
  return id !== null && id === event.id;
};
/** §11: whether the event's signature checks out. */
const signatureChecks = (event) => {
  try {
    return schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
  } catch {
    return false;
  }
};

for (const c of leases.events) {
  check(`lease: ${c.name}`, () => {
    const place = onchainPlace(leaseRegistry, c.address);
    let outside = null;
    try {
      // §31 "Opening a lease": whatever its author; the id first; a content of a newer NIP-44
      // version is ignored (decrypt throws); the signature is not checked here.
      const event = c.event;
      if (!idIsHash(event)) throw new Error("id");
      // §12: kind 30078 and the `d` tag; other tags are ignored.
      if (
        event.kind !== 30078 ||
        !event.tags.some(([name, value]) => name === "d" && value === place)
      ) {
        throw new Error("not at this place");
      }
      const plaintext = decrypt(event.content, leaseOuterKey(place, event.pubkey));
      if (utf8ToBytes(plaintext).length % 256 !== 0) throw new Error("record padding");
      const record = JSON.parse(plaintext);
      expect(record.t, "registry-onchain");
      const value = record.v;
      if (typeof value.version === "number" && value.version > 1) outside = "newer";
      else if (value.version === 1 && value.withdrawn === true) outside = value;
      else if (
        value.version === 1 &&
        Number.isSafeInteger(value.end) &&
        typeof value.sealed === "string"
      ) {
        outside = value;
      }
    } catch {
      outside = null;
    }
    expect(outside, c.outside);
    expect(signatureChecks(c.event), c.signature ?? true);
    const inside =
      outside && outside !== "newer" && !outside.withdrawn && c.event.pubkey === leases.saleAuthor
        ? leaseInside(outside, place)
        : null;
    expect(inside, c.inside);
    // §31 "The merchant's tolerance": the order's, absent or invalid read as none.
    if (inside) expect(toleranceOf(inside.tolerance), c.tolerance ?? 0);
    // §31 Leases: confirmed when `confirmed` is true.
    if (inside) expect(inside.confirmed === true, c.confirmed ?? true);
  });
}

/** §31: whether a record holds its address at `t`. */
const holdsAt = (record, t) =>
  record.outside === "newer" || (!record.outside.withdrawn && record.outside.end >= t - 300);

/**
 * §31: whether the records lease the address at `t`, walking each author's records from the
 * newest; and the records whose signature the walks check (indices).
 */
function walkLeases(records, t) {
  const checked = [];
  let leased = false;
  const usable = records.map((record, index) => ({ record, index }));
  const authors = new Set(usable.map(({ record }) => record.author));
  for (const author of authors) {
    const walk = usable
      .filter(({ record }) => record.author === author && record.id !== false)
      .sort(
        (a, b) =>
          b.record.createdAt - a.record.createdAt ||
          (a.record.eventId ?? "").localeCompare(b.record.eventId ?? "")
      );
    for (const [position, { record, index }] of walk.entries()) {
      if (holdsAt(record, t)) {
        leased = true;
        break;
      }
      const ends = walk.slice(position + 1).some((older) => holdsAt(older.record, t));
      if (!ends) break;
      checked.push(index);
      if (record.signature !== false) break;
    }
  }
  return { leased, checked: checked.sort((a, b) => a - b) };
}
for (const c of leases.leased) {
  check(`leased: ${c.name}`, () =>
    expect(walkLeases(c.records, c.t), { leased: c.expected, checked: c.checked })
  );
}

/** §31 "Leasing an address", step 3.3: a lease confirmed by a read of its address's leases. */
function isConfirmed({ records, sale, lease, t, complete }) {
  if (!complete || lease === null) return false;
  if (
    walkLeases(
      records.filter((record) => record.author !== sale),
      t
    ).leased
  )
    return false;
  const own = records[lease];
  return records.every(
    (record, index) =>
      index === lease ||
      record.author !== sale ||
      record.id === false ||
      record.createdAt < own.createdAt ||
      (record.createdAt === own.createdAt && (record.eventId ?? "") > (own.eventId ?? ""))
  );
}
for (const c of leases.confirmed) {
  check(`confirmed: ${c.name}`, () => expect(isConfirmed(c), c.expected));
}

check("app: an integration's lot of addresses", () => {
  const v = read("vectors/app/onchain-lot.json");
  const parsed = parseKey(v.secretKey);
  const key = hexToBytes(parsed.integrationKey);
  const lotAddress = bytesToHex(derive(key, INTEGRATION_SALT, "onchain-lot/address/v1"));
  const encryptionKey = derive(key, INTEGRATION_SALT, "channel/encryption-key/v1");
  expect(
    { team: parsed.team, lotAddress, channelEncryptionKey: bytesToHex(encryptionKey) },
    { team: v.team, lotAddress: v.lotAddress, channelEncryptionKey: v.channelEncryptionKey }
  );
  const { value } = openRecord(v.lot.event, {
    type: "integration-onchain-lot",
    address: lotAddress,
    author: parsed.team,
    key: encryptionKey
  });
  expect(value, v.lot.value.v);
  expect(value.updatedAt, v.lot.event.created_at);
  if (!value.addresses.every(isDepositAddress)) throw new Error("not deposit addresses");
  if (new Set(value.addresses).size !== value.addresses.length) throw new Error("twice");
});

// §31 "The merchant's acceptance": the app's records, read as a check reads them.
{
  const v = read("vectors/app/merchant-acceptance.json");
  const parsed = parseKey(v.secretKey);
  const key = hexToBytes(parsed.integrationKey);
  const encryptionKey = derive(key, INTEGRATION_SALT, "channel/encryption-key/v1");
  check("merchant's acceptances: the team and the channel's key", () =>
    expect(
      { team: parsed.team, channelEncryptionKey: bytesToHex(encryptionKey) },
      { team: v.team, channelEncryptionKey: v.channelEncryptionKey }
    )
  );
  /**
   * The record `event` is, read for `invoice`: what it counts, null, or "newer". A record dated after
   * the lease's end is set aside first, of a newer format or not.
   */
  const readMerchantAcceptance = (event, invoice, team = parsed.team) => {
    const address = invoice.acceptanceAddress;
    if (
      event.kind !== 30078 ||
      event.pubkey !== team ||
      !event.tags.some((tag) => tag[0] === "d" && tag[1] === address)
    ) {
      return null;
    }
    try {
      checkEvent(event);
    } catch {
      return null;
    }
    if (event.created_at > invoice.expiresAt + 120) return null;
    const record = openContent(event, encryptionKey);
    if (record === "newer") return "newer";
    if (record === null || record.t !== "integration-onchain-accepted") return null;
    const value = record.v;
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    if (typeof value.version === "number" && value.version > 1) return "newer";
    if (value.version !== 1) return null;
    const { received } = value;
    if (
      !Number.isSafeInteger(received) ||
      received < 1 ||
      BigInt(received) >= BigInt(invoice.sats)
    ) {
      return null;
    }
    return { received, createdAt: event.created_at };
  };
  for (const invoice of v.invoices) {
    check(`merchant's acceptance address of ${invoice.ref} at ${invoice.expiresAt}`, () => {
      const s = sale(key, { reader: v.team }, invoice.ref);
      expect([s.key, s.author], [invoice.saleKey, invoice.sale]);
      const info = `onchain-accepted/${s.author}/${invoice.onchainAddress}/${invoice.expiresAt}/v1`;
      expect(bytesToHex(derive(key, INTEGRATION_SALT, info)), invoice.acceptanceAddress);
    });
  }
  for (const c of v.records) {
    check(`merchant's acceptance: ${c.name}`, () =>
      expect(readMerchantAcceptance(c.event, v.invoices[c.invoice]), c.expected)
    );
  }

  // `made`: records the app cannot be asked to make (a damaged signature, a kind, a content of a
  // newer NIP-44 version, another integration's seal, `received` or `version` spelled otherwise, a
  // `version` above 1 that is no integer), made here with a team of this repository's own and fixed
  // random bytes; each is made again, then read.
  const made = v.made;
  const madeKey = parseKey(made.secretKey);
  const teamSecret = hexToBytes(made.teamSecret);
  check(
    "merchant's acceptances made here: the team, and the integration of the app's records",
    () =>
      expect(
        [madeKey.team, madeKey.integrationKey],
        [bytesToHex(schnorr.getPublicKey(teamSecret)), parsed.integrationKey]
      )
  );
  const otherKey = derive(
    hexToBytes(made.otherIntegrationKey),
    INTEGRATION_SALT,
    "channel/encryption-key/v1"
  );
  const fixed = (what, name) => sha256(utf8ToBytes(`${what}/${name}`));
  /** Signs `event` (its `id` set) with the team's secret, auxiliary data of `name`. */
  const signed = (event, name) => {
    const id = eventHash(event);
    const sig = bytesToHex(schnorr.sign(hexToBytes(id), teamSecret, fixed("aux", name)));
    return { ...event, id, pubkey: madeKey.team, sig };
  };
  /** §12: the plaintext `text` padded with spaces to a multiple of 256 bytes, sealed under `key`. */
  const sealed = (text, key, name) => {
    const padded = text + " ".repeat((256 - (utf8ToBytes(text).length % 256)) % 256);
    return encrypt(padded, key, fixed("nonce", name));
  };
  const plain = (value) => `{"t":"integration-onchain-accepted","v":${value}}`;
  const event = ({ name, kind = 30078, createdAt = 1791378300, value, key = encryptionKey }) =>
    signed(
      {
        kind,
        created_at: createdAt,
        tags: [["d", v.invoices[0].acceptanceAddress]],
        content: sealed(plain(value), key, name),
        pubkey: madeKey.team
      },
      name
    );
  const flip = (hex) => hex.slice(0, -1) + (hex.at(-1) === "0" ? "1" : "0");
  const recipes = [
    [
      "made here: accepted at 30 000 sats",
      () => event({ name: "base", value: '{"version":1,"received":30000}' })
    ],
    [
      "made here: `received` spelled 3e4: 30000, counted",
      () => event({ name: "3e4", value: '{"version":1,"received":3e4}' })
    ],
    [
      "made here: `received` spelled 30000.0: 30000, counted",
      () => event({ name: "30000.0", value: '{"version":1,"received":30000.0}' })
    ],
    [
      "made here: a damaged signature: ignored",
      () => {
        const e = event({ name: "base", value: '{"version":1,"received":30000}' });
        return { ...e, sig: flip(e.sig) };
      }
    ],
    [
      "made here: an id that is not its hash: ignored",
      () => {
        const e = event({ name: "base", value: '{"version":1,"received":30000}' });
        return { ...e, id: flip(e.id) };
      }
    ],
    [
      "made here: a content of a newer NIP-44 version (`#`): a newer format",
      () => {
        const e = event({ name: "#", value: '{"version":1,"received":30000}' });
        return signed(
          {
            kind: e.kind,
            created_at: e.created_at,
            tags: e.tags,
            content: "#",
            pubkey: madeKey.team
          },
          "#"
        );
      }
    ],
    [
      "made here: a content of NIP-44 version 3: a newer format",
      () => {
        const e = event({ name: "version 3", value: '{"version":1,"received":30000}' });
        const data = base64Strict(e.content);
        data[0] = 3;
        const content = Buffer.from(data).toString("base64");
        return signed(
          { kind: e.kind, created_at: e.created_at, tags: e.tags, content, pubkey: madeKey.team },
          "version 3"
        );
      }
    ],
    [
      "made here: of kind 1: ignored",
      () => event({ name: "kind 1", kind: 1, value: '{"version":1,"received":30000}' })
    ],
    [
      "made here: sealed with the channel key of another integration of the team: ignored",
      () =>
        event({
          name: "another integration",
          key: otherKey,
          value: '{"version":1,"received":30000}'
        })
    ],
    [
      "made here: a content of a newer NIP-44 version (`#`), dated after the lease's end: set aside",
      () =>
        signed(
          {
            kind: 30078,
            created_at: v.invoices[0].expiresAt + 121,
            tags: [["d", v.invoices[0].acceptanceAddress]],
            content: "#",
            pubkey: madeKey.team
          },
          "# late"
        )
    ],
    [
      "made here: version 2, dated after the lease's end: set aside",
      () =>
        event({
          name: "version 2 late",
          createdAt: v.invoices[0].expiresAt + 121,
          value: '{"version":2,"received":30000}'
        })
    ],
    [
      "made here: `version` spelled 1.0: version 1, counted",
      () => event({ name: "version 1.0", value: '{"version":1.0,"received":30000}' })
    ],
    [
      "made here: `version` 1.5, above 1: a newer format",
      () => event({ name: "version 1.5", value: '{"version":1.5,"received":30000}' })
    ]
  ];
  check("merchant's acceptances made here: each made again", () =>
    expect(
      made.records.map(({ name, invoice, event }) => ({ name, invoice, event })),
      recipes.map(([name, make]) => ({ name, invoice: 0, event: make() }))
    )
  );
  for (const c of made.records) {
    check(`merchant's acceptance: ${c.name}`, () =>
      expect(readMerchantAcceptance(c.event, v.invoices[c.invoice], madeKey.team), c.expected)
    );
  }
}

const witnesses = read("vectors/onchain-witnesses.json");
const witnessIntegrationKey = hexToBytes(witnesses.integrationKey);
const seenSecret = derive(
  witnessIntegrationKey,
  INTEGRATION_SALT,
  "onchain-seen/nostr-secret-key/v1"
);
const seenAddressKey = derive(
  witnessIntegrationKey,
  INTEGRATION_SALT,
  "onchain-seen/address-key/v1"
);
const seenAuthor = bytesToHex(schnorr.getPublicKey(seenSecret));
const seenMac = (text) => bytesToHex(hmac(sha256, seenAddressKey, utf8ToBytes(text)));
const witnessAddress = (address, txid, sale) => seenMac(`${address}/${txid}/${sale ?? "none"}`);
const orderTag = (address, sale) => seenMac(`order/${address}/${sale ?? "none"}`);
const addressTag = (address) => seenMac(`address/${address}`);
/** A coin as §31 writes it: `<txid>:<vout>`, lowercase, the vout a u32 without leading zeros. */
const isCoin = (value) =>
  typeof value === "string" &&
  /^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/.test(value) &&
  Number(value.slice(65)) <= 4294967295;

check("witnesses: the seen keys", () =>
  expect(
    {
      seenSecret: bytesToHex(seenSecret),
      seenAuthor,
      seenAddressKey: bytesToHex(seenAddressKey)
    },
    witnesses.derived
  )
);
for (const c of witnesses.addresses) {
  check(`witness address of ${c.txid.slice(0, 8)}, ${c.sale ?? "none"}`, () =>
    expect(witnessAddress(c.address, c.txid, c.sale), c.witnessAddress)
  );
}
for (const c of witnesses.orderTags) {
  check(`order tag of ${c.address.slice(0, 12)}, ${c.sale ?? "none"}`, () =>
    expect(orderTag(c.address, c.sale), c.orderTag)
  );
}
for (const c of witnesses.addressTags) {
  check(`address tag of ${c.address.slice(0, 12)}`, () =>
    expect(addressTag(c.address), c.addressTag)
  );
}
/** §31 Witnesses: `expiresAt` null for none, a safe integer for a sale. */
const witnessEnd = (v) =>
  v.sale === null ? v.expiresAt === null : Number.isSafeInteger(v.expiresAt);
/** §31 Witnesses, "Opening one": its value, "newer" (a newer format), or null. */
function openWitness(event) {
  try {
    // §12: a record is of a newer format only once its event checks out (§11), first here.
    checkEvent(event);
    if (event.pubkey !== seenAuthor || event.kind !== 30078) return null;
    const d = event.tags.filter(([name]) => name === "d");
    const o = event.tags.filter(([name]) => name === "o");
    if (d.length !== 1) return null;
    // §12 step 2: a content of a newer NIP-44 version (empty, `#`, a version byte other than 2).
    const record = openContent(event, hexToBytes(witnesses.channelEncryptionKey));
    if (record === null || record === "newer") return record;
    if (record.t !== "integration-onchain-seen") return null;
    const v = record.v;
    if (typeof v.version === "number" && v.version > 1) return "newer";
    return v.version === 1 &&
      isDepositAddress(v.address) &&
      /^[0-9a-f]{64}$/.test(v.txid) &&
      (v.sale === null || /^[0-9a-f]{64}$/.test(v.sale)) &&
      Number.isSafeInteger(v.sats) &&
      v.sats >= 1 &&
      v.sats <= 2_100_000_000_000_000 &&
      Array.isArray(v.inputs) &&
      v.inputs.length <= 100 &&
      v.inputs.every(isCoin) &&
      new Set(v.inputs).size === v.inputs.length &&
      typeof v.replacement === "boolean" &&
      !(v.sale === null && v.replacement) &&
      witnessEnd(v) &&
      d[0][1] === witnessAddress(v.address, v.txid, v.sale) &&
      o.some(([, tag]) => tag === orderTag(v.address, v.sale)) &&
      o.some(([, tag]) => tag === addressTag(v.address))
      ? v
      : null;
  } catch {
    return null;
  }
}
for (const c of witnesses.events) {
  check(`witness: ${c.name}`, () => expect(openWitness(c.event), c.value));
}

/**
 * §31 Leasing an address, step 3: the addresses of `addressTags` an event names. One of the seen
 * author that checks out names each address whose address tag it holds as an `o` tag, whatever its
 * content.
 */
function namedBy(event) {
  try {
    checkEvent(event);
  } catch {
    return [];
  }
  if (event.pubkey !== seenAuthor) return [];
  return witnesses.addressTags
    .map(({ address }) => address)
    .filter((address) =>
      event.tags.some(([name, tag]) => name === "o" && tag === addressTag(address))
    );
}
for (const c of witnesses.events) {
  check(`witness names: ${c.name}`, () => expect(namedBy(c.event), c.names));
}

/** §31 Replacements: the parts of each listed transaction, by txid. */
function paymentParts(txs) {
  const byTxid = new Map();
  for (const tx of txs) if (!byTxid.has(tx.txid)) byTxid.set(tx.txid, tx);
  const sorted = [...byTxid.values()].sort((a, b) =>
    a.order === b.order
      ? a.txid < b.txid
        ? -1
        : 1
      : a.order === null
        ? 1
        : b.order === null
          ? -1
          : a.order - b.order
  );
  const position = new Map(sorted.map((tx, i) => [tx.txid, i]));
  const rootsOf = new Map();
  sorted.forEach((tx, i) => {
    const before = sorted
      .slice(0, i)
      .filter((other) => other.inputs.some((coin) => tx.inputs.includes(coin)));
    const roots =
      before.length === 0
        ? [tx.txid]
        : [...new Set(before.flatMap((other) => rootsOf.get(other.txid)))].sort(
            (a, b) => position.get(a) - position.get(b)
          );
    rootsOf.set(tx.txid, roots);
  });
  const toGive = new Map(sorted.map((tx) => [tx.txid, BigInt(tx.sats)]));
  const parts = {};
  for (const tx of sorted.filter(({ listed }) => listed)) {
    const roots = rootsOf.get(tx.txid);
    let owed = BigInt(tx.sats);
    const list = [];
    if (roots.length === 1 && roots[0] === tx.txid) {
      toGive.set(tx.txid, 0n);
    } else {
      for (const root of roots) {
        const take = owed < toGive.get(root) ? owed : toGive.get(root);
        if (take > 0n) {
          list.push({ sats: String(take), root });
          toGive.set(root, toGive.get(root) - take);
          owed -= take;
        }
      }
    }
    if (owed > 0n) list.push({ sats: String(owed), root: tx.txid });
    parts[tx.txid] = list;
  }
  return parts;
}

for (const c of read("vectors/onchain-replacements.json").cases) {
  check(`replacements: ${c.name}`, () => expect(paymentParts(c.txs), c.parts));
}

/** The least accepted of `sats` (bigint) with `tolerance` (basis points), on integers. */
const leastAccepted = (sats, tolerance) => sats - (sats * BigInt(tolerance)) / 10000n;
/**
 * §31 "The on-chain payment", step 4: what is due on-chain, max(1, min(L, M) − R), 0 once the rest
 * invoices paid `sats`; `merchant` (M), the `received` of the merchant's acceptance (null without
 * one), counts against the least the tolerance accepts (L) only when it is less.
 */
function dueOnchain(sats, tolerance, paidByRests, merchant = null) {
  if (paidByRests >= sats) return 0n;
  const least = leastAccepted(sats, tolerance);
  const accepted = merchant !== null && merchant < least ? merchant : least;
  const due = accepted - paidByRests;
  return due > 0n ? due : 1n;
}
const tolerances = read("vectors/onchain-tolerances.json");
for (const c of tolerances.values) {
  check(`tolerance: ${c.name}`, () => expect(toleranceOf(c.value), c.expected));
}
for (const c of tolerances.accepted) {
  check(`least accepted of ${c.sats} at ${c.tolerance}`, () =>
    expect(leastAccepted(BigInt(c.sats), c.tolerance).toString(), c.expected)
  );
}
for (const c of tolerances.due) {
  const merchant = c.merchantAccepted === undefined ? null : BigInt(c.merchantAccepted);
  const name = `${c.sats} at ${c.tolerance}, ${c.paidByRests} paid by rests, accepted ${merchant}`;
  check(`due on-chain of ${name}`, () =>
    expect(
      dueOnchain(BigInt(c.sats), c.tolerance, BigInt(c.paidByRests), merchant).toString(),
      c.expected
    )
  );
}

const onchainPayments = read("vectors/onchain-payments.json");

/** The merchant's relays in onchain-payments.json: a list of 3, of which 2 are a majority. */
const MERCHANT_RELAYS = 3;
/**
 * §31 "The merchant's acceptance", counted: of the records read on every relay (`records`, each
 * opened: its `received` and `createdAt`, or `newer` for one of a newer format; `sentBy`, how many
 * of the merchant's relays sent it, absent: all of them; absent: none), those valid (`received` a
 * safe integer from 1, below `sats`) or of a newer format, dated at the latest at the lease's `end`,
 * that a majority of the relays sent; the newest of them (`createdAt`, then the lowest `id`)
 * decides: its `received`, or null for one of a newer format. Null when none counts.
 */
function merchantAccepted(records, sats, end) {
  if (records === undefined) return null;
  const majority = Math.floor(MERCHANT_RELAYS / 2) + 1;
  const counted = records
    .filter((record) => {
      if ((record.sentBy ?? MERCHANT_RELAYS) < majority || record.createdAt > end) return false;
      if (record.newer === true) return true;
      const value = BigInt(record.received);
      return value >= 1n && value < sats && value <= BigInt(Number.MAX_SAFE_INTEGER);
    })
    .sort((a, b) => {
      if (a.createdAt !== b.createdAt) return b.createdAt - a.createdAt;
      if (a.id === undefined || b.id === undefined) throw new Error("two of one date need ids");
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
  if (counted.length === 0 || counted[0].newer === true) return null;
  return BigInt(counted[0].received);
}

/**
 * §31 Explorers, "When a transaction was received": BlockCypher's `received` as BlockCypher writes
 * it, in Unix milliseconds (the fraction past milliseconds dropped); throws for anything else.
 * Not `Date.parse`, which takes other spellings and days a month does not have.
 */
function blockcypherTime(text) {
  const match =
    typeof text === "string" &&
    /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$/.exec(
      text
    );
  if (!match) throw new Error(`Not BlockCypher's time: ${text}`);
  const [year, month, day, hours, minutes, seconds] = match.slice(1, 7).map(Number);
  const milliseconds = Number((match[7] ?? "").padEnd(3, "0").slice(0, 3));
  const time = Date.UTC(year, month - 1, day, hours, minutes, seconds, milliseconds);
  const back = new Date(time);
  const real =
    back.getUTCFullYear() === year &&
    back.getUTCMonth() === month - 1 &&
    back.getUTCDate() === day &&
    back.getUTCHours() === hours &&
    back.getUTCMinutes() === minutes &&
    back.getUTCSeconds() === seconds;
  if (!real || !(time > 0)) throw new Error(`Not a real time: ${text}`);
  return time;
}

/**
 * §31 Explorers: whether a value is a transaction as an explorer must write it (more members are
 * ignored). `scriptpubkey_address` is a string when present: null is not absent (§2). Its outputs
 * together hold 2 100 000 000 000 000 sats at most.
 */
function explorerTx(tx) {
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const isTxid = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  return (
    isObject(tx) &&
    isTxid(tx.txid) &&
    Array.isArray(tx.vin) &&
    tx.vin.every(
      (input) =>
        isObject(input) &&
        (input.is_coinbase === true ||
          (isTxid(input.txid) &&
            Number.isInteger(input.vout) &&
            input.vout >= 0 &&
            input.vout <= 4294967295))
    ) &&
    Array.isArray(tx.vout) &&
    tx.vout.every(
      (output) =>
        isObject(output) &&
        Number.isSafeInteger(output.value) &&
        output.value >= 0 &&
        (!Object.hasOwn(output, "scriptpubkey_address") ||
          typeof output.scriptpubkey_address === "string")
    ) &&
    tx.vout.reduce((sum, output) => sum + BigInt(output.value), 0n) <= 2100000000000000n &&
    isObject(tx.status) &&
    typeof tx.status.confirmed === "boolean" &&
    (!tx.status.confirmed ||
      (Number.isSafeInteger(tx.status.block_height) && tx.status.block_height >= 0))
  );
}

/** §31 "The on-chain payment", then how both parts combine; and the witnesses it publishes. */
function onchainStatus(invoice, c) {
  const sats = BigInt(invoice.sats);
  // "The rest of an underpayment": the rest invoices in their order (date, then payment hash), and
  // what those paid (each payment hash once). Each one's amount, payment hash and dates are its
  // invoice's, decoded here: never the vector's copy of them.
  const rests = (c.rests ?? [])
    .map((rest) => {
      const decoded = satsInvoiceOf(rest.invoice);
      if (!decoded) throw new Error(`Not an invoice of the rest: ${rest.invoice}`);
      const own = {
        ...rest,
        sats: (decoded.msat / 1000n).toString(),
        paymentHash: decoded.paymentHash,
        createdAt: decoded.timestamp,
        expiresAt: decoded.timestamp + decoded.expiry
      };
      expect(
        [rest.sats, rest.paymentHash, rest.createdAt, rest.expiresAt],
        [own.sats, own.paymentHash, own.createdAt, own.expiresAt]
      );
      return own;
    })
    .sort(
      (a, b) =>
        a.createdAt - b.createdAt ||
        (a.paymentHash < b.paymentHash ? -1 : a.paymentHash > b.paymentHash ? 1 : 0)
    );
  const paidHashes = new Set();
  const preimages = [];
  let paidByRests = 0n;
  for (const rest of rests) {
    if (rest.lightning.state !== "paid" || paidHashes.has(rest.paymentHash)) continue;
    paidHashes.add(rest.paymentHash);
    paidByRests += BigInt(rest.sats);
    preimages.push(rest.lightning.preimage);
  }
  const restError = rests.find((rest) => rest.lightning.error)?.lightning.error;
  const restsFinal = rests.every(
    (rest) => rest.lightning.state === "expired" || rest.lightning.state === "paid"
  );
  const end = invoice.expiresAt + 120;
  const address = invoice.onchainAddress;
  const published = [];
  const asked = [];
  const paysA = (tx) =>
    tx.vout
      .filter((output) => output.scriptpubkey_address === address)
      .reduce((total, output) => total + BigInt(output.value), 0n);
  const coins = (tx) =>
    tx.vin.filter((input) => !input.is_coinbase).map(({ txid, vout }) => `${txid}:${vout}`);
  /** BlockCypher's time of `txid` (Unix ms), null when it does not know it; throws when it fails. */
  const receivedTime = (txid) => {
    asked.push(txid);
    if (c.blockcypher.error) throw new Error("BlockCypher failed");
    const text = c.blockcypher[txid];
    if (text === undefined) return null;
    return blockcypherTime(text);
  };
  const onchain = (() => {
    if (c.explorer.error) return { error: "network" };
    // §31 Explorers: anything but an array of such transactions is a failure.
    if (!Array.isArray(c.explorer.txs) || !c.explorer.txs.every(explorerTx)) {
      return { error: "network" };
    }
    const paying = c.explorer.txs.filter((tx) => paysA(tx) > 0n);
    if (paying.length > 0 && c.witnesses === "unreadable") return { error: "network" };
    // §31 "The merchant's acceptance": read with the witnesses; fewer than a majority answering
    // is `network`.
    if (paying.length > 0 && c.merchantAccepted === "unreadable") return { error: "network" };
    // §31 Witnesses: a witness at another address is of no invoice of this read (a relay sent
    // it anyway: the same transaction may pay another order's address).
    const atA = (witnesses) => witnesses.filter((w) => w.address !== "other");
    const held = Array.isArray(c.witnesses) ? atA(c.witnesses) : [];
    const listed = new Set(paying.map(({ txid }) => txid));
    // §31 Witnesses: of this invoice (its sale, its expiresAt), of another invoice (another sale,
    // or another expiresAt of its sale).
    const isOfThis = (w) => w.sale === "this" && w.expiresAt === invoice.expiresAt;
    const isOfOther = (w) =>
      w.sale === "other" || (w.sale === "this" && w.expiresAt !== invoice.expiresAt);
    const ofSale = new Map(held.filter(isOfThis).map((w) => [w.txid, w]));
    // Of a newer format at the witness address of a txid and the order's sale, or of `none`.
    const newer = held.filter((w) => w.sale === "newer").map(({ txid }) => txid);
    const newerNone = held.filter((w) => w.sale === "newer none").map(({ txid }) => txid);
    // Step 2: the parts, from the witnesses of this invoice and of other invoices; and step 3.1:
    // whether a transaction is another invoice's.
    const partsOf = (witnesses) => {
      const mine = witnesses.filter(isOfThis);
      const others = witnesses.filter(isOfOther);
      const named = new Set([...mine, ...others].map(({ txid }) => txid));
      const parts = paymentParts([
        ...[...mine, ...others].map((w) => ({
          txid: w.txid,
          sats: w.sats,
          inputs: w.inputs,
          order: w.seenAt,
          listed: listed.has(w.txid)
        })),
        ...paying
          .filter(({ txid }) => !named.has(txid))
          .map((tx) => ({
            txid: tx.txid,
            sats: paysA(tx),
            inputs: coins(tx),
            order: null,
            listed: true
          }))
      ]);
      const othersName = new Set(others.map(({ txid }) => txid));
      const anothers = (txid) =>
        othersName.has(txid) || parts[txid].some(({ root }) => othersName.has(root));
      return { parts, anothers };
    };
    const { parts, anothers } = partsOf(held);
    // Step 3: what each transaction is.
    const kindOf = new Map();
    for (const tx of paying) {
      const { txid } = tx;
      // Another invoice's: named by its witness, or standing for a payment one names.
      if (anothers(txid)) {
        kindOf.set(txid, "another's");
        continue;
      }
      const witness = ofSale.get(txid);
      if (witness && !witness.replacement) {
        kindOf.set(txid, "in time");
        continue;
      }
      if (newer.includes(txid)) {
        kindOf.set(txid, "undecided");
        continue;
      }
      const publishInTime = () => {
        if (c.publishFails) return false;
        published.push({ txid, sale: "this", replacement: false });
        kindOf.set(txid, "in time");
        return true;
      };
      if (c.now <= end) {
        if (!publishInTime()) return { error: "network" };
        continue;
      }
      if (witness) {
        kindOf.set(txid, "replacement");
        continue;
      }
      const replaces = parts[txid].some(({ root }) => root !== txid);
      if (!parts[txid].every(({ root }) => root !== txid)) {
        let time;
        try {
          time = receivedTime(txid);
        } catch {
          return { error: "network" };
        }
        if (time !== null && time <= end * 1000) {
          if (!publishInTime()) return { error: "network" };
          continue;
        }
      }
      if ([...newer, ...newerNone].some((other) => !listed.has(other))) {
        kindOf.set(txid, "undecided");
        continue;
      }
      if (replaces) {
        if (c.publishFails) return { error: "network" };
        published.push({ txid, sale: "this", replacement: true });
        kindOf.set(txid, "replacement");
      } else {
        // A witness none, unless one names it, or one of a newer format is where it would go
        // (§12: never written over).
        if (!held.some((w) => w.txid === txid && w.sale === null) && !newerNone.includes(txid)) {
          published.push({ txid, sale: null, replacement: false });
        }
        kindOf.set(txid, "late");
      }
    }
    // Read again once its witnesses are on a majority: one another invoice's witness names now is
    // another's.
    if (published.some(({ sale }) => sale === "this")) {
      if (c.witnessesAgain === "unreadable") return { error: "network" };
      if (c.witnessesAgain) {
        const again = partsOf(atA(c.witnessesAgain));
        for (const { txid } of paying) if (again.anothers(txid)) kindOf.set(txid, "another's");
      }
    }
    // Step 4: what counts.
    const inTime = (root) =>
      listed.has(root) ? kindOf.get(root) === "in time" : ofSale.get(root)?.replacement === false;
    const counted = new Map();
    for (const { txid } of paying) {
      if (kindOf.get(txid) === "undecided" || kindOf.get(txid) === "another's") continue;
      const sum = parts[txid]
        .filter(({ root }) => inTime(root))
        .reduce((total, part) => total + BigInt(part.sats), 0n);
      if (sum > 0n) counted.set(txid, sum);
    }
    const undecided = [...kindOf.values()].includes("undecided");
    const received = [...counted.values()].reduce((total, sum) => total + sum, 0n);
    // What is due on-chain: the least the order's tolerance accepts (the amount without one), less
    // what the rest invoices paid; nothing when they paid the amount.
    const due = dueOnchain(
      sats,
      toleranceOf(c.tolerance),
      paidByRests,
      paying.length > 0 ? merchantAccepted(c.merchantAccepted, sats, end) : null
    );
    if (due === 0n) return { kind: "paid", received, txids: [] };
    if (received < due) {
      return { kind: "underpaid", received, final: c.now > end && !undecided };
    }
    const order = paying.filter(({ txid }) => counted.has(txid));
    const confirmationsOf = (tx, height) =>
      tx.status.confirmed ? Math.max(1, height - tx.status.block_height + 1) : 0;
    const confirmations = Math.min(...order.map((tx) => confirmationsOf(tx, c.explorer.height)));
    const txids = order.map(({ txid }) => txid);
    // At 3 or more on the explorer read (mempool.space, or the merchant's node): paid.
    if (confirmations >= 3) return { kind: "paid", received, txids };
    return { kind: "unconfirmed", received, confirmations, txids };
  })();
  const status = (() => {
    const lightning = c.lightning;
    if (lightning?.state === "paid") {
      return { state: "paid", method: "lightning", preimage: lightning.preimage };
    }
    if (paidByRests >= sats) {
      // What came on-chain in time counts too (0 when the on-chain part failed).
      const onchainReceived = onchain.error ? 0n : onchain.received;
      return {
        state: "paid",
        method: "mixed",
        received: (onchainReceived + paidByRests).toString(),
        txids: [],
        preimages
      };
    }
    if (onchain.kind === "paid") {
      const received = (onchain.received + paidByRests).toString();
      return paidByRests > 0n
        ? { state: "paid", method: "mixed", received, txids: onchain.txids, preimages }
        : { state: "paid", method: "onchain", received, txids: onchain.txids };
    }
    if (onchain.kind === "unconfirmed") {
      return {
        state: "unconfirmed",
        received: (onchain.received + paidByRests).toString(),
        confirmations: onchain.confirmations,
        txids: onchain.txids
      };
    }
    if (lightning?.error) return { error: lightning.error };
    if (restError) return { error: restError };
    if (onchain.error) return { error: onchain.error };
    const received = onchain.received + paidByRests;
    const lightningFinal = lightning === null || lightning.state === "expired";
    if (lightningFinal && onchain.final && restsFinal) {
      return { state: "expired", received: received.toString() };
    }
    // "The status's rest": what is left, the latest rest invoice of exactly that, its QR code.
    let rest = null;
    if (received > 0n && received < sats && c.now < invoice.expiresAt) {
      const left = sats - received;
      const bolt11 =
        rests
          .filter(
            (r) => BigInt(r.sats) === left && !paidHashes.has(r.paymentHash) && c.now < r.expiresAt
          )
          .at(-1)?.invoice ?? null;
      const uri =
        left >= 1000n
          ? `bitcoin:${address}?amount=${btcOf(left)}` + (bolt11 ? `&lightning=${bolt11}` : "")
          : bolt11 && `lightning:${bolt11}`;
      rest = { sats: left.toString(), bolt11, paymentUri: uri };
    }
    return { state: "open", expiresAt: invoice.expiresAt, received: received.toString(), rest };
  })();
  // "Acceptance records": what the check publishes for the pages of the order's checkout links,
  // unless a majority of the relays each hold one of `received` or less (`accepted`).
  let acceptance = null;
  const accepted =
    status.state === "unconfirmed" ||
    (status.state === "paid" && status.method !== "lightning" && status.txids.length > 0);
  if (
    accepted &&
    BigInt(status.received) < sats &&
    c.now < invoice.expiresAt + 604800 &&
    !(c.accepted != null && BigInt(c.accepted) <= BigInt(status.received))
  ) {
    acceptance = status.received;
  }
  return { status, published: status.error ? [] : published, asked, acceptance };
}
// §2: these vectors spell integers as floats on purpose; a tool that rewrites a vector through a
// JSON parser and back would silently drop those spellings, and their test with them.
check("vectors keep the integers they spell as floats", () => {
  const spellings = {
    "vectors/onchain-payments.json": ['"vout": 0.0', '"value": 4.9e4', '"block_height": 969998.0'],
    "vectors/onchain-witnesses.json": ['"created_at": 1791378380.0', '"kind": 30078.0']
  };
  for (const [file, texts] of Object.entries(spellings)) {
    const raw = readFileSync(join(ROOT, file), "utf8");
    for (const text of texts) if (!raw.includes(text)) throw new Error(`${file}: no ${text}`);
  }
});
for (const c of onchainPayments.cases) {
  check(`on-chain payment: ${c.name}`, () => {
    const { status, published, asked, acceptance } = onchainStatus(onchainPayments.invoice, c);
    expect(status, c.expected);
    if (!c.expected.error) expect(published, c.published);
    expect(asked, c.asked);
    expect(acceptance, c.acceptance ?? null);
  });
}

// ---- The merchant's Bitcoin node (SPEC.md §31) ------------------------------------------------

/**
 * §31 "A node URL", an IPv4 address: 4 decimal numbers from 0 to 255 without a leading zero; its
 * numbers, or null when the text is not one.
 */
function nodeIpv4(host) {
  const numbers = host.split(".");
  if (numbers.length !== 4) return null;
  const values = [];
  for (const number of numbers) {
    if (number.length < 1 || number.length > 3 || ![...number].every(isDigit)) return null;
    if (number.length > 1 && number[0] === "0") return null;
    if (+number > 255) return null;
    values.push(+number);
  }
  return values;
}

/** §31 "A node URL", a name: 2 labels or more, the last starting with a letter, not localhost. */
function isNodeName(host) {
  if (host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (![...label].every((c) => isLower(c) || isDigit(c) || c === "-")) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  if (!isLower(labels.at(-1)[0])) return false;
  return host !== "localhost" && !host.endsWith(".localhost");
}

/** §31 "A node URL": whether a host is one, and local; null when it is none. */
function nodeHost(host) {
  const ip = nodeIpv4(host);
  if (ip !== null) {
    const [a, b] = ip;
    if (a === 0 || a === 127) return null;
    const local =
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127);
    return { local };
  }
  if (!isNodeName(host)) return null;
  return { local: host.slice(host.lastIndexOf(".") + 1) === "local" };
}

/**
 * §31 "A node URL" in its one spelling, then "Where the node is read": its REST and WebSocket
 * URLs, or null when the value is not one. Nothing is repaired.
 */
function nodeUrl(url) {
  if (typeof url !== "string" || url.length > 200) return null;
  const scheme = url.startsWith("https://") ? "https" : url.startsWith("http://") ? "http" : null;
  if (scheme === null) return null;
  const after = url.slice(scheme.length + 3);
  const slash = after.indexOf("/");
  const authority = slash < 0 ? after : after.slice(0, slash);
  const path = slash < 0 ? null : after.slice(slash);
  const colon = authority.indexOf(":");
  const host = colon < 0 ? authority : authority.slice(0, colon);
  const port = colon < 0 ? null : authority.slice(colon + 1);
  const kind = nodeHost(host);
  if (kind === null || (scheme === "http" && !kind.local)) return null;
  if (port !== null) {
    if (port.length < 1 || port.length > 5 || ![...port].every(isDigit)) return null;
    if (port[0] === "0" || +port > 65535) return null;
  }
  if (path !== null) {
    const rest = [...path.slice(1)];
    if (!rest.every((c) => c >= "!" && c <= "~" && !"?#@\\".includes(c))) return null;
    if (path.endsWith("/") || asciiLower(path).endsWith("/api")) return null;
  }
  return {
    rest: `${url}/api`,
    webSocket: `${scheme === "https" ? "wss" : "ws"}${url.slice(scheme.length)}/api/v1/ws`
  };
}

/** §31: `url` and `fallback` of a node as the channel and a link's record write them, or null. */
function nodeParts(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (!Object.hasOwn(value, "url") || nodeUrl(value.url) === null) return null;
  if (value.fallback !== "mempool" && value.fallback !== "none") return null;
  return { url: value.url, fallback: value.fallback };
}

/** §31 "A node of the Internet": a node URL in https whose host is a name not under `local`. */
function isInternetNode(url) {
  if (!url.startsWith("https://")) return false;
  const authority = url.slice("https://".length).split("/")[0];
  const host = authority.split(":")[0];
  return nodeIpv4(host) === null && !host.endsWith(".local");
}

/** §14, §31: the channel's `bitcoinNode` (`present` false: absent), or null for none. */
function channelNode(present, value) {
  const parts = present ? nodeParts(value) : null;
  if (parts === null || typeof value.payers !== "boolean") return null;
  if (value.payers && !isInternetNode(parts.url)) return null;
  return { ...parts, payers: value.payers };
}

/** §30 "The record": the `bitcoinNode` a checkout link's record holds, or null when absent. */
function writtenNode(present, channel, address) {
  const node = channelNode(present, channel);
  return address && node !== null && node.payers
    ? { url: node.url, fallback: node.fallback }
    : null;
}

/** §31 "`fallback`": the explorers one read asks, in order, and whose answer it gives. */
function explorerRead(node, mempoolAnswers) {
  const order =
    node === null
      ? ["mempool"]
      : node.fallback === "none"
        ? ["node"]
        : node.failedRecently
          ? ["mempool", "node"]
          : ["node", "mempool"];
  const asked = [];
  for (const explorer of order) {
    asked.push(explorer);
    if (explorer === "node" ? node.answers : mempoolAnswers) return { asked, result: explorer };
  }
  return { asked, result: "network" };
}

const bitcoinNodes = read("vectors/bitcoin-nodes.json");
for (const c of bitcoinNodes.urls) {
  check(`node URL: ${c.name}`, () => expect(nodeUrl(c.url), c.expected));
}
for (const c of bitcoinNodes.channels) {
  check(`channel's node: ${c.name}`, () =>
    expect(channelNode(Object.hasOwn(c, "value"), c.value), c.expected)
  );
}
for (const c of bitcoinNodes.reads) {
  check(`explorer read: ${c.name}`, () =>
    expect(explorerRead(c.node, c.mempoolAnswers), c.expected)
  );
}
for (const c of bitcoinNodes.writes) {
  check(`record's node written: ${c.name}`, () =>
    expect(writtenNode(Object.hasOwn(c, "channel"), c.channel, c.address), c.expected)
  );
}

// ---- The rest of an underpayment (SPEC.md §31) ---------------------------------------------------

/**
 * §19: a BOLT11 invoice's network, its amount in millisatoshis (null without one), its timestamp,
 * its first payment hash and first description hash of 52 words (null without one) and its last
 * expiry (3600 s without one). Null when it is not one: mixed case, a bad checksum, a field
 * running past the signature, an amount above 21 000 000 BTC or not in whole millisatoshis, an
 * expiry field of more than 7 words, no payment hash.
 */
function bolt11Of(text) {
  if (typeof text !== "string" || (/[a-z]/.test(text) && /[A-Z]/.test(text))) return null;
  const lowered = asciiLower(text);
  const at = lowered.lastIndexOf("1");
  if (at < 1) return null;
  const hrp = lowered.slice(0, at);
  const words = [];
  for (const char of lowered.slice(at + 1)) {
    const word = BECH32_CHARSET.indexOf(char);
    if (word < 0) return null;
    words.push(word);
  }
  const codes = [...hrp].map((c) => c.charCodeAt(0));
  const expanded = [...codes.map((c) => c >> 5), 0, ...codes.map((c) => c & 31), ...words];
  if (bech32Polymod(expanded) !== 1) return null;
  const head = /^ln(bcrt|bc|tbs|tb)(?:([1-9][0-9]*)([munp]?))?$/.exec(hrp);
  if (!head) return null;
  let msat = null;
  if (head[2] !== undefined) {
    const digits = BigInt(head[2]);
    const unit = head[3];
    if (unit === "p") {
      if (digits % 10n !== 0n) return null;
      msat = digits / 10n;
    } else {
      msat = digits * { "": 10n ** 11n, m: 10n ** 8n, u: 10n ** 5n, n: 10n ** 2n }[unit];
    }
    if (msat > 2_100_000_000_000_000_000n) return null;
  }
  const data = words.slice(0, -6);
  if (data.length < 7 + 104) return null;
  const integer = (list) => list.reduce((n, w) => n * 32 + w, 0);
  const timestamp = integer(data.slice(0, 7));
  let paymentHash = null;
  let descriptionHash = null;
  let expiry = 3600;
  let i = 7;
  const end = data.length - 104;
  const wordsToHex = (field) => {
    let bits = 0n;
    for (const w of field) bits = (bits << 5n) | BigInt(w);
    return (bits >> 4n).toString(16).padStart(64, "0");
  };
  while (i < end) {
    const tag = data[i];
    const length = data[i + 1] * 32 + data[i + 2];
    const field = data.slice(i + 3, i + 3 + length);
    if (i + 3 + length > end) return null;
    if (tag === 1 && length === 52 && paymentHash === null) paymentHash = wordsToHex(field);
    if (tag === 23 && length === 52 && descriptionHash === null)
      descriptionHash = wordsToHex(field);
    if (tag === 6) {
      if (length > 7) return null;
      expiry = integer(field);
    }
    i += 3 + length;
  }
  if (paymentHash === null) return null;
  return { network: head[1], msat, timestamp, expiry, paymentHash, descriptionHash };
}

/**
 * What every record asks of its invoice: it decodes (§19) on network `bc`, with an amount above 0
 * and a whole number of sats. Its decoding, or null.
 */
function satsInvoiceOf(text) {
  const invoice = bolt11Of(text);
  if (!invoice || invoice.network !== "bc" || invoice.msat === null) return null;
  return invoice.msat > 0n && invoice.msat % 1000n === 0n ? invoice : null;
}

for (const c of read("vectors/bolt11.json").cases) {
  check(`BOLT11: ${c.name}`, () => {
    const decoded = bolt11Of(c.invoice);
    expect(
      decoded && {
        network: decoded.network,
        amountMsat: decoded.msat === null ? null : decoded.msat.toString(),
        timestamp: decoded.timestamp,
        expirySeconds: decoded.expiry,
        paymentHash: decoded.paymentHash,
        descriptionHash: decoded.descriptionHash
      },
      c.expected
    );
  });
}

/** §18 "Invoice checks", in their order: the first an answer fails, or null when it passes all. */
function invoiceCheck({ answer, sats, durationSeconds, now }, payRequest) {
  const invoice = bolt11Of(answer.pr);
  if (!invoice) return "bolt11";
  if (invoice.network !== "bc") return "network";
  if (invoice.msat !== BigInt(sats) * 1000n) return "amount";
  if (invoice.descriptionHash !== bytesToHex(sha256(utf8ToBytes(payRequest.metadata)))) {
    return "description_hash";
  }
  const callback = httpsUrl(payRequest.callback);
  const verify = httpsUrl(answer.verify);
  if (!callback) throw new Error("the vector's callback is not an https URL");
  if (!verify || !sameHost(verify, callback)) return "verify_url";
  if (invoice.expiry > durationSeconds) return "duration";
  if (invoice.expiry <= 0) return "expired";
  if (Math.abs(invoice.timestamp - now) > 300) return "clock";
  if (invoice.timestamp + invoice.expiry <= now) return "expired";
  return null;
}
{
  const v = read("vectors/invoice-checks.json");
  for (const c of v.cases) {
    check(`invoice check: ${c.name}`, () => {
      const failed = invoiceCheck(c, v.payRequest);
      expect(
        failed === null ? { valid: true } : { error: "invalid_invoice", check: failed },
        c.expected
      );
    });
  }
}

/** §30 "Reading a record": what the page shows of a link's record value, "newer" or "invalid". */
function readLinkRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return "invalid";
  if (typeof value.version === "number" && value.version > 2) return "newer";
  if (value.version !== 1 && value.version !== 2) return "invalid";
  const text = (s) => typeof s === "string" && s.isWellFormed();
  const { businessName, fiat, note, redirectUrl } = value;
  if (!text(businessName) || trimAscii(businessName) === "") return "invalid";
  if ([...businessName].length > 200) return "invalid";
  const fiatOk =
    fiat === null ||
    (typeof fiat === "object" &&
      !Array.isArray(fiat) &&
      Number.isSafeInteger(fiat.minor) &&
      fiat.minor >= 1 &&
      Number.isInteger(fiat.digits) &&
      fiat.digits >= 0 &&
      fiat.digits <= 8 &&
      typeof fiat.currency === "string" &&
      /^[A-Z]{3}$/.test(fiat.currency) &&
      fiat.currency !== "SAT");
  if (!fiatOk) return "invalid";
  if (!text(note)) return "invalid";
  const noteLength = [...note].length;
  if (noteLength < 1 || noteLength > 100 || /[\u0000-\u001f\u007f]/.test(note)) return "invalid";
  const redirect = typeof redirectUrl === "string" ? redirectShown(redirectUrl) : null;
  if (redirectUrl !== null && redirect === null) return "invalid";
  /** The invoice and its verify URL, both null (version 2 only), or valid; undefined if not. */
  const lightning = () => {
    if (value.invoice === null && value.verifyUrl === null) return null;
    const invoice = satsInvoiceOf(value.invoice);
    return invoice && httpsUrl(value.verifyUrl) !== null ? invoice : undefined;
  };
  const invoice = lightning();
  if (value.version === 1) {
    if (!invoice) return "invalid";
    return {
      sats: (invoice.msat / 1000n).toString(),
      paymentHash: invoice.paymentHash,
      onchainAddress: null,
      expiresAt: invoice.timestamp + invoice.expiry,
      redirect,
      rest: null
    };
  }
  const { onchainAddress, sats, createdAt, expiresAt, restAuthor, restKey } = value;
  if (invoice === undefined || !isDepositAddress(onchainAddress)) return "invalid";
  if (!Number.isSafeInteger(sats) || sats < 1 || sats > 2_100_000_000_000_000) return "invalid";
  if (!Number.isSafeInteger(createdAt) || !Number.isSafeInteger(expiresAt)) return "invalid";
  if (createdAt >= expiresAt) return "invalid";
  if (
    invoice &&
    (invoice.msat !== BigInt(sats) * 1000n ||
      invoice.timestamp !== createdAt ||
      invoice.timestamp + invoice.expiry !== expiresAt)
  ) {
    return "invalid";
  }
  let rest = null;
  if (restAuthor !== undefined || restKey !== undefined) {
    const hex32 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
    if (!hex32(restAuthor) || !hex32(restKey)) return "invalid";
    try {
      schnorr.utils.lift_x(BigInt(`0x${restAuthor}`));
    } catch {
      return "invalid";
    }
    rest = { author: restAuthor, key: restKey };
  }
  return {
    sats: String(sats),
    paymentHash: invoice ? invoice.paymentHash : null,
    onchainAddress,
    expiresAt,
    redirect,
    rest
  };
}
for (const c of links.records) {
  check(`checkout record: ${c.name}`, () => expect(readLinkRecord(c.value), c.expected));
}

/**
 * §30 "Reading a record", `bitcoinNode`: the node the page reads (version 2 only), or null for
 * mempool.space; any other value is set aside, and the record stays valid.
 */
function recordNode(value) {
  if (value.version !== 2 || !Object.hasOwn(value, "bitcoinNode")) return null;
  const parts = nodeParts(value.bitcoinNode);
  return parts !== null && isInternetNode(parts.url) ? parts : null;
}
for (const c of bitcoinNodes.records) {
  check(`record's node read: ${c.name}`, () => {
    const shown = readLinkRecord(c.value);
    if (typeof shown !== "object") throw new Error(`the record is ${shown}`);
    expect(recordNode(c.value), c.expected);
  });
}

const REST_SALT = CHECKOUT_SALT;
/** "Rest records": the keys of the invoice of an order's `ref` with the address `A` and end `E`. */
function restKeysOf(integrationKey, ref, address, expiresAt) {
  const key = derive(
    integrationKey,
    INTEGRATION_SALT,
    `checkout-rest/${ref}/${address}/${expiresAt}/key/v1`
  );
  const secret = derive(
    integrationKey,
    INTEGRATION_SALT,
    `checkout-rest/${ref}/${address}/${expiresAt}/nostr-secret-key/v1`
  );
  return {
    restKey: bytesToHex(key),
    restSecret: bytesToHex(secret),
    restAuthor: bytesToHex(schnorr.getPublicKey(secret)),
    restEncryptionKey: bytesToHex(derive(key, REST_SALT, "rest/encryption-key/v1"))
  };
}
const restRecordAt = (restKey, paymentHash) =>
  bytesToHex(derive(hexToBytes(restKey), REST_SALT, `rest/address/${paymentHash}/v1`));
/** "Acceptance records": the address of the acceptance record of the invoice of `restKey`. */
const acceptanceAt = (restKey) =>
  bytesToHex(derive(hexToBytes(restKey), REST_SALT, "rest/accepted/v1"));

/** "Reading an acceptance record", as the page: `{received}`, "newer", or null. */
function readAcceptance(event, { restKey, restAuthor }, link) {
  try {
    checkEvent(event);
  } catch {
    return null;
  }
  if (event.kind !== 30078 || event.pubkey !== restAuthor) return null;
  const d = event.tags.find(([name]) => name === "d")?.[1];
  if (d !== acceptanceAt(restKey)) return null;
  // §12 step 2: a content of a newer NIP-44 version, its event checked out (above).
  const record = openContent(
    event,
    derive(hexToBytes(restKey), REST_SALT, "rest/encryption-key/v1")
  );
  if (record === null || record === "newer") return record;
  if (record.t !== "checkout-accepted" || record.v === null || typeof record.v !== "object") {
    return null;
  }
  const v = record.v;
  if (typeof v.version === "number" && v.version > 1) return "newer";
  if (v.version !== 1 || !Number.isSafeInteger(v.received) || v.received < 1) return null;
  return BigInt(v.received) < BigInt(link.sats) ? { received: String(v.received) } : null;
}

/** "Reading a rest record", as the page: what it shows, "newer", or null. */
function readRest(event, { restKey, restAuthor }, link) {
  try {
    checkEvent(event);
  } catch {
    return null;
  }
  if (event.kind !== 30078 || event.pubkey !== restAuthor) return null;
  const d = event.tags.find(([name]) => name === "d")?.[1];
  // §12 step 1: a `d` tag, whatever the format; the link's acceptance record (same author) is no
  // rest record, of a newer format or not.
  if (typeof d !== "string" || d === acceptanceAt(restKey)) return null;
  // §12 step 2: a content of a newer NIP-44 version, its event checked out (above).
  const record = openContent(
    event,
    derive(hexToBytes(restKey), REST_SALT, "rest/encryption-key/v1")
  );
  if (record === null || record === "newer") return record;
  if (record.t !== "checkout-rest" || record.v === null || typeof record.v !== "object")
    return null;
  const v = record.v;
  if (typeof v.version === "number" && v.version > 1) return "newer";
  // §15: `verifyUrl` an https URL.
  if (v.version !== 1 || httpsUrl(v.verifyUrl) === null) return null;
  const invoice = satsInvoiceOf(v.invoice);
  if (!invoice) return null;
  const sats = invoice.msat / 1000n;
  if (
    sats >= BigInt(link.sats) ||
    invoice.timestamp < link.createdAt - 300 ||
    invoice.timestamp + invoice.expiry > link.expiresAt + 300
  ) {
    return null;
  }
  if (d !== restRecordAt(restKey, invoice.paymentHash)) return null;
  return {
    invoice: v.invoice,
    paymentHash: invoice.paymentHash,
    verifyUrl: v.verifyUrl,
    sats: sats.toString()
  };
}

const rests = read("vectors/onchain-rests.json");
const restIntegrationKey = hexToBytes(rests.integrationKey);
for (const c of rests.keys) {
  check(`rest keys of ${c.ref}, ${c.address.slice(0, 12)}, ${c.expiresAt}`, () => {
    const keys = restKeysOf(restIntegrationKey, c.ref, c.address, c.expiresAt);
    expect(keys, {
      restKey: c.restKey,
      restSecret: c.restSecret,
      restAuthor: c.restAuthor,
      restEncryptionKey: c.restEncryptionKey
    });
    for (const record of c.records) {
      expect(restRecordAt(c.restKey, record.paymentHash), record.address);
    }
    expect(acceptanceAt(c.restKey), c.acceptanceAddress);
  });
}
check("rest records: the keys of the first order", () =>
  expect(
    [rests.records.restKey, rests.records.restAuthor, rests.records.link.expiresAt],
    [rests.keys[0].restKey, rests.keys[0].restAuthor, rests.keys[0].expiresAt]
  )
);
for (const c of rests.records.cases) {
  check(`rest record: ${c.name}`, () =>
    expect(readRest(c.event, rests.records, rests.records.link), c.expected)
  );
}
check("acceptance records: the keys of the first order", () =>
  expect(
    [rests.acceptances.restKey, rests.acceptances.restAuthor],
    [rests.keys[0].restKey, rests.keys[0].restAuthor]
  )
);
for (const c of rests.acceptances.cases) {
  check(`acceptance record: ${c.name}`, () =>
    expect(readAcceptance(c.event, rests.acceptances, rests.acceptances.link), c.expected)
  );
}

/** §20, a declaration of the sale `s` opened as the sale: its invoice, note and `rest`, or null. */
function readSaleDeclaration(event, registry, s) {
  try {
    checkEvent(event);
  } catch {
    return null;
  }
  const d = event.tags.find(([name]) => name === "d")?.[1];
  if (event.kind !== 30078 || event.pubkey !== s.author || typeof d !== "string") return null;
  let inside;
  try {
    const outer = derive(registry.key, REGISTRY_DECLARATION_SALT, `outer/v1/${d}/${s.author}`);
    const record = JSON.parse(decrypt(event.content, outer));
    if (record.t !== "registry-declaration") return null;
    inside = JSON.parse(decrypt(record.v.sealed, s.inner));
  } catch {
    return null;
  }
  if (inside === null || typeof inside !== "object") return null;
  // An amount above 0 and a whole number of sats; `verifyUrl` an https URL (§15).
  const invoice = satsInvoiceOf(inside.invoice);
  if (inside.version !== 1 || !invoice || httpsUrl(inside.verifyUrl) === null) return null;
  if (inside.sale?.key !== s.key || typeof inside.sale.note !== "string") return null;
  // `rest`: absent, or the invoice it is the rest of (its address and end), more fields ignored.
  let rest = null;
  if (inside.rest !== undefined) {
    const of = inside.rest;
    if (of === null || typeof of !== "object" || Array.isArray(of)) return null;
    if (!isDepositAddress(of.address)) return null;
    if (!Number.isSafeInteger(of.expiresAt) || of.expiresAt < 0) return null;
    rest = { address: of.address, expiresAt: of.expiresAt };
  }
  if (d !== bytesToHex(hmac(sha256, registry.key, hexToBytes(invoice.paymentHash)))) return null;
  return { invoice: inside.invoice, note: inside.sale.note, rest };
}
{
  const registry = {
    key: hexToBytes(rests.declarations.registryKey),
    reader: rests.declarations.registryReader
  };
  const s = sale(restIntegrationKey, registry, rests.declarations.ref);
  for (const c of rests.declarations.cases) {
    check(`rest declaration: ${c.name}`, () =>
      expect(readSaleDeclaration(c.event, registry, s), c.expected)
    );
  }
}

for (const c of rests.asking) {
  check(`asking for a rest invoice: ${c.name}`, () => {
    const received = BigInt(c.received);
    const sats = BigInt(c.sats);
    let rest = null;
    if (received > 0n && received < sats && c.now < c.expiresAt) {
      const left = sats - received;
      // By date, then payment hash (hex, lowercase: as bytes).
      const latest = [...c.rests]
        .sort(
          (a, b) =>
            a.createdAt - b.createdAt ||
            (a.paymentHash < b.paymentHash ? -1 : a.paymentHash > b.paymentHash ? 1 : 0)
        )
        .filter((r) => BigInt(r.sats) === left && !r.paid && c.now < r.expiresAt)
        .at(-1);
      rest = { sats: left.toString(), invoice: latest?.id ?? null };
    }
    const asks =
      rest !== null &&
      rest.invoice === null &&
      c.now + 60 <= c.expiresAt &&
      c.lease !== null &&
      c.lease.sats === c.sats &&
      c.lease.expiresAt === c.expiresAt &&
      BigInt(rest.sats) >= BigInt(c.sendable.min) &&
      BigInt(rest.sats) <= BigInt(c.sendable.max);
    expect(
      { rest, ask: asks ? { sats: rest.sats, expirySeconds: c.expiresAt - c.now } : null },
      c.expected
    );
  });
}

check("implementation: the rest of an underpayment the web app reads", () => {
  const v = read("vectors/app/checkout-rest.json");
  const keys = restKeysOf(hexToBytes(v.integrationKey), v.order.ref, v.onchainAddress, v.expiresAt);
  expect([v.rest.restKey, v.rest.restAuthor], [keys.restKey, keys.restAuthor]);
  expect(v.rest.encryptionKey, keys.restEncryptionKey);
  // The link's record carries the rest author and key.
  expect(checkoutKeys(hexToBytes(v.link.linkKey)), {
    address: v.link.address,
    encryptionKey: v.link.encryptionKey
  });
  checkEvent(v.link.event);
  expect(
    [v.link.event.kind, v.link.event.pubkey, v.link.event.tags],
    [
      30078,
      v.link.author,
      [
        ["d", v.link.address],
        ["expiration", String(v.expiresAt + 604800)]
      ]
    ]
  );
  const plaintext = decrypt(v.link.event.content, hexToBytes(v.link.encryptionKey));
  if (utf8ToBytes(plaintext).length % 256 !== 0) throw new Error("record padding");
  const record = JSON.parse(plaintext);
  expect(record.t, "checkout");
  const value = record.v;
  expect(value, v.link.value);
  expect([value.version, value.restAuthor, value.restKey], [2, keys.restAuthor, keys.restKey]);
  expect([value.onchainAddress, value.sats], [v.onchainAddress, Number(v.sats)]);
  // The rest record: what the page shows.
  expect(
    readRest(v.rest.event, v.rest, {
      sats: v.sats,
      createdAt: v.createdAt,
      expiresAt: v.expiresAt
    }),
    {
      invoice: v.rest.invoice,
      paymentHash: v.rest.paymentHash,
      verifyUrl: v.rest.verifyUrl,
      sats: v.rest.sats
    }
  );
  expect(v.rest.event.tags, [
    ["d", restRecordAt(v.rest.restKey, v.rest.paymentHash)],
    ["expiration", String(v.expiresAt + 604800)]
  ]);
  // The rest: the amount less what came on-chain, its QR code on-chain and in Lightning.
  const left = BigInt(v.sats) - BigInt(v.transaction.sats);
  expect(v.rest.sats, left.toString());
  expect(v.status, {
    state: "open",
    expiresAt: v.expiresAt,
    received: v.transaction.sats,
    rest: {
      sats: left.toString(),
      bolt11: v.rest.invoice,
      paymentUri: `bitcoin:${v.onchainAddress}?amount=${btcOf(left)}&lightning=${v.rest.invoice}`
    }
  });
});

/**
 * §16 to §18: a pay request `createInvoice` was answered, and invoices made for it: their
 * description hash is its metadata's, their verify URL on its callback's host, their amount
 * within its sendable sats.
 */
function checkPayRequest(payRequest, invoices) {
  expect(payRequest.tag, "payRequest");
  const callback = httpsUrl(payRequest.callback);
  if (!callback) throw new Error("callback: not an https URL");
  const descriptionHash = bytesToHex(sha256(utf8ToBytes(payRequest.metadata)));
  const min = (BigInt(payRequest.minSendable) + 999n) / 1000n;
  const max = BigInt(payRequest.maxSendable) / 1000n;
  for (const { invoice, verifyUrl } of invoices) {
    const decoded = satsInvoiceOf(invoice);
    if (!decoded) throw new Error("invoice: not on bc in whole sats");
    expect(decoded.descriptionHash, descriptionHash);
    const verify = httpsUrl(verifyUrl);
    if (!verify || !sameHost(verify, callback)) {
      throw new Error("verify URL: not on the callback's host");
    }
    const sats = decoded.msat / 1000n;
    if (sats < min || sats > max) throw new Error("outside the sendable sats");
  }
}
check("implementation: the checkout link's pay request and price", () => {
  const v = read("vectors/app/checkout-link.json");
  checkPayRequest(v.payRequest, [{ invoice: v.invoice, verifyUrl: v.verifyUrl }]);
  const sats = satsAt(v.order.fiat, v.price);
  expect(sats.toString(), v.sats);
  expect(bolt11Of(v.invoice).msat, sats * 1000n);
});
check("implementation: the pay request of the rest's link and of its rest", () => {
  const v = read("vectors/app/checkout-rest.json");
  checkPayRequest(v.payRequest, [
    { invoice: v.link.value.invoice, verifyUrl: v.link.value.verifyUrl },
    { invoice: v.rest.invoice, verifyUrl: v.rest.verifyUrl }
  ]);
});

// ---- Stored invoices (SPEC.md §22) ---------------------------------------------------------------

/** §22: whether a payment check takes a stored invoice (else `invalid_order`, `invoice`). */
function storedInvoiceValid(invoice) {
  if (invoice === null || typeof invoice !== "object" || Array.isArray(invoice)) return false;
  // Every member the check reads is there, but onchainAddress (§2: one left out is not null).
  for (const name of ["sats", "expiresAt", "bolt11", "paymentHash", "verifyUrl"]) {
    if (!Object.hasOwn(invoice, name)) return false;
  }
  const { sats, expiresAt, bolt11, paymentHash, verifyUrl } = invoice;
  if (typeof sats !== "string" || !/^[0-9]{1,16}$/.test(sats)) return false;
  const amount = BigInt(sats);
  if (amount < 1n || amount > 2_100_000_000_000_000n || !Number.isSafeInteger(expiresAt)) {
    return false;
  }
  if (bolt11 === null) {
    if (paymentHash !== null || verifyUrl !== null) return false;
  } else {
    const decoded = typeof bolt11 === "string" ? bolt11Of(bolt11) : null;
    if (
      !decoded ||
      decoded.network !== "bc" ||
      decoded.msat !== amount * 1000n ||
      !isHex(paymentHash, 64) ||
      decoded.paymentHash !== paymentHash ||
      decoded.timestamp + decoded.expiry !== expiresAt ||
      httpsUrl(verifyUrl) === null
    ) {
      return false;
    }
  }
  const address = Object.hasOwn(invoice, "onchainAddress") ? invoice.onchainAddress : null;
  if (address !== null && !isDepositAddress(address)) return false;
  if (bolt11 === null && address === null) return false;
  // With an address, its order's reference (§17).
  return (
    address === null ||
    (typeof invoice.ref === "string" && /^[A-Za-z0-9._:-]{1,64}$/.test(invoice.ref))
  );
}
for (const c of read("vectors/payments.json").stored) {
  check(`stored invoice: ${c.name}`, () =>
    expect(
      storedInvoiceValid(c.invoice)
        ? { valid: true }
        : { error: "invalid_order", param: "invoice" },
      c.expected
    )
  );
}

// ---- Nostr event ids (SPEC.md §11) ------------------------------------------------------------

const SHORT_ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r"
};

/** §11: a string of an event as its id serializes it, from the rule's own words. */
function eventString(text) {
  let out = '"';
  for (const c of text) {
    const code = c.codePointAt(0);
    out += SHORT_ESCAPES[c] ?? (code < 0x20 ? `\\u${code.toString(16).padStart(4, "0")}` : c);
  }
  return `${out}"`;
}

/** §11: what an event's id is the SHA-256 of (its UTF-8). */
function eventSerialization({ pubkey, created_at, kind, tags, content }) {
  if (!Number.isSafeInteger(created_at) || !Number.isSafeInteger(kind)) throw new Error("numbers");
  const list = (items) => `[${items.join(",")}]`;
  return list([
    "0",
    eventString(pubkey),
    String(created_at),
    String(kind),
    list(tags.map((tag) => list(tag.map(eventString)))),
    eventString(content)
  ]);
}

for (const c of read("vectors/nostr-events.json").cases) {
  check(`event id: ${c.name}`, () => {
    const serialized = eventSerialization(c.event);
    expect(serialized, c.serialized);
    expect(bytesToHex(sha256(new TextEncoder().encode(serialized))), c.id);
  });
}

// ---- Pay requests (SPEC.md §15, §16) ------------------------------------------------------------

/** §15 and §2: the JSON of an answer's body (one leading byte order mark ignored), or undefined. */
function answerJson(http) {
  if ("body" in http) return http.body;
  const text = http.bodyText.startsWith("﻿") ? http.bodyText.slice(1) : http.bodyText;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

const isJsonObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** §16 "An LNURL answer": a refusal, no answer (`network`), or the answer's object. */
function lnurlAnswer(http) {
  const json = answerJson(http);
  const ok = http.status >= 200 && http.status <= 299;
  const refusable =
    ok || (http.status >= 400 && http.status <= 499 && http.status !== 408 && http.status !== 429);
  if (
    refusable &&
    isJsonObject(json) &&
    typeof json.status === "string" &&
    asciiLower(json.status) === "error"
  ) {
    return { refusal: typeof json.reason === "string" ? json.reason : "" };
  }
  if (!ok || !isJsonObject(json)) return { network: true };
  return { json };
}

/** §16 "The pay request" and "Sendable sats": what it gives, or the error. */
function payRequestOf(http) {
  const answer = lnurlAnswer(http);
  // A refusal of the pay URL is `network` too.
  if (!("json" in answer)) return { error: "network" };
  const { json } = answer;
  const msat = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  if (
    json.tag !== "payRequest" ||
    httpsUrl(json.callback) === null ||
    !msat(json.minSendable) ||
    !msat(json.maxSendable) ||
    json.minSendable > json.maxSendable ||
    typeof json.metadata !== "string" ||
    !json.metadata.isWellFormed()
  ) {
    return { error: "invalid_invoice" };
  }
  const comment = json.commentAllowed;
  return {
    callback: json.callback,
    sendable: {
      min: ((BigInt(json.minSendable) + 999n) / 1000n).toString(),
      max: (BigInt(json.maxSendable) / 1000n).toString()
    },
    commentAllowed: msat(comment) ? comment : 0,
    descriptionHash: bytesToHex(sha256(new TextEncoder().encode(json.metadata)))
  };
}

for (const c of read("vectors/pay-requests.json").cases) {
  check(`pay request: ${c.name}`, () => expect(payRequestOf(c.http), c.expected));
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  console.error(`${failures.length} of ${checks} checks failed.`);
  process.exitCode = 1;
} else {
  console.log(`${checks} checks computed again, all equal to the vectors.`);
}
