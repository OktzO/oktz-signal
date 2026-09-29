<div align="center">

# ⚡ oktz-signal

### Signal Protocol native Rust — MIT replacement for `libsignal` (GPL)

[![Version](https://img.shields.io/badge/npm-0.3.0--rc.1-339933?style=for-the-badge&logo=npm&logoColor=white)](https://www.npmjs.com/package/oktz-signal)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D20.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

**oktz-signal** is a Rust implementation of the Signal Protocol — X3DH, the
Double Ratchet, the session record format and the protobuf codec — exposed
through napi-rs with a thin JS wrapper. It is MIT-licensed, and it is wire
compatible with `libsignal` v6 (`WhiskeySockets/libsignal-node`), which is
GPL-3.0 and therefore not something many projects can ship.

Every claim below is traceable to a line of this repository, a test that
exists, or a command quoted with its output. Where something is *not*
verified, it says so instead of implying otherwise. The
[documentation](./docs) is executable: `npm run docs:verify` runs every code
block on every documentation page, so none of it can quietly go stale.

---

## ⚠️ Status: UNSTABLE / EXPERIMENTAL

- **Never audited by a third party.** There is no formal security review of
  this code. The [audit notes](#known-limitations) below are a line-by-line
  reading plus the tests written from it — not an assessment.
- **Linux only.** There is no macOS and no Windows build. See
  [Platform support](#platform-support).
- **The version on `main` is not what `0.3.0-rc.1` shipped as.** `v0.3.0-rc.1`
  is tagged at `8dfc4d3`, and every commit after it — 57 of them at the time
  of writing, including every security fix in [the
  changelog](./CHANGELOG.md) — is **unreleased**. `package.json` still says
  `0.3.0-rc.1`, so the package on npm today is `8dfc4d3` and contains none of
  that work.
- Wire compatibility with real WhatsApp clients is not guaranteed in every
  edge case. The interop evidence is against `libsignal` v6, which is a
  strong signal but not the same thing.
- The API can change between minor versions.

---

## Install

```bash nonrunnable
npm install oktz-signal
```

The main package ships **no native binary**. It contains the JS wrapper, the
platform loader and `napi.config.json` — 13 files, a 21.7 kB tarball, and zero
`.node` files (`tests/pack-install.test.mjs` asserts the last two on every
`npm test`). The binary arrives through four platform packages installed as
`optionalDependencies`.

### Platform support

| Platform package | Target | Published |
|---|---|---|
| `@oktz-signal/signal-linux-x64-gnu` | `x86_64-unknown-linux-gnu` | yes |
| `@oktz-signal/signal-linux-x64-musl` | `x86_64-unknown-linux-musl` (Alpine) | yes |
| `@oktz-signal/signal-linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | yes |
| `@oktz-signal/signal-linux-arm64-musl` | `aarch64-unknown-linux-musl` | yes |

That is the whole list, and it is the list in `package.json:33-38` and the
publish steps in `.github/workflows/release.yml:121-132`.

- **macOS: not built, not published, not supported.** No `darwin` target
  appears in `napi.config.json` or any workflow.
- **Windows: not built, not published, not supported.** Same.
- **Android / Termux: cross-compiled in CI, deliberately not published.** The
  `aarch64-linux-android` build runs in both workflows and produces an
  artifact, but there is no publish step for it and it is not in
  `optionalDependencies`. `release.yml:109-113` says why: a
  `workflow_dispatch` boolean used to stand in for a Termux run that does not
  exist, so nothing had ever loaded that binary before it would have shipped.
  **On Termux, `npm install` gives you the JS wrapper and no `.node`** — build
  it yourself.

### What has and has not actually been run

Be precise about this, because the difference matters:

| | Status |
|---|---|
| `x86_64-unknown-linux-gnu` binary | **built and loaded.** CI runs the full JS suite against it (`ci.yml:53-56`). |
| musl x64/arm64, glibc arm64 binaries | **built in CI. Never loaded** — no runner executes them, and this repository's tests cannot. |
| Android arm64 binary | **cross-compiled in CI. Never loaded, never published.** |

The four arm64/musl claims above are compile results, not runtime results. The
workload that would prove them needs the corresponding hardware.

### Building for an unsupported platform

```bash nonrunnable
rustup target add aarch64-linux-android
cargo build --manifest-path native/signal/Cargo.toml --release \
  --target aarch64-linux-android
```

You need the Android NDK, and you need to supply the `ANDROID_NDK_HOME` linker
configuration yourself. The musl and arm64 targets need Zig
(`taiki-e/install-action` in CI, or `zig cc`) for the cross link. For
publishing, use `napi build --release --target <target> …` as the workflows do;
plain `cargo build` leaves a `libsignal.so` rather than a named `.node`.

### Verifying the native module loads

```js
// In a checkout. From an installed package the specifier is 'oktz-signal'.
import { native } from './index.js';

console.log('curveSign is', typeof native.curveSign);
console.log('ratchetEncrypt is', typeof native.ratchetEncrypt);
console.log('16 exports:', Object.keys(native).filter((k) => typeof native[k] === 'function').length);
```

This package has no runtime dependencies, so if this fails the problem is the
`.node` — wrong platform, or a platform package whose version does not match
this loader. The loader enforces that version match unconditionally
(`tests/platform-loader.test.mjs:314-334`), so a stale platform package fails
loudly at require time rather than crashing later inside the addon.

---

## Usage

```js nonrunnable
// Sketch only — the runnable version, with a real storage and real keys, is
// docs/quickstart.md and examples/handshake.mjs.
import { ProtocolAddress, SessionBuilder, SessionCipher } from 'oktz-signal';

const addr = new ProtocolAddress('6280000000000.0', 0);

// Outgoing, against a prekey bundle you fetched from a server:
await new SessionBuilder(storage, addr).initOutgoing(bundle);
const { type, body } = await new SessionCipher(storage, addr).encrypt(data);
// type 3 = PreKeyWhisperMessage, type 1 = WhisperMessage

// Incoming — use this one when you do not know whether a session exists yet:
const fromPreKey = await new SessionCipher(storage, addr)
  .decryptPreKeyWhisperMessage(incoming);
// ...or, when you do know it is a plain ratchet message:
const fromRatchet = await new SessionCipher(storage, addr)
  .decryptWhisperMessage(incoming);
```

`storage` is seven async methods and nothing else. `loadSenderKey`,
`storeSenderKey` and `saveIdentity` are never called — this package does not
implement group messaging.

```js nonrunnable
getOurIdentity()              -> { privKey: Buffer(32), pubKey: Buffer(33) }
getOurRegistrationId()        -> number
loadSession(address)          -> SessionRecord | null
storeSession(address, record) -> void
loadPreKey(id)                -> { privKey, pubKey } | null
loadSignedPreKey(id)          -> { privKey, pubKey } | null
removePreKey(id)              -> void   // a throw here is reported, not swallowed
```

A complete in-memory implementation is in
[`docs/storage-stub.mjs`](./docs/storage-stub.mjs), and a full two-peer
handshake is in [`examples/handshake.mjs`](./examples/handshake.mjs) — run it
with `node examples/handshake.mjs`.

- [docs/quickstart.md](./docs/quickstart.md) — a runnable handshake
- [docs/api.md](./docs/api.md) — every export, with its real signature
- [docs/protocol.md](./docs/protocol.md) — what the implementation does, cited
  to `file:line`

---

## What is actually verified

Everything in this section is a test that exists in this repository. The one
cross-implementation check is the oracle, and it is described honestly below.

### Against `libsignal` v6

`tests/oracle/interop.test.mjs` is the only evidence that this speaks the same
protocol as something else. It has three parts:

- **libsignal → oktz-signal, both directions.** `libsignal` owns *both*
  endpoints and writes the receiver's session record itself; oktz-signal is
  dropped in as that receiver. A four-turn conversation crosses DH ratchet
  steps in both engines, with the record handed back and forth.
- **oktz-signal → libsignal.** oktz-signal builds the session and encrypts;
  `libsignal`'s own `SessionCipher` decrypts.
- **Session record.** A record `libsignal` serialised is parsed by
  `sessionDeserialize`.

This matters because the previous version of that test was tautological. It
hand-built the receiver's record in oktz-signal's own shape — its own
`chainType: 0` and its own 32-byte chain keys — so the test named
"libsignal → oktz-signal interop" never once let `libsignal` produce a
receiver record. The real interop was one-directional and broken: oktz-signal
could not decrypt a single message from a session `libsignal` had established
(three record-format mismatches, fixed in `fc0d234`). See
[the changelog](./CHANGELOG.md).

**Running it needs `libsignal`, which is a GPL devDependency.** It is not
shipped — it is not in `files` and no `.node` or dependency reaches the
tarball — but it is installed by `npm ci`, and three test files import it:
`tests/oracle/interop.test.mjs`, `tests/ratchet-libsignal-record.test.mjs` and
`tests/ratchet-prev-counter.test.mjs`. Without it `npm test` is **not green**:
those three files fail to import and the run exits 1 with 3 failures. This was
measured, not assumed.

### Known-answer vectors

External vectors, not self-consistency:

- **X25519**, RFC 7748 §5.2 (`curve.rs:238-254`).
- **XEdDSA**, a `curve25519-js` vector on the `rnd` path (`curve.rs:392-405`).
- **Protobuf wire bytes** for both message types (`proto.rs:423-433`,
  `proto.rs:667-685`).

There are **no** separate known-answer vectors for the shared-secret layout,
the info strings, the message-key schedule or the AES-CBC+MAC construction.
Those are covered only end-to-end, by the oracle and by the round-trip tests.
Anyone reading this should know the difference.

### Cryptographic and protocol behaviour

- **Out-of-order delivery inside one ratchet epoch** — 2500 messages delivered
  in shuffled order, none resent (`tests/ratchet-counter-window.test.mjs`), plus
  a 3 → 2 → 1 reversal in `examples/ratchet-epochs.mjs`.
- **The 2000-message skip bound is a distance, not an absolute counter**, and a
  counter 2001 ahead of the chain is refused before any key is derived
  (`ratchet.rs:41`, `ratchet.rs:205`).
- **Forgery resistance**: a chain emptied by a ratchet step cannot decrypt
  (`tests/forgery.test.mjs`); a bad MAC leaves the record bit-for-bit
  unchanged and does not apply the ratchet step
  (`bad_mac_leaves_the_record_untouched`, `bad_mac_does_not_step_the_ratchet`).
- **Pre-authentication**: a forged `PreKeyWhisperMessage` neither persists a
  session nor burns a one-time prekey, and the victim can still send
  (`tests/session-pkmsg-auth.test.mjs`).
- **Multi-entry records** select the open session, not the first
  (`tests/multi-session.test.mjs`); archived entries are capped at 40
  (`tests/session-archive-cap.test.mjs`).
- **Loader hardening** — 25 assertions over version enforcement, platform
  dispatch, WASI suppression and error surfacing
  (`tests/platform-loader.test.mjs`), plus a guard that refuses to publish a
  regenerated loader (`tests/prepublish-loader-guard.test.mjs`).

### Test counts

Measured on this tree:

```bash nonrunnable
cargo test --locked --manifest-path native/signal/Cargo.toml   # 83 passed, 0 failed
npm test                                                      # 132 passed, 0 failed, 23 files
npm run docs:verify                                           # 25 blocks + 3 examples, 0 failures
```

---

## What is **not** verified

Stated plainly, because a README that only lists strengths is not a README you
can rely on.

**XEdDSA signatures are not byte-identical to libsignal, and cannot be.**
This is not an unfinished task. `libsignal@6.0.0`'s
`curve.calculateSignature(privKey, message)` takes two arguments and hard-codes
`curve25519-js`'s `crypto_sign_direct`, so there is no way to inject a shared
nonce from either side. Since this implementation draws its nonce from
`OsRng` when none is supplied (`curve.rs:128-138`) — which it must, because a
deterministic `SHA512(sk‖m)` nonce lets two chosen-message signatures recover
the identity key via a lattice attack — the two engines pick different nonces
by design. The earlier byte-for-byte comparison passed only because both sides
shared that unsafe nonce.

What replaced it is narrower and still real: public key derivation is
byte-identical, and signatures cross-verify **in both directions across 100
random cases** (`tests/oracle/interop.test.mjs:28`). The deterministic path is
pinned separately by a `curve25519-js` known-answer vector.

**A message held back across a DH ratchet step is rejected.** The step removes
the previous receiving chain from the record rather than blanking its key, so
its keys no longer exist. `libsignal` retires a chain the same way; this is
protocol behaviour, not a shortcut. Demonstrated, not asserted, in
`examples/ratchet-epochs.mjs`.

**No third-party audit.** See [Status](#️-status-unstable--experimental).

**No performance claim.** The previous versions of this README published
benchmarks — "9× faster than libsignal" and so on. There is no benchmark
script in this repository, in `package.json`, or anywhere in its git history,
so none of those numbers can be reproduced or checked. They have been removed
rather than restated. If you need a comparison, measure it yourself.

**No group messaging.** SenderKey is not implemented. This is 1:1 only.

**No `isTrustedIdentity` check.** It is never called, so a peer swapping its
identity key is not detected here. Enforce it in your own storage if you need
trust-on-first-use.

**The arm64 and musl binaries have never been executed.** See
[Platform support](#platform-support).

---

## Known limitations

The previous README carried an audit section whose findings are now mostly
fixed. Each is listed with where it stands, so nothing is left as a stale
alarm and nothing fixed is still presented as a live risk.

### Fixed

| Was | Now |
|---|---|
| The active session entry was the *first* `BTreeMap`/object value, so a multi-entry record could encrypt through an archived session | `current_session_mut` prefers `closed === -1`, then most recent `used` (`session.rs:237-254`) |
| A re-init replaced the open session, losing its backlog | The old session is archived into the same record, capped at 40 entries (`session-cipher.js:149-178`) |
| A one-time prekey was not consumed after `initIncoming` | Consumed after the MAC verifies, and a failing `removePreKey` is reported (`session-cipher.js:125-127`) |
| `loadSignedPreKey()` took no id, so signed-prekey rotation produced a misleading MAC failure | Called with the id the message names, falling back to an argument-less call (`session-builder.js:65-75`) |
| 4–6 JSON string round-trips per message | Decoded results cross as napi objects of `Buffer`s (`lib.rs:57-73`); a `SessionRecord` stores the canonical string verbatim (`session-record.js:12`); the remote identity is read natively from the record (`ratchet.rs:419`) |
| Key material was never scrubbed | `Zeroize`/`ZeroizeOnDrop` on the record types (`session.rs:33-45`) and `Zeroizing` on every derived key (`x3dh.rs:34`, `ratchet.rs:161`) |
| MAC comparison was not constant-time | `verify_truncated_left` (`ratchet.rs:585`) and `timingSafeEqual` (`crypto.js:67`) |
| `block-modes` and `hkdf` were dead dependencies | Removed from `Cargo.toml` |

### Still open

- **`isTrustedIdentity` is never called.** A peer changing its identity key is
  not detected. Implement TOFU enforcement yourself.
- **All 16 `native` exports are synchronous** and run on the calling thread.
  An X3DH is four X25519 operations and blocks the event loop. Moving them to
  napi async tasks is available and unused.
- **One redundant X25519 per session build.** `x3dh.rs:121` and `x3dh.rs:180`
  compute the same scalar multiply. Costs one extra operation; not a
  correctness issue.
- **`napi` is built with `features = ["full"]`.** Overkill for what is used,
  and not cleaned up.
- **`protoEncodePkmsg` is asymmetric with its decoder.** It takes a JSON string
  whose byte fields are arrays of numbers, while `protoDecodePkmsg` returns
  `Buffer`s. A decode/encode round-trip is not a no-op.
- **Out-of-order delivery across a ratchet epoch.** See above.

### `crypto.encrypt` / `crypto.decrypt` are not a security primitive

`src/crypto.js` ships in the package, is exported as `crypto`, and has its own
tests. It is not dead code and is not going away: removing the export would
break consumers using it.

> **`encrypt` and `decrypt` are plain `createCipheriv('aes-256-cbc')` with no
> MAC.** A ciphertext can be modified bitwise without detection, and the
> padding can be changed. This is the classic CBC failure. Do not use them for
> anything that needs integrity — use `SessionCipher`, which verifies an 8-byte
> truncated MAC before it decrypts anything. `calculateMAC`, `hash`,
> `deriveSecrets` and `verifyMAC` have no such problem. `crypto.*` is not used
> by the protocol path at all: X3DH and the ratchet derive everything in Rust.

---

## Not implemented, by design

- **SenderKey / group E2EE.** Multi-device group messaging needs a SenderKey
  implementation the consumer supplies.

---

## License

**MIT** — use, modify and redistribute it, commercially included. This is the
point of the package: `libsignal` is GPL-3.0, which many projects cannot ship.

> **Disclaimer:** "Signal Protocol" is a trademark of the Signal Foundation.
> This project is independent, is not affiliated with Signal, and is a
> reimplementation of a publicly specified protocol.
