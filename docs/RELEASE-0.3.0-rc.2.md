# oktz-signal 0.3.0-rc.2

Signal protocol (X3DH + Double Ratchet) as a Rust native module for Node, MIT licensed, a drop-in replacement for the GPL `libsignal`. A thin JS wrapper sits on top of the napi binding.

```bash nonrunnable
npm install oktz-signal
```

> **Platform coverage is `linux-x64-gnu` only in this release.** The four
> `@oktz-signal/signal-*` platform packages referenced by earlier drafts have
> never existed on the registry, and the scope could not be created, so the
> binding is bundled in the tarball instead. `arm64` and `musl` need CI builds.
> See [Known limitations](#known-limitations).

---

## Security

Four defects were severe enough that an attacker who could talk to the library
could forge or destroy sessions. All four are fixed here, and each has a
regression test that was observed failing first.

### A closed receiving chain could be used to forge messages — FIXED

`ratchet.rs` retired a receiving chain by blanking its key but left the entry
in the chain map. `fill_message_keys` then derived every message key from a
**zero-length** key. HMAC with an empty key is public knowledge, so an
attacker who had observed a session could derive the AES key, the MAC key and
the IV, and produce a ciphertext that passed the real 8-byte MAC check.

The MAC input is `remoteIdentityKey || ourIdentityKey || 0x33 || message`, all
of it public. The forged message decrypted correctly.

```text nonrunnable
before:  DECRYPT SUCCEEDED — attacker plaintext = "FORGED BY ATTACKER"
after:   forgery REJECTED: receiving chain is closed
```

libsignal *removes* the retired chain. This now does too, and
`fill_message_keys` additionally refuses an empty chain key.

### Session state was committed before the ciphertext was authenticated — FIXED

`session-cipher.js` built a session from attacker-supplied `identityKey` and
`baseKey`, persisted it, and consumed a one-time prekey — all before
`ratchetDecryptPkmsg` checked the MAC.

One garbage, unauthenticated, **remote** type-3 message permanently destroyed
the session, substituted an attacker-chosen identity as the record's open
session, and burned a one-time prekey. There was no self-heal. The reproduction
burned prekeys 101, 102 and 103 and left the victim unable to send.

The flow is now: build the candidate in memory, decrypt, and only on success
persist the session and consume the prekey.

### Record format did not match libsignal, so interop was one-directional — FIXED

The package's headline claim is libsignal compatibility, and the interop was
one-directional: **oktz-signal could not decrypt a single message from a
session real libsignal established.** Three mismatches:

| | libsignal 6 | was | now |
|---|---|---|---|
| `ChainType.RECEIVING` | `2` | `0` | `2` |
| chain-map key | 33 bytes (wire key) | 32 bytes | reads both |
| retired chain | key deleted, field omitted | `key` was required | `#[serde(default)]` |

A real libsignal receiver record failed with `MAC verification failed` — which
looks exactly like an ordinary wrong-session error, so it would have sent an
operator debugging the wrong thing indefinitely.

**The test named "libsignal → oktz-signal interop" could not see this**: it
hand-built the receiver record in oktz-signal's own format, including
`chainType: 0`. It was tautological in precisely the direction that mattered.
It now drives a real `libsignal.SessionBuilder` and `libsignal.SessionCipher`
conversation and lets libsignal build the record.

### All 39 Rust unit tests were executed by nothing — FIXED

There was no `cargo test` in either workflow, and no `test:rust` script. The
39 tests, including `x3dh::tests::test_invalid_signature_rejected` — the only
negative crypto test in the project — ran only if a human happened to type the
command. Deleting signature verification from `x3dh.rs:86` left 100% of the
automated suite green.

`ci.yml` now runs `cargo test --locked` on all five targets, ungated, and
`release.yml` gates `publish` on a job that actually runs the tests. The
previous release pipeline built, packed and published with no test, no install
and no import.

## Hardening

- **XEdDSA verification was cofactorless.** Now uses `verify_strict`, which
  rejects small-order public keys and `R`. Across the low-order X25519 values
  the old path accepted **3,136 forgeries**; the new path accepts **0**.
- **The XEdDSA nonce was derived prefix-less** when `rnd` was absent, which is
  the exact condition RFC 8032's prefix exists to prevent. It is now randomised.
  The explicit `rnd` argument is kept so the libsignal oracle can still pin it.
- **PKCS#7 unpadding validated only the last byte**, non-constant-time, with
  distinguishable error strings. Now constant-time with one error.
- **Chain counters used unchecked `i64` arithmetic** — a debug build panicked,
  a release build wrapped. Now checked.
- **Secret material was never zeroized.** Chain keys, private keys, skipped
  message keys and derived AES/MAC keys are now scrubbed on drop.
- **`MAX_UNAUTHENTICATED_COUNTER` was an absolute cap, not a skip-distance
  cap**, so a session sending more than 2000 messages in one ratchet epoch lost
  the tail — and the sender had no matching cap, so it kept producing messages
  the receiver could not read. Now bounded on skip distance.
- **`previous_counter` (our sending counter) was compared against the
  receiving chain**, rejecting legitimate messages whenever the receiving chain
  lagged. libsignal has no such check.
- **The protobuf decoder accepted structurally invalid messages.** A 62-byte
  unauthenticated pkmsg with attacker-chosen `base_key` and `identity_key`
  decoded successfully. It now requires the fields it needs, asserts the wire
  type of fields it knows, and rejects out-of-range varints. 120,206 hostile
  inputs were run through it: 1 decoded, 120,205 rejected, no panic, no hang.
- **`session_deserialize` was a byte-identical duplicate of
  `session_serialize`** — it did not parse, it lossily re-serialised, and
  silently deleted every field it did not model. Unknown state is now rejected
  rather than eaten.
- **Every exported function lacked `#[napi(catch_unwind)]`**, so a panic would
  abort the Node process instead of throwing. All 16 exports carry it now.
- **X3DH parameters were accepted that contradicted their own keys.** An
  `identity_pub` inconsistent with `identity_priv` was accepted; so was a
  `signed_prekey_pub` inconsistent with its private half.
- **`generate_keypair` accepted an all-zero seed**, yielding a publicly known
  private key.
- **The shared `(storage, addr)` queue could deadlock permanently** on a
  re-entrant storage callback.
- The archived-session list is now capped at 40, matching libsignal's
  `ARCHIVED_STATES_MAX_LENGTH`.
- The second publication argument to `curveSign` no longer has to be supplied
  for the nonce to be safe.
- `deriveSecrets` implements N chunks instead of silently returning 3 for any
  request above 3.

## The native loader

`native/signal/index.cjs` is generated by napi and then **hand-patched** — the
generator emits none of the hardening below, so regenerating it silently
reverted all of it and reported success.

- A bad `NAPI_RS_NATIVE_LIBRARY_PATH` no longer disables every platform
  fallback and discards its own error.
- Absent WASI candidates no longer bury the real load error behind
  `MODULE_NOT_FOUND`, and the misleading `npm has a bug related to optional
  dependencies` advice is now gated.
- `process.report.excludeNetwork` is scoped and restored. It was a permanent
  process-global mutation performed by a library `require`.
- The `ldd --version` libc probe no longer writes to the host process's stderr.
- The binding version check is unconditional and propagates
  `ERR_NAPI_BINDING_VERSION_MISMATCH` instead of loading a stale binding
  silently.

`prepublishOnly` now runs a guard that fails the publish if the committed
loader has lost any of its hand-maintained regions, and a real
`npm publish --dry-run` was verified to leave the file byte-identical.

**The binding version is read from `package.json`** rather than hardcoded in six
places, so a release bump cannot leave a stale string behind.

## Testing

| Suite | Before | Now |
|---|---|---|
| `cargo test --locked` | 83 (run by nothing) | 83, in CI on all 5 targets |
| `npm test` | 16 pass / **1 fail** on Node 22 | **132 / 132** |
| `npm test` on Node 22 | `Cannot find module '.../tests'` | works |
| libsignal oracle | never ran | 4/4, bidirectional |

`npm test` was broken on Node 22: `node --test tests/` treats a positional
directory as a glob. The script is now bare `node --test`, which works on
Node 20 and 22, and there is a regression test asserting no workflow
reintroduces a positional glob.

## Documentation

`README.md` was rewritten from the source. It previously claimed to be
**"bit-exact vs libsignal"** with tables of "9× faster", which were never
backed by a reproduction script; those are withdrawn. Bit-exactness is not
achievable: `libsignal@6.0.0`'s `calculateSignature` takes two arguments and
hard-codes `crypto_sign_direct`, so a shared nonce cannot be injected on either
side.

`docs/quickstart.md`, `docs/api.md` and `docs/protocol.md` cite `file:line` for
every claim, and `npm run docs:verify` **executes all 25 code blocks and 3
examples** in CI so the documentation cannot rot.

## Known limitations

- **`linux-x64-gnu` only.** The `@oktz-signal/signal-*` platform packages do
  not exist on the registry — the scope is not registered and the publish
  token cannot create scopes. `arm64` and `musl` need a token that can create
  the scope, or an unscoped rename, plus CI builds.
- **This package is unaudited.** No third-party cryptographic review has been
  performed. The tests and the adversarial audit behind this release are not a
  substitute.
- `prepublishOnly` fails the publish if `@napi-rs/cli` changes its output. That
  is deliberate — it names the region and the expected count — but it will
  need the patch re-derived after a generator upgrade.
- `src/crypto.js` still exports **unauthenticated** AES-256-CBC `encrypt` /
  `decrypt` alongside the MAC helpers. Not a substitute for a security
  primitive.
