<div align="center">

# ⚡ oktz-signal

### Signal Protocol native Rust — MIT replacement for `libsignal` (GPL)

[![Version](https://img.shields.io/badge/npm-0.1.7-339933?style=for-the-badge&logo=npm&logoColor=white)](https://www.npmjs.com/package/oktz-signal)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D20.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![Rust](https://img.shields.io/badge/Rust-native%20napi--rs-red?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

**oktz-signal** adalah implementasi ulang (clean-room) dari Signal Protocol (X3DH + Double Ratchet + session record + protobuf codec) untuk WhatsApp Multi-Device, ditulis dalam **Rust** via **napi-rs** dan dibungkus JS. Dibuat sebagai pengganti `libsignal` (GPL-3.0) yang **license-safe** (MIT).

Wire format dan kriptografi diverifikasi bit-exact terhadap oracle `libsignal` v6 (WhiskeySockets/libsignal-node) lewat test interop dua arah.

---

## ⚠️ Status: UNSTABLE / EXPERIMENTAL

> **Proyek ini masih dalam tahap produksi awal (alpha).** Dipakai di `oktz-baileys` dan bot `ourin-md` untuk menggantikan `libsignal`, namun:

- **Wire compatibility** terhadap klien WhatsApp resmi **belum 100% terjamin** di semua edge case (perangkat lama, iOS versi lawas, re-sync session, backlog message).
- Bug interop ditemukan & diperbaiki terus (lihat [Changelog](#-changelog)) — **upgrade minor disarankan**.
- **Belum diaudit keamanan pihak ketiga.** Jangan pakai untuk skenario yang butuh jaminan audit formal.
- API masih bisa berubah antar minor version.

---

## Fitur

- **X3DH** — build session initiator & recipient (identity key, signed prekey, one-time prekey).
- **Double Ratchet** — message keys, chain stepping, skipped-message keys, DH ratchet, MAC.
- **SessionRecord** — serialize/deserialize format `libsignal` v6 (`_sessions`, `_chains`).
- **Protobuf codec** — `WhisperMessage` & `PreKeyWhisperMessage` wire format, hand-written.
- **Curve** — X25519 DH, XEdDSA sign/verify, generate keypair (Rust, `curve25519-dalek`).
- **JS wrapper** — `SessionCipher`, `SessionBuilder`, `SessionRecord`, `ProtocolAddress`, `QueueJob`.

## Instalasi

```bash
npm install oktz-signal
```

Native binary disertakan untuk **`linux-x64-gnu`** (`signal.linux-x64-gnu.node`). Build dari source untuk platform lain:

```bash
npm run build:native   # butuh Rust + gcc (nix-shell -p gcc)
```

## Penggunaan

```js
import { SessionCipher, SessionBuilder, SessionRecord, ProtocolAddress } from 'oktz-signal';

const addr = new ProtocolAddress('628xxxxxxx.0', 0);
const cipher = new SessionCipher(storage, addr);

// Decrypt incoming
const plaintext = await cipher.decryptPreKeyWhisperMessage(ciphertext);
// atau
const plaintext = await cipher.decryptWhisperMessage(ciphertext);

// Encrypt outgoing
const { type, body } = await cipher.encrypt(data); // type: 1 = msg, 3 = pkmsg
```

`storage` harus mengimplementasikan antarmuka yang sama dengan libsignal (`loadSession`, `storeSession`, `getOurIdentity`, `getOurRegistrationId`, `loadPreKey`, `loadSignedPreKey`, `loadSenderKey`, `storeSenderKey`).

## Testing

```bash
npm test                                   # unit + wrapper
node --test tests/oracle/interop.test.mjs  # oracle vs libsignal (butuh libsignal terinstall)
```

## Changelog

| Versi | Isi |
|-------|-----|
| **0.1.7** | Wire ephemeral key → **33-byte** (`0x05` prefix, format libsignal). `decryptPreKeyWhisperMessage` reuse session by baseKey (jangan selalu rebuild) — fix "Menunggu pesan ini" |
| 0.1.6 | `decryptPreKeyWhisperMessage` selalu rebuild session dari pkmsg |
| 0.1.5 | Signed prekey 33-byte utk verifikasi signature; prekey_pub strip internal utk DH |
| 0.1.3 | Strip `0x05` prefix dari ephemeral key saat decrypt |
| 0.1.2 | `SessionRecord` terima input object (libsignal serialize return object) |
| 0.1.0 | Rilis pertama — full rewrite Rust + oracle test |

## Lisensi

**MIT** — bebas dipakai, dimodifikasi, dan disebarluaskan, termasuk untuk komersial. Tidak seperti `libsignal` (GPL-3.0) yang membatasi distribusi.

> ⚠️ **Disclaimer:** "Signal Protocol" adalah trademark dari Signal Foundation. Proyek ini independen, tidak berafiliasi dengan Signal, dan hanya implementasi ulang dari spesifikasi protokol yang sudah publik.
