// index.js — public API oktz-signal, API parity dengan libsignal
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
export const native = require('./native/signal/index.cjs');

export { SessionCipher } from './src/session-cipher.js';
export { SessionBuilder } from './src/session-builder.js';
export { SessionRecord } from './src/session-record.js';
export { ProtocolAddress } from './src/protocol-address.js';
export * as errors from './src/errors.js';
export * as crypto from './src/crypto.js';

/** Decode PreKeyWhisperMessage wire format — API parity dengan libsignal protobufs */
export const PreKeyWhisperMessage = {
  decode(bytes) {
    const proto = JSON.parse(native.protoDecodePkmsg(Buffer.from(bytes)));
    return {
      identityKey: proto.identity_key ? Uint8Array.from(proto.identity_key) : undefined,
      baseKey: proto.base_key ? Uint8Array.from(proto.base_key) : undefined,
      message: proto.message ? Uint8Array.from(proto.message) : undefined,
      registrationId: proto.registration_id,
      preKeyId: proto.pre_key_id ?? undefined,
      signedPreKeyId: proto.signed_pre_key_id ?? undefined,
    };
  },
};
