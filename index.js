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
