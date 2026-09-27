import crypto from 'node:crypto';
import { createRequire } from 'module';
import { test } from 'node:test';
import assert from 'node:assert/strict';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');

const H = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const un64 = s => Buffer.from(s, 'base64');

function deriveN(input, salt, info, cnt) {
  const prk = H(salt, input);
  const out = [];
  let prev = Buffer.alloc(0);
  for (let i = 0; i < cnt; i++) {
    const chunk = H(prk, Buffer.concat([prev, Buffer.from(info), Buffer.from([i + 1])]));
    out.push(chunk);
    prev = chunk;
  }
  return out;
}

function realSession() {
  const alice = n.curveGenerateKeypair(crypto.randomBytes(32));
  const bob = n.curveGenerateKeypair(crypto.randomBytes(32));
  const bobSpk = n.curveGenerateKeypair(crypto.randomBytes(32));
  const idA = P5(alice[0]);
  const idB = P5(bob[0]);
  const spk33 = P5(bobSpk[0]);
  const json = n.x3DhBuildInitialSession(
    alice[1], idA, spk33, n.curveSign(bob[1], spk33, null), null, null, idB, spk33, 42, 1);
  return { rec: JSON.parse(json), idB };
}

test('a receiving chain emptied by a ratchet step cannot decrypt', () => {
  const { rec, idB } = realSession();
  const sess = rec._sessions[Object.keys(rec._sessions)[0]];

  // A DH ratchet step blanks a retired receiving chain's key. libsignal then
  // REMOVES the chain from the map. If the entry survives, fill_message_keys
  // derives every message key from a ZERO-LENGTH chain key, and HMAC with an
  // empty key is public knowledge — so a forgery passes the real MAC.
  const chainId = sess.currentRatchet.ephemeralKeyPair.pubKey;
  sess._chains[chainId] = { chainKey: { counter: 0, key: '' }, chainType: 0, messageKeys: {} };
  sess.pendingPreKey = null;

  const COUNTER = 3;
  let ck = Buffer.alloc(0);
  let messageKey;
  for (let i = 0; i < COUNTER; i++) {
    messageKey = H(ck, Buffer.from([0x01]));
    ck = H(ck, Buffer.from([0x02]));
  }
  const keys = deriveN(messageKey, Buffer.alloc(32), 'WhisperMessageKeys', 3);
  const cipher = crypto.createCipheriv('aes-256-cbc', keys[0], keys[2].subarray(0, 16));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from('FORGED BY ATTACKER')), cipher.final()]);
  const msgBuf = n.protoEncodeWhisper(un64(chainId), COUNTER, 0, ciphertext);
  const macInput = Buffer.concat([
    un64(sess.indexInfo.remoteIdentityKey), idB, Buffer.from([0x33]), msgBuf,
  ]);
  const mac = H(keys[1], macInput).subarray(0, 8);
  const wire = Buffer.concat([Buffer.from([0x33]), msgBuf, mac]);

  assert.throws(
    () => n.ratchetDecryptWhisper(JSON.stringify(rec), wire, idB),
    /closed/i,
    'decrypting on a closed receiving chain must fail'
  );
});
