// examples/wire-format.mjs — what actually goes on the wire.
//
// The JS wrapper hides the byte layout completely. This example takes one real
// PreKeyWhisperMessage apart so the shape in docs/protocol.md can be checked
// against something you can print.
//
//   node examples/wire-format.mjs

import { randomBytes } from 'node:crypto';
import { PreKeyWhisperMessage, native } from '../index.js';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const hex8 = (b) => `0x${b.toString(16).padStart(2, '0')}`;
const keyPair = () => {
  const privKey = randomBytes(32);
  return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) };
};

// --- keys ------------------------------------------------------------------
const alice = keyPair();
const bob = keyPair();
const spk = keyPair();
const opk = keyPair();

// Bob's signed prekey is signed by Bob's identity key over the 33-byte prefixed
// form, because that is the exact byte string x3dh.rs verifies.
const spkSignature = native.curveSign(bob.privKey, spk.pubKey, null);

const aliceSession = native.x3DhBuildInitialSession(
  alice.privKey, alice.pubKey,
  spk.pubKey, spkSignature,
  opk.pubKey, 7,
  bob.pubKey, spk.pubKey,
  22222, 1,
);

const record = JSON.parse(aliceSession);
const entry = Object.values(record._sessions)[0];
console.log('session record version     %s', record.version);
console.log('entries in record          %d', Object.values(record._sessions).length);
console.log('entry open (closed === -1) %s', entry.indexInfo.closed === -1);
console.log('chains in entry            %d', Object.keys(entry._chains).length);
console.log('pendingPreKey present      %s', entry.pendingPreKey !== undefined);

// --- the first message is a PreKeyWhisperMessage --------------------------
const first = native.ratchetEncrypt(aliceSession, Buffer.from('hello'), alice.pubKey, 22222);
const decoded = PreKeyWhisperMessage.decode(first.ciphertext.subarray(1));

console.log('');
console.log('message type               %d (3 = PreKeyWhisperMessage)', first.messageType);
console.log('outer version byte         %s', hex8(first.ciphertext[0]));
console.log('pkmsg preKeyId             %s', decoded.preKeyId);
console.log('pkmsg signedPreKeyId       %s', decoded.signedPreKeyId);
console.log('pkmsg registrationId       %d', decoded.registrationId);
console.log('pkmsg identityKey          %d bytes, prefix %s', decoded.identityKey.length, hex8(decoded.identityKey[0]));
console.log('pkmsg baseKey              %d bytes, prefix %s', decoded.baseKey.length, hex8(decoded.baseKey[0]));

// --- the inner WhisperMessage: version byte || protobuf || 8-byte MAC -----
const inner = decoded.message;
const whisper = native.protoDecodeWhisper(inner.subarray(1, inner.length - 8));
console.log('');
console.log('inner version byte         %s', hex8(inner[0]));
console.log('inner ephemeral key        %d bytes', whisper.ephemeralKey.length);
console.log('inner counter              %d', whisper.counter);
console.log('inner previousCounter      %d', whisper.previousCounter);
console.log('inner ciphertext           %d bytes', whisper.ciphertext.length);
console.log('inner frame                %d bytes = 1 version + %d protobuf + 8 MAC',
  inner.length, inner.length - 9);

// Every message stays a PreKeyWhisperMessage until the sender receives a
// reply: pendingPreKey is deleted on decrypt, not on encrypt.
const stillWrapped = native.ratchetEncrypt(first.sessionJson, Buffer.from('again'), alice.pubKey, 22222);
console.log('next message still type    %d (pendingPreKey is cleared on decrypt)', stillWrapped.messageType);

// --- the exchange that clears it -----------------------------------------
const aliceBaseKey = Buffer.from(
  JSON.parse(aliceSession)._sessions[Object.keys(JSON.parse(aliceSession)._sessions)[0]]
    .currentRatchet.ephemeralKeyPair.pubKey,
  'base64',
);
const bobSession = native.x3DhBuildRecipientSession(
  bob.privKey, spk.privKey, spk.pubKey.slice(1), opk.privKey,
  alice.pubKey, aliceBaseKey, 22222,
);
const bobGot = native.ratchetDecryptPkmsg(bobSession, first.ciphertext, bob.pubKey);
const bobReply = native.ratchetEncrypt(bobGot.sessionJson, Buffer.from('balasan'), bob.pubKey, 22222);
const aliceGot = native.ratchetDecryptWhisper(first.sessionJson, bobReply.ciphertext, alice.pubKey);
console.log('bob decrypted              %j', Buffer.from(bobGot.plaintext).toString());
console.log('alice decrypted            %j', Buffer.from(aliceGot.plaintext).toString());
console.log('alice pendingPreKey now    %s',
  JSON.parse(aliceGot.sessionJson)._sessions[Object.keys(JSON.parse(aliceGot.sessionJson)._sessions)[0]]
    .pendingPreKey === undefined);

// --- from here on it is a bare WhisperMessage -----------------------------
const third = native.ratchetEncrypt(aliceGot.sessionJson, Buffer.from('dan seterusnya'), alice.pubKey, 22222);
const thirdWhisper = native.protoDecodeWhisper(third.ciphertext.subarray(1, third.ciphertext.length - 8));
console.log('');
console.log('message type               %d (1 = WhisperMessage)', third.messageType);
console.log('outer version byte         %s', hex8(third.ciphertext[0]));
console.log('counter advanced to        %d', thirdWhisper.counter);
console.log('outer frame                %d bytes = 1 version + %d protobuf + 8 MAC',
  third.ciphertext.length, third.ciphertext.length - 9);

// --- a chain map key is the 33-byte wire key, not the 32-byte X25519 one --
const entryAfter = Object.values(JSON.parse(aliceGot.sessionJson)._sessions)[0];
for (const key of Object.keys(entryAfter._chains)) {
  console.log('chain key                  %d bytes, prefix %s', Buffer.from(key, 'base64').length,
    hex8(Buffer.from(key, 'base64')[0]));
}
console.log('chain types                %j (1 = SENDING, 2 = RECEIVING)',
  Object.values(entryAfter._chains).map((c) => c.chainType));
