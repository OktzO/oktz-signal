// examples/ratchet-epochs.mjs — what survives reordering, and what does not.
//
// Two things get conflated when people say "the ratchet handles out-of-order
// delivery". One is true and one is not, so this example demonstrates both
// against the real implementation rather than describing them.
//
//   Within one ratchet epoch: any order works. The receiver keeps the message
//   keys it derives while stepping the chain forward, so a message that turns
//   up late still has its key. The bound is how far AHEAD of the chain it is
//   allowed to be — 2000, the same bound libsignal uses.
//
//   Across a DH ratchet step: a message from the previous epoch is gone. A step
//   retires the previous receiving chain and removes it from the record, so
//   its keys are not merely unused, they no longer exist. This is libsignal's
//   own design, not an oktz-signal shortcut.
//
//   node examples/ratchet-epochs.mjs

import { randomBytes } from 'node:crypto';
import { native } from '../index.js';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const keyPair = () => {
  const privKey = randomBytes(32);
  return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) };
};
const baseKeyOf = (sessionJson) => Buffer.from(
  Object.values(JSON.parse(sessionJson)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey,
  'base64',
);

// A fresh X3DH pair: the initiator's session, the recipient's, both identities.
function pair() {
  const alice = keyPair();
  const bob = keyPair();
  const spk = keyPair();
  const opk = keyPair();
  const aliceSession = native.x3DhBuildInitialSession(
    alice.privKey, alice.pubKey,
    spk.pubKey, native.curveSign(bob.privKey, spk.pubKey, null),
    opk.pubKey, 7,
    bob.pubKey, spk.pubKey,
    22222, 1,
  );
  const bobSession = native.x3DhBuildRecipientSession(
    bob.privKey, spk.privKey, spk.pubKey.slice(1), opk.privKey,
    alice.pubKey, baseKeyOf(aliceSession), 22222,
  );
  return { alice: aliceSession, bob: bobSession, aliceId: alice.pubKey, bobId: bob.pubKey };
}

const send = (sessionJson, text, id) => {
  const out = native.ratchetEncrypt(sessionJson, Buffer.from(text), id, 22222);
  return { sessionJson: out.sessionJson, wire: Buffer.from(out.ciphertext), type: out.messageType };
};

// A message is a PreKeyWhisperMessage (3) while the sender still carries
// pendingPreKey, and a bare WhisperMessage (1) once a reply has cleared it.
const receive = (sessionJson, message, id) => {
  const out = message.type === 3
    ? native.ratchetDecryptPkmsg(sessionJson, message.wire, id)
    : native.ratchetDecryptWhisper(sessionJson, message.wire, id);
  return { sessionJson: out.sessionJson, text: Buffer.from(out.plaintext).toString() };
};

// --- 1. reversed order inside one epoch -----------------------------------
{
  const p = pair();
  const sent = [];
  let sender = p.alice;
  for (let i = 1; i <= 3; i += 1) {
    const m = send(sender, `pesan ${i}`, p.aliceId);
    sender = m.sessionJson;
    sent.push(m);
  }
  console.log('sent 1, 2, 3 in one ratchet epoch (all type %d)', sent[0].type);

  let receiver = p.bob;
  for (const index of [2, 1, 0]) {
    const got = receive(receiver, sent[index], p.bobId);
    receiver = got.sessionJson;
    console.log('  delivered #%d first -> %j', index + 1, got.text);
  }
}

// --- 2. a whole shuffled batch, still inside one epoch --------------------
{
  const p = pair();
  const total = 500;
  const sent = [];
  let sender = p.alice;
  for (let i = 1; i <= total; i += 1) {
    const m = send(sender, `m${i}`, p.aliceId);
    sender = m.sessionJson;
    sent.push(m);
  }

  // The opening PreKeyWhisperMessage has to arrive first: it is the only one
  // carrying the prekey ids the recipient needs to build a session at all.
  // Everything after it is plain reordering, and the keys for it exist.
  let receiver = receive(p.bob, sent[0], p.bobId).sessionJson;
  const rest = sent.slice(1).sort(() => Math.random() - 0.5);
  for (const m of rest) receiver = receive(receiver, m, p.bobId).sessionJson;
  console.log('');
  console.log('%d messages sent in one epoch, %d delivered in random order', total, rest.length);
  console.log('  every one decrypted, none needed a resend');
}

// --- 3. a message from the previous ratchet epoch -------------------------
{
  const p = pair();
  let alice = p.alice;
  let bob = p.bob;

  // Epoch 1 opens and the network holds the SECOND message back.
  const opening = send(alice, 'pembuka', p.aliceId);
  alice = opening.sessionJson;
  const held = send(alice, 'tertunda dari epoch 1', p.aliceId);
  alice = held.sessionJson;

  // Bob takes the opening message, which ratchets his receiving side, and
  // answers. Alice's decrypt of the answer ratchets her sending side, so her
  // next message uses a new ratchet key: that is epoch 2.
  const bobGot = receive(bob, opening, p.bobId);
  bob = bobGot.sessionJson;
  const reply = send(bob, 'balasan', p.bobId);
  bob = reply.sessionJson;
  alice = receive(alice, reply, p.aliceId).sessionJson;

  // Bob accepts the epoch-2 message. Doing so retires the receiving chain that
  // `held` belongs to.
  const epoch2 = send(alice, 'dari epoch 2', p.aliceId);
  bob = receive(bob, epoch2, p.bobId).sessionJson;

  console.log('');
  console.log('a message from the previous ratchet epoch:');
  try {
    receive(bob, held, p.bobId);
    console.log('  decrypted (unexpected)');
  } catch (error) {
    console.log('  rejected: %s', error.message);
  }
  console.log('  the retired chain is removed from the record, so its keys are gone,');
  console.log('  not merely unused. libsignal retires a chain the same way, so a');
  console.log('  peer that wants old messages kept must resend them before replying.');
}
