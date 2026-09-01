import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { deepStrictEqual, strictEqual, ok } from 'assert';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');

const FIXTURE = readFileSync(
  new URL('../fixtures/libsignal-session.json', import.meta.url),
  'utf-8',
);

// ── curve_sign / curve_verify / curve_generate_keypair ──
{
  const seed = Buffer.alloc(32, 0x42);
  const msg = Buffer.from('hello');
  const [pub, priv] = n.curveGenerateKeypair(seed);
  strictEqual(pub.length, 32, 'pubkey is 32 bytes');
  strictEqual(priv.length, 32, 'privkey is 32 bytes');
  const sig = n.curveSign(priv, msg, null);
  ok(sig instanceof Buffer, 'curveSign returns Buffer');
  strictEqual(sig.length, 64, 'signature is 64 bytes');
  strictEqual(n.curveVerify(pub, msg, sig), true);
  // tamper → verify fails
  strictEqual(n.curveVerify(pub, Buffer.from('hallo'), sig), false);
}

// ── curve_generate_keypair ──
{
  const seed = Buffer.alloc(32, 0xab);
  const [pub, priv] = n.curveGenerateKeypair(seed);
  strictEqual(pub.length, 32);
  strictEqual(priv.length, 32);
  // Deterministic: same seed → same keypair
  const [pub2, priv2] = n.curveGenerateKeypair(seed);
  deepStrictEqual(pub, pub2);
  deepStrictEqual(priv, priv2);
}

// ── curve_scalar_multiply ──
{
  const seedA = Buffer.alloc(32, 0xaa);
  const seedB = Buffer.alloc(32, 0xbb);
  const [pubA, privA] = n.curveGenerateKeypair(seedA);
  const [pubB, privB] = n.curveGenerateKeypair(seedB);
  const sharedAB = n.curveScalarMultiply(privA, pubB);
  const sharedBA = n.curveScalarMultiply(privB, pubA);
  strictEqual(sharedAB.length, 32);
  deepStrictEqual(sharedAB, sharedBA);
}

// ── session_deserialize / session_serialize / session_have_open_session ──
{
  const json = n.sessionDeserialize(FIXTURE);
  const parsed = JSON.parse(json);
  ok(parsed.version, 'has version');
  ok(parsed._sessions, 'has sessions');
  strictEqual(n.sessionHaveOpenSession(json), true);
  // serialize roundtrip
  const json2 = n.sessionSerialize(FIXTURE);
  deepStrictEqual(JSON.parse(json), JSON.parse(json2));
}

// ── proto roundtrip ──
{
  const eph = Buffer.alloc(32, 0xaa);
  const ct = Buffer.alloc(64, 0xbb);
  const encoded = n.protoEncodeWhisper(eph, 42, 7, ct);
  ok(encoded instanceof Buffer);

  const decoded = JSON.parse(n.protoDecodeWhisper(encoded));
  deepStrictEqual(Buffer.from(decoded.ephemeral_key), eph);
  strictEqual(decoded.counter, 42);
  strictEqual(decoded.previous_counter, 7);
  deepStrictEqual(Buffer.from(decoded.ciphertext), ct);
}

// ── proto pkmsg roundtrip ──
{
  const msg = {
    pre_key_id: null,
    base_key: [...Buffer.alloc(33, 0x11)],
    identity_key: [...Buffer.alloc(33, 0x22)],
    message: [...Buffer.alloc(50, 0x33)],
    registration_id: 555,
    signed_pre_key_id: null,
  };
  const encoded = n.protoEncodePkmsg(JSON.stringify(msg));
  ok(encoded instanceof Buffer);

  const decoded = JSON.parse(n.protoDecodePkmsg(encoded));
  strictEqual(decoded.registration_id, 555);
  deepStrictEqual(Buffer.from(decoded.base_key), Buffer.from(msg.base_key));
  deepStrictEqual(Buffer.from(decoded.identity_key), Buffer.from(msg.identity_key));
  strictEqual(decoded.pre_key_id, null);
  strictEqual(decoded.signed_pre_key_id, null);
}

// ── x3dh_build_initial_session ──
{
  const identityPriv = Buffer.alloc(32, 0x42);
  const [identityPub32, _] = n.curveGenerateKeypair(identityPriv);
  const identityPub = Buffer.concat([Buffer.from([0x05]), identityPub32]);

  const recipientSeed = Buffer.alloc(32, 0x44);
  const [recipPub32, recipPriv] = n.curveGenerateKeypair(recipientSeed);
  const recipientPub = Buffer.concat([Buffer.from([0x05]), recipPub32]);

  const signedPrekeyPub = Buffer.alloc(32, 0x43);
  // signed prekey must be signed by recipient's identity key
  const sig = n.curveSign(recipPriv, signedPrekeyPub, null);
  strictEqual(sig.length, 64);

  const recipientPrekey = Buffer.alloc(32, 0x45);

  const sessionJson = n.x3DhBuildInitialSession(
    identityPriv,
    identityPub,
    signedPrekeyPub,
    sig,
    null,  // prekeyPub
    null,  // prekeyId
    recipientPub,
    recipientPrekey,
    42,    // registrationId
  );
  ok(typeof sessionJson === 'string');
  const session = JSON.parse(sessionJson);
  ok(session._sessions, 'has sessions');
  const entries = Object.values(session._sessions);
  strictEqual(entries.length, 1);
  strictEqual(entries[0].registrationId, 42);
  strictEqual(entries[0].indexInfo.closed, -1);
}

// ── ratchet encrypt (shape only) ──
{
  // Build initiator session (same as x3dh test above)
  const identityPriv = Buffer.alloc(32, 0x42);
  const [identityPub32, _] = n.curveGenerateKeypair(identityPriv);
  const identityPub = Buffer.concat([Buffer.from([0x05]), identityPub32]);

  const recipientSeed = Buffer.alloc(32, 0x44);
  const [recipPub32, recipPriv] = n.curveGenerateKeypair(recipientSeed);
  const recipientPub = Buffer.concat([Buffer.from([0x05]), recipPub32]);

  const signedPrekeyPub = Buffer.alloc(32, 0x43);
  const sig = n.curveSign(recipPriv, signedPrekeyPub, null);

  const recipientPrekey = Buffer.alloc(32, 0x45);

  const sessionJson = n.x3DhBuildInitialSession(
    identityPriv, identityPub,
    signedPrekeyPub, sig,
    null, null,
    recipientPub, recipientPrekey, 42,
  );

  const plaintext = Buffer.from('hello signal');
  const encResult = JSON.parse(
    n.ratchetEncrypt(sessionJson, plaintext, identityPub, recipientPub)
  );
  ok(encResult.session_json, 'has session_json');
  ok(encResult.ciphertext, 'has ciphertext');
  ok(typeof encResult.message_type === 'number');
  ok(encResult.ciphertext.length > 0);

  // decrypt_whisper and decrypt_pkmsg exist and are callable
  ok(typeof n.ratchetDecryptWhisper === 'function');
  ok(typeof n.ratchetDecryptPkmsg === 'function');
}

// ── all exports exist ──
{
  const expected = [
    'curveSign', 'curveVerify', 'curveScalarMultiply', 'curveGenerateKeypair',
    'protoEncodeWhisper', 'protoDecodeWhisper', 'protoEncodePkmsg', 'protoDecodePkmsg',
    'sessionDeserialize', 'sessionSerialize', 'sessionHaveOpenSession',
    'x3DhBuildInitialSession',
    'ratchetEncrypt', 'ratchetDecryptWhisper', 'ratchetDecryptPkmsg',
  ];
  for (const name of expected) {
    ok(typeof n[name] === 'function', `missing export: ${name}`);
  }
}