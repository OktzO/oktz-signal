#![deny(unsafe_code)]
// Double Ratchet encrypt/decrypt (Signal Protocol, v6 wire-compatible).
// Wire format verified against libsignal v6 oracle:
//   - Message key: HMAC-SHA256(chainKey.key, [0x01]); chain step HMAC [0x02].
//   - Encryption keys: deriveSecrets(messageKey, zeros(32), "WhisperMessageKeys")
//     → [0] AES-256 key (32B), [1] MAC key (32B), [2][0..16] IV.
//   - WhisperMessage = [0x33] || protobuf || MAC[0..8] (8-byte MAC, version byte).
//   - MAC input (encrypt): ourIdentity(33) || remoteIdentity(33) || [0x33] || proto.
//   - MAC input (decrypt): remoteIdentity(33) || ourIdentity(33) || [0x33] || proto.
//   - DH ratchet: deriveSecrets(shared, rootKey, "WhisperRatchet", 2).
//   - Record storage: _chains is keyed by the 33-byte wire public key
//     (session_record.js addChain/getChain key on the Buffer it is handed, and
//     every key it is handed came off the wire with its 0x05 prefix), and a
//     receiving chain is chainType 2 (chain_type.js).

use crate::curve;
use crate::proto;
use crate::session::{
    self, Chain, ChainKey, KeyPair, SessionEntry, SessionRecord, RECEIVING, SENDING,
};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Most message keys one message may buy an unauthenticated sender, measured
/// as the DISTANCE from the chain's own position — libsignal's bound
/// (session_cipher.js fillMessageKeys: "Over 2000 messages into the future!"),
/// and the only one that does not reject traffic a peer is entitled to send.
/// An absolute ceiling on the wire counter was worse than useless: it dropped
/// every message past counter 2000 of an epoch while the peer could still send
/// them, losing them silently until the next ratchet step. The distance is
/// what bounds the work — a chain sitting at 0 still refuses anything more than
/// 2000 ahead of it, and a chain at 1_000_000 has nothing left to fill.
const MAX_SKIP: i64 = 2000;

/// Total cap on retained skipped keys per chain. MAX_SKIP bounds the distance
/// of a single jump; this bounds the store, which is what a peer that sends
/// counters MAX_SKIP apart, repeatedly, would otherwise grow without limit.
/// signalapp/libsignal separates the two as MAX_FORWARD_JUMPS and
/// MAX_MESSAGE_KEYS; we keep MAX_SKIP's value for both and add this.
const MAX_RETAINED_MESSAGE_KEYS: usize = 2000;

// AES-256-CBC (32-byte key) encrypt, manual (block-modes 0.9.1 is deprecated-empty).
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
    let pad_len = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len() + pad_len, pad_len as u8);

    let mut ct = Vec::with_capacity(padded.len());
    let mut prev = *iv;
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(&mut block);
        ct.extend_from_slice(&block);
        prev = block.into();
    }
    Ok(ct)
}

// AES-256-CBC decrypt (manual).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return Err("invalid ciphertext length".to_string());
    }
    let cipher = Aes256::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.chunks(16) {
        let block = GenericArray::clone_from_slice(chunk);
        let mut dec = block;
        cipher.decrypt_block(&mut dec);
        for (d, p) in dec.iter_mut().zip(prev.iter()) {
            *d ^= p;
        }
        out.extend_from_slice(&dec);
        prev = block.into();
    }
    // PKCS7 unpad. Every one of the last `pad` bytes must equal `pad`; only the
    // final one was read before, so a forged padding block passed. Compare all
    // of them without an early exit, and report every failure the same way.
    let pad = *out.last().ok_or("invalid padding")? as usize;
    let mut diff = 0u8;
    if pad > 0 && pad <= 16 && out.len() >= pad {
        for &b in &out[out.len() - pad..] {
            diff |= b ^ pad as u8;
        }
    } else {
        diff = 1;
    }
    if diff != 0 {
        return Err("invalid padding".to_string());
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// The _chains map is keyed by the 33-byte wire public key, but oktz-signal
// releases before this alignment stored the 32-byte X25519 key, and records
// already on disk still carry it. A lookup therefore tries the 33-byte form
// first — what libsignal writes and what every new record gets — and falls
// back to the stripped form so an existing oktz-signal record still decrypts.
// Nothing is migrated: the record oktz-signal reads is used as found, and the
// first successful message advances it to the canonical form.
fn chain_key_ids(raw: &[u8]) -> Vec<String> {
    let mut ids = vec![crate::util::b64(raw)];
    if raw.len() == 33 && raw[0] == 0x05 {
        let stripped = crate::util::b64(&raw[1..]);
        if stripped != ids[0] {
            ids.push(stripped);
        }
    }
    ids
}

fn chain_key_ids_b64(key: &str) -> Vec<String> {
    match crate::util::unb64(key) {
        Ok(raw) => chain_key_ids(&raw),
        Err(_) => vec![key.to_string()],
    }
}

// 33-byte wire public key → the 32-byte X25519 scalar curve::scalar_multiply
// wants. 32-byte keys pass through.
fn as_x25519(raw: &[u8]) -> &[u8] {
    if raw.len() == 33 && raw[0] == 0x05 {
        &raw[1..]
    } else {
        raw
    }
}

fn find_chain<'a>(chains: &'a BTreeMap<String, Chain>, ids: &[String]) -> Option<&'a Chain> {
    ids.iter().find_map(|id| chains.get(id))
}

fn find_chain_mut<'a>(
    chains: &'a mut BTreeMap<String, Chain>,
    ids: &[String],
) -> Option<&'a mut Chain> {
    for id in ids {
        if chains.contains_key(id) {
            return chains.get_mut(id);
        }
    }
    None
}

// N-chunk HKDF (RFC 5869 Extract-then-Expand) — same as libsignal deriveSecrets.
// Chunks are Zeroizing: they are the derived AES/MAC keys and IV, so they must
// be scrubbed rather than left in the heap when the caller's scope ends.
pub(crate) fn derive_secrets_n(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
    n: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
    let prk = {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).map_err(|e| e.to_string())?;
        mac.update(input);
        mac.finalize().into_bytes()
    };
    let mut out = Vec::with_capacity(n);
    let mut prev = Vec::new();
    for i in 0..n {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&prev);
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let chunk = mac.finalize().into_bytes().to_vec();
        out.push(Zeroizing::new(chunk.clone()));
        prev = chunk;
    }
    Ok(out)
}

// Drop the oldest retained keys until the store is within
// MAX_RETAINED_MESSAGE_KEYS. BTreeMap iterates in ascending key order and a key
// IS its counter, so pop_first takes the lowest counter — the oldest key. That
// is the right one to lose: a counter further in the past is the least likely
// to still be redelivered. An evicted key is unrecoverable — there is no way to
// re-derive it without walking the chain key back from the current position,
// which is exactly what this cap exists to prevent — so eviction is a real
// loss, not a cache miss. That is accepted deliberately: the cap must hold at
// every return point, and the alternative (no cap) is unbounded growth driven
// by any peer that holds the chain key.
fn evict_oldest_message_keys(chain: &mut Chain) {
    while chain.messageKeys.len() > MAX_RETAINED_MESSAGE_KEYS {
        if chain.messageKeys.pop_first().is_none() {
            break;
        }
    }
}

// Derive + store message keys for skipped counters (recursive chain key step).
// Per oracle:
//   if counter <= chainKey.counter → return
//   if counter - chainKey.counter > 2000 → Err("Over 2000 messages into the future!")
//   messageKeys[counter+1] = HMAC(chainKey.key, [0x01])  (index = counter being filled)
//   chainKey.key = HMAC(chainKey.key, [0x02])
//   chainKey.counter += 1
//   recurse
//
// The store is capped at MAX_RETAINED_MESSAGE_KEYS (see evict_oldest_message_keys).
// Eviction is placed AFTER each insert and BEFORE the recursion, and only there.
// Three placements were considered:
//   - Before every recursion level, including on entry: REJECTED, see below.
//   - Once after the recursion returns (i.e. only at the outermost level):
//     rejected, because fill_message_keys inserts one key per level, so a single
//     legal MAX_SKIP jump would carry the store at 2 * MAX_RETAINED_MESSAGE_KEYS
//     for the whole descent — exactly the over-cap state the cap exists to stop.
//   - After each insert, before recursing: CHOSEN. The store is at or under the
//     cap before and after every insert, so a chain that STARTS within the cap
//     peaks at cap + 1 for the single instant between the insert and the trim,
//     and every return point of every level is at or under the cap — with no
//     dependence on where the outermost level happens to unwind.
//
// Evicting on ENTRY was rejected on evidence, not on preference. decrypt_entry
// peeks the message key, verifies the MAC, then calls this function and removes
// the key by counter (ratchet.rs decrypt_entry). A record written by an uncapped
// producer — libsignal-js's fillMessageKeys has no store cap at all — can arrive
// with a store already over the limit. Trimming on entry then discards the very
// key peek had just found and the MAC had just verified, and the remove that
// follows fails with "message key not found": a redelivered message that
// decrypts correctly today stops decrypting. Trimming after the insert instead
// leaves such a record's existing keys alone, and normalises the store on the
// first fill that actually grows it — so the cap still converges, and no
// readable message is lost to a trim it did not need.
//
// The cost of that choice is stated rather than hidden: until a growing fill
// happens, an over-cap record read from an uncapped producer keeps its extra
// keys. The cap bounds what THIS code accumulates, which is the unbounded-growth
// problem being fixed; it is not a claim that every possible on-disk record is
// already within the limit.
fn fill_message_keys(chain: &mut Chain, counter: i64) -> Result<(), String> {
    if counter <= chain.chainKey.counter {
        return Ok(());
    }
    // A retired chain is stored with its key deleted. Deriving from it would
    // mean HMAC under an empty key — public knowledge — so a forgery would
    // pass the real MAC. Fail closed instead.
    if chain.chainKey.is_closed() {
        return Err("receiving chain is closed".to_string());
    }
    if counter - chain.chainKey.counter > MAX_SKIP {
        return Err("Over 2000 messages into the future!".to_string());
    }
    let ck = Zeroizing::new(crate::util::unb64(chain.chainKey.key()?)?);
    let message_key = Zeroizing::new(hmac_sha256(&ck, &[0x01]));
    let next_chain_key = Zeroizing::new(hmac_sha256(&ck, &[0x02]));
    chain.messageKeys.insert(
        chain.chainKey.counter + 1,
        crate::util::b64(&message_key),
    );
    evict_oldest_message_keys(chain);
    chain.chainKey.key = Some(crate::util::b64(&next_chain_key));
    chain.chainKey.counter += 1;
    fill_message_keys(chain, counter)
}

// Read-only twin of fill_message_keys: identical guards and identical key
// schedule, but it writes nothing. Returns the message key the chain would have
// produced, or `Ok(None)` when the counter is behind the chain and no such key
// was retained. This is what lets decrypt read the message key for the MAC
// without stepping the chain.
fn peek_message_key(chain: &Chain, counter: i64) -> Result<Option<String>, String> {
    if counter <= chain.chainKey.counter {
        return Ok(chain.messageKeys.get(&counter).cloned());
    }
    if chain.chainKey.is_closed() {
        return Err("receiving chain is closed".to_string());
    }
    if counter - chain.chainKey.counter > MAX_SKIP {
        return Err("Over 2000 messages into the future!".to_string());
    }
    let mut ck = Zeroizing::new(crate::util::unb64(chain.chainKey.key()?)?);
    let mut message_key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    for _ in chain.chainKey.counter..counter {
        let next = Zeroizing::new(hmac_sha256(&ck, &[0x01]));
        ck = Zeroizing::new(hmac_sha256(&ck, &[0x02]));
        message_key = next;
    }
    Ok(Some(crate::util::b64(&message_key[..])))
}

// A DH ratchet step that has been computed but not applied. Every field it
// will write is derived here, from the entry as it stands, so the step can be
// dropped on a MAC failure with the record never having been touched.
struct RatchetPlan {
    // Chain-map key of the chain to drop: the receiving chain this step
    // retires. The id it is stored under, not a recomputed one, so a record
    // keyed the legacy 32-byte way is emptied correctly too.
    retired_recv_chain: Option<String>,
    receiving_chain_id: String,
    last_remote_ephemeral_key: String,
    previous_counter: u32,
    root_key: String,
    ephemeral_key_pair: KeyPair,
    receiving_chain: Chain,
    sending_chain: Chain,
}

// DH ratchet step: only when no chain exists for the remote ephemeral key.
// Mirrors libsignal maybeStepRatchet (session_cipher.js):
//   1. Close previous receiving chain (if any): fill to previousCounter, drop key.
//   2. receiving chain from current_ratchet_priv x remoteKey (rootKey update).
//   3. Swap ephemeral keypair to a fresh key; previousCounter = old sending chain counter.
//   4. sending chain from new_ratchet_priv x remoteKey (rootKey update).
// Every input is read; the four writes happen in apply_ratchet.
// `remote_key_ids` are the chain-map keys the incoming wire ephemeral key may be
// stored under, canonical (33-byte) form first.
fn plan_ratchet(
    entry: &SessionEntry,
    remote_key_ids: &[String],
    previous_counter: u32,
) -> Result<Option<RatchetPlan>, String> {
    if find_chain(&entry.chains, remote_key_ids).is_some() {
        return Ok(None);
    }
    let remote_raw = crate::util::unb64(&remote_key_ids[0])?;
    let remote_key = as_x25519(&remote_raw);

    // 1. Close previous receiving chain (keyed by lastRemoteEphemeralKey).
    // libsignal empties the chain's key but LEAVES it in the map
    // (delete previousRatchet.chainKey.key); the keys it derives to reach
    // previousCounter are discarded either way, because once a ratchet step
    // happens messages still pending on the old chain are unrecoverable.
    // Removing it instead is strictly tighter and is what an oktz-signal record
    // holds, so a record libsignal wrote is read and then left in the
    // canonical shape.
    let retired_recv_chain = if entry.currentRatchet.lastRemoteEphemeralKey.is_empty() {
        None
    } else {
        let prev_ids = chain_key_ids_b64(&entry.currentRatchet.lastRemoteEphemeralKey);
        if let Some(prev_chain) = find_chain(&entry.chains, &prev_ids) {
            if prev_chain.is_receiving() {
                peek_message_key(prev_chain, previous_counter as i64)?;
            }
        }
        prev_ids.into_iter().next()
    };

    // 2. Receiving chain.
    let ratchet_priv = Zeroizing::new(crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.privKey)?);
    let shared = Zeroizing::new(curve::scalar_multiply(&ratchet_priv, &remote_key)?);
    let root_key = crate::util::unb64(&entry.currentRatchet.rootKey)?;
    let mk_recv = derive_secrets_n(&shared[..], &root_key, b"WhisperRatchet", 2)?;

    // 3. Fresh ephemeral keypair; snapshot the old sending chain's counter.
    let old_send_ids = chain_key_ids_b64(&entry.currentRatchet.ephemeralKeyPair.pubKey);
    let mut plan_previous_counter = entry.currentRatchet.previousCounter;
    if let Some(old_send) = find_chain(&entry.chains, &old_send_ids) {
        if old_send.is_sending() {
            plan_previous_counter = old_send.chainKey.counter.max(0) as u32;
        }
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let (new_pub, new_priv) = curve::generate_keypair(&seed)?;

    // 4. Sending chain: DH(new_priv, remoteKey) with the updated root key.
    let shared_send = Zeroizing::new(curve::scalar_multiply(&new_priv, &remote_key)?);
    let mk_send = derive_secrets_n(&shared_send[..], &mk_recv[0], b"WhisperRatchet", 2)?;

    // libsignal stores the ratchet keypair and the sending chain under the
    // 33-byte wire form (calculateRatchet), so a record oktz-signal writes is
    // one libsignal can keep using.
    let mut new_pub_wire = if new_pub.len() == 32 {
        vec![0x05u8]
    } else {
        Vec::new()
    };
    new_pub_wire.extend_from_slice(&new_pub);
    let new_pub_id = crate::util::b64(&new_pub_wire);

    Ok(Some(RatchetPlan {
        retired_recv_chain,
        receiving_chain_id: remote_key_ids[0].clone(),
        last_remote_ephemeral_key: remote_key_ids[0].clone(),
        previous_counter: plan_previous_counter,
        root_key: crate::util::b64(&mk_send[0]),
        ephemeral_key_pair: KeyPair {
            pubKey: new_pub_id.clone(),
            privKey: crate::util::b64(&new_priv),
        },
        receiving_chain: Chain {
            chainKey: ChainKey {
                counter: -1,
                key: Some(crate::util::b64(&mk_recv[1])),
            },
            chainType: RECEIVING,
            messageKeys: BTreeMap::new(),
        },
        sending_chain: Chain {
            chainKey: ChainKey {
                counter: -1,
                key: Some(crate::util::b64(&mk_send[1])),
            },
            chainType: SENDING,
            messageKeys: BTreeMap::new(),
        },
    }))
}

fn apply_ratchet(entry: &mut SessionEntry, plan: RatchetPlan) {
    if let Some(retired) = plan.retired_recv_chain {
        entry.chains.remove(&retired);
    }
    entry
        .chains
        .insert(plan.receiving_chain_id, plan.receiving_chain);
    let old_send_ids = chain_key_ids_b64(&entry.currentRatchet.ephemeralKeyPair.pubKey);
    let mut retired_sending = None;
    for id in &old_send_ids {
        if let Some(chain) = entry.chains.remove(id) {
            retired_sending = Some(chain);
            break;
        }
    }
    if let Some(old_send) = retired_sending {
        if old_send.is_sending() {
            entry.currentRatchet.previousCounter = plan.previous_counter;
        }
    }
    let new_eph_id = plan.ephemeral_key_pair.pubKey.clone();
    entry.currentRatchet.rootKey = plan.root_key;
    entry.currentRatchet.ephemeralKeyPair = plan.ephemeral_key_pair;
    entry.currentRatchet.lastRemoteEphemeralKey = plan.last_remote_ephemeral_key;
    entry.chains.insert(new_eph_id, plan.sending_chain);
}

#[derive(serde::Serialize)]
pub struct EncryptResult {
    pub session_json: String,
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize)]
pub struct DecryptResult {
    pub session_json: String,
    pub plaintext: Vec<u8>,
}

/// Double Ratchet encrypt (v6 oracle wire format).
/// result = [0x33] || WhisperMessage(ephemeralKey, counter, previousCounter, ct) || MAC[0..8]
/// If pendingPreKey is set, wraps as PreKeyWhisperMessage (message_type=3, ciphertext =
/// [0x33] || encode_pkmsg). pendingPreKey persists until first decrypt (oracle behavior).
/// Remote identity is read from the record's indexInfo (matches libsignal, which
/// derives it from the stored session rather than a JS-supplied argument).
pub fn encrypt(
    session_json: &str,
    plaintext: &[u8],
    our_identity_pub: &[u8],    // 33 bytes, sender identity
    our_registration_id: u32,   // sender's own registration ID (for PKMsg)
) -> Result<EncryptResult, String> {
    let mut record: SessionRecord = session::deserialize(session_json)?;
    let entry = session::current_session_mut(&mut record)
        .ok_or("no session entry")?;
    let remote_identity_pub = crate::util::unb64(&entry.indexInfo.remoteIdentityKey)?;

    // Wire ephemeral keys are 33-byte (0x05 prefix) in WhisperMessage — same as
    // libsignal curve.generateKeyPair (prefixKeyInPublicKey). Internal chain
    // keys stay 32-byte; prefix only at the wire boundary.
    let eph_pub = crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.pubKey)?;
    let ephemeral_key = if eph_pub.len() == 32 {
        let mut pk = vec![0x05u8];
        pk.extend_from_slice(&eph_pub);
        pk
    } else {
        eph_pub
    };
    let previous_counter = entry.currentRatchet.previousCounter;

    // libsignal selects the sending chain explicitly —
    // session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey) — and
    // then asserts the chain it got is not a receiving chain. Map order is not a
    // substitute for either half of that. `chains` is a BTreeMap keyed by
    // base64, so `find(|c| c.is_sending())` returned the lexicographically
    // smallest sending chain, which in a record holding two is not necessarily
    // the peer's: the message then goes out under a chain key the peer never
    // derives from — emitted, delivered, and silently undeliverable.
    let sending_ids = chain_key_ids_b64(&entry.currentRatchet.ephemeralKeyPair.pubKey);
    let named_sending = find_chain(&entry.chains, &sending_ids).map_or(false, Chain::is_sending);
    let chain = if named_sending {
        find_chain_mut(&mut entry.chains, &sending_ids).ok_or("no sending chain")?
    } else {
        // pubKey names no sending chain. Two records are legitimately in that
        // state and must keep encrypting: one written before the chain key was
        // aligned to the 33-byte wire form, which keys the chain the legacy way,
        // and a self-session record, which keys the receiving mirror of the
        // sending chain by pubKey. Both are unambiguous while exactly one chain
        // is a sending chain. More than one means the record cannot say which
        // chain the peer is on, and choosing between them by map order is the
        // failure being fixed here, so refuse instead of guessing.
        match entry.chains.values().filter(|c| c.is_sending()).count() {
            0 => return Err("no sending chain".to_string()),
            1 => entry
                .chains
                .values_mut()
                .find(|c| c.is_sending())
                .ok_or("no sending chain")?,
            n => {
                return Err(format!(
                    "ambiguous sending chain: {} chains are sending and none is keyed by the \
                     current ephemeralKeyPair.pubKey",
                    n
                ))
            }
        }
    };

    let target_counter = chain
        .chainKey
        .counter
        .checked_add(1)
        .ok_or("message counter overflow")?;
    fill_message_keys(chain, target_counter)?;
    let message_key_b64 = chain
        .messageKeys
        .remove(&target_counter)
        .ok_or("message key not found")?;
    let message_key = Zeroizing::new(crate::util::unb64(&message_key_b64)?);

    // keys = deriveSecrets(messageKey, zeros(32), "WhisperMessageKeys") → 3 chunks.
    let keys = derive_secrets_n(&message_key, &[0u8; 32], b"WhisperMessageKeys", 3)?;
    let iv: [u8; 16] = keys[2][..16].try_into().map_err(|_| "iv length")?;
    let ciphertext = aes_cbc_encrypt(&keys[0], &iv, plaintext)?;

    let whisper_msg = proto::WhisperMessage {
        ephemeral_key,
        counter: u32::try_from(target_counter)
            .map_err(|_| "message counter does not fit the u32 wire field".to_string())?,
        previous_counter,
        ciphertext,
    };
    let msg_buf = proto::encode_whisper(&whisper_msg)?;

    // macInput = ourIdentityKey || remoteIdentityKey || [0x33] || msgBuf
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(our_identity_pub);
    mac_input.extend_from_slice(&remote_identity_pub);
    mac_input.push(0x33);
    mac_input.extend_from_slice(&msg_buf);
    let mac = hmac_sha256(&keys[1], &mac_input);

    // result = [0x33] || msgBuf || mac[0..8]
    let mut result = Vec::with_capacity(1 + msg_buf.len() + 8);
    result.push(0x33);
    result.extend_from_slice(&msg_buf);
    result.extend_from_slice(&mac[..8]);

    let pending = entry.pendingPreKey.clone();
    let session_json = session::serialize(&record)?;

    if let Some(pk) = pending {
        let pk_bk = crate::util::unb64(&pk.baseKey)?;
        let base_key = if pk_bk.len() == 32 {
            let mut b = vec![0x05u8];
            b.extend_from_slice(&pk_bk);
            b
        } else {
            pk_bk
        };
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: pk.preKeyId,
            base_key,
            identity_key: our_identity_pub.to_vec(),
            message: result.clone(),
            registration_id: our_registration_id,
            signed_pre_key_id: pk.signedKeyId,
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg)?;
        let mut wrapped = Vec::with_capacity(1 + pk_bytes.len());
        wrapped.push(0x33);
        wrapped.extend_from_slice(&pk_bytes);
        return Ok(EncryptResult {
            session_json,
            message_type: 3,
            ciphertext: wrapped,
        });
    }
    Ok(EncryptResult {
        session_json,
        message_type: 1,
        ciphertext: result,
    })
}

/// Decrypt a WhisperMessage (v6 oracle wire format).
pub fn decrypt_whisper(
    session_json: &str,
    ciphertext: &[u8],
    our_identity_pub: &[u8], // 33 bytes, local receiver identity
) -> Result<DecryptResult, String> {
    if ciphertext.len() < 9 || ciphertext[0] != 0x33 {
        return Err("bad version byte or truncated message".to_string());
    }
    let msg_buf = &ciphertext[1..ciphertext.len() - 8];
    let mac_bytes = &ciphertext[ciphertext.len() - 8..];
    let msg = proto::decode_whisper(msg_buf)?;

    let mut record: SessionRecord = session::deserialize(session_json)?;
    let entry = session::current_session_mut(&mut record)
        .ok_or("no session entry")?;
    let plaintext = decrypt_entry(entry, &msg, msg_buf, mac_bytes, our_identity_pub)?;

    let session_json = session::serialize(&record)?;
    Ok(DecryptResult {
        session_json,
        plaintext,
    })
}

fn decrypt_entry(
    entry: &mut SessionEntry,
    msg: &proto::WhisperMessage,
    msg_buf: &[u8],
    mac_bytes: &[u8],
    our_identity_pub: &[u8],
) -> Result<Vec<u8>, String> {
    // Real WhatsApp ephemeral keys are 33 bytes (0x05 prefix) in WhisperMessage,
    // and libsignal keys _chains by that same 33-byte value. The record may hold
    // the chain under the 32-byte X25519 form instead, so both are tried.
    let remote_key_ids = chain_key_ids(&msg.ephemeral_key);

    // Plan the DH ratchet step without applying it. The sender is
    // unauthenticated until verify_truncated_left below, so no part of the
    // record may move before that point: a forged message must not install a
    // new sending chain, rewrite the root key, or burn a message key.
    let plan = plan_ratchet(entry, &remote_key_ids, msg.previous_counter)?;

    let receiving_chain = match &plan {
        Some(plan) => &plan.receiving_chain,
        None => find_chain(&entry.chains, &remote_key_ids)
            .filter(|c| c.is_receiving())
            .ok_or("no receiving chain")?,
    };
    let message_key_b64 = peek_message_key(receiving_chain, msg.counter as i64)?
        .ok_or("message key not found")?;
    let message_key = Zeroizing::new(crate::util::unb64(&message_key_b64)?);

    let keys = derive_secrets_n(&message_key, &[0u8; 32], b"WhisperMessageKeys", 3)?;

    // macInput = remoteIdentityKey || ourIdentityKey || [0x33] || messageProto
    // (remote first, ours second — reversed vs encrypt).
    let remote_identity = crate::util::unb64(&entry.indexInfo.remoteIdentityKey)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&remote_identity);
    mac_input.extend_from_slice(our_identity_pub);
    mac_input.push(0x33);
    mac_input.extend_from_slice(msg_buf);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys[1]).map_err(|e| e.to_string())?;
    mac.update(&mac_input);
    // Constant-time truncated-tag compare. NB: `verify_slice` demands a
    // full-length tag; `verify_truncated_left` is the constant-time prefix
    // check that matches the 8-byte wire MAC.
    mac.verify_truncated_left(mac_bytes)
        .map_err(|_| "MAC verification failed".to_string())?;

    // Authenticated. Commit the plan and step the receiving chain in place —
    // no clone, so a chain holding up to MAX_SKIP skipped message keys is not
    // copied. peek_message_key applied the same guards (skip cap, open chain,
    // retained key) to the same chain key, so this reaches the same state the
    // read-only pass assumed.
    if let Some(plan) = plan {
        apply_ratchet(entry, plan);
    }
    let chain = find_chain_mut(&mut entry.chains, &remote_key_ids)
        .filter(|c| c.is_receiving())
        .ok_or("no receiving chain")?;
    fill_message_keys(chain, msg.counter as i64)?;
    chain
        .messageKeys
        .remove(&(msg.counter as i64))
        .ok_or("message key not found")?;

    let iv: [u8; 16] = keys[2][..16].try_into().map_err(|_| "iv length")?;
    let plaintext = aes_cbc_decrypt(&keys[0], &iv, &msg.ciphertext)?;

    entry.pendingPreKey = None; // delete pendingPreKey
    Ok(plaintext)
}

/// Decrypt a PreKeyWhisperMessage.
/// version = data[0] (must be 0x33); pkmsg = decode_pkmsg(data[1..]).
/// Open session → extract embedded WhisperMessage, decrypt_whisper.
/// No open session → Err (X3DH recipient init deferred to JS wrapper).
pub fn decrypt_pkmsg(
    session_json: &str,
    ciphertext: &[u8],
    our_identity_pub: &[u8],
) -> Result<DecryptResult, String> {
    if ciphertext.is_empty() || ciphertext[0] != 0x33 {
        return Err("bad version byte".to_string());
    }
    let pkmsg = proto::decode_pkmsg(&ciphertext[1..])?;
    let record = session::deserialize(session_json)?;
    if !session::have_open_session(&record) {
        return Err(
            "no open session — X3DH recipient init deferred to JS wrapper".to_string(),
        );
    }
    decrypt_whisper(session_json, &pkmsg.message, our_identity_pub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;

    fn identity_keypair(seed: &[u8; 32]) -> Vec<u8> {
        let (mont, _) = curve::generate_keypair(seed).unwrap();
        let mut pk = vec![0x05u8];
        pk.extend_from_slice(&mont);
        pk
    }

    // Build Alice (sender) session via x3dh + Bob (receiver) mirror session,
    // with distinct identities. Returns (alice, bob, alice_id, bob_id).
    fn build_pair() -> (String, String, Vec<u8>, Vec<u8>) {
        let alice_sk = [0x42u8; 32];
        let bob_sk = [0x77u8; 32];
        let alice_identity = identity_keypair(&alice_sk);
        let bob_identity = identity_keypair(&bob_sk);
        let spk = [0x43u8; 32];
        // Signed prekey must be signed by the recipient's (Bob's) identity.
        let sig = curve::sign(&bob_sk, &spk, None).unwrap();
        let params = x3dh::X3dhParams {
            identity_priv: &alice_sk,
            identity_pub: &alice_identity,
            signed_prekey_pub: &spk,
            signed_prekey_sig: &sig,
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: &bob_identity,
            recipient_prekey: &spk,
            registration_id: 42,
            signed_key_id: 1,
        };
        let fixed_eph = [0x55u8; 32];
        let mut alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();
        // Clear pendingPreKey so bare-ratchet tests exercise the WhisperMessage
        // path (type 1). Type-3 PKMsg wrapping is tested separately.
        let mut alice_record = session::deserialize(&alice).unwrap();
        for entry in alice_record.sessions.values_mut() {
            entry.pendingPreKey = None;
        }
        alice = session::serialize(&alice_record).unwrap();
        let bob = build_bob_session(&alice, &alice_identity);
        (alice, bob, alice_identity, bob_identity)
    }

    // Build a receiver (Bob) session that mirrors Alice's sending chain as
    // Bob's receiving chain (mathematically equivalent to a real X3DH
    // recipient: DH(SPK_B_priv, A_eph_pub) = DH(A_eph_priv, SPK_B_pub)).
    fn build_bob_session(alice_json: &str, alice_identity: &[u8]) -> String {
        let alice: SessionRecord = session::deserialize(alice_json).unwrap();
        let a_entry = alice.sessions.values().next().unwrap();
        let a_eph_pub = a_entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
        let a_send_chain = a_entry
            .chains
            .values()
            .find(|c| c.is_sending())
            .unwrap();
        let root_key = a_entry.currentRatchet.rootKey.clone();

        let bob_seed = [0x11u8; 32];
        let (bob_pub, bob_priv) = curve::generate_keypair(&bob_seed).unwrap();

        let mut chains = BTreeMap::new();
        chains.insert(
            a_eph_pub.clone(),
            Chain {
                chainKey: ChainKey {
                    counter: -1,
                    key: a_send_chain.chainKey.key.clone(),
                },
                chainType: RECEIVING,
                messageKeys: BTreeMap::new(),
            },
        );

        let entry = session::SessionEntry {
            registrationId: 42,
            currentRatchet: session::Ratchet {
                ephemeralKeyPair: KeyPair {
                    pubKey: crate::util::b64(&bob_pub),
                    privKey: crate::util::b64(&bob_priv),
                },
                lastRemoteEphemeralKey: a_eph_pub,
                previousCounter: 0,
                rootKey: root_key,
            },
            indexInfo: session::IndexInfo {
                baseKey: "bob-base".to_string(),
                baseKeyType: 0,
                closed: -1,
                used: 0,
                created: 0,
                remoteIdentityKey: crate::util::b64(alice_identity),
            },
            chains,
            pendingPreKey: None,
        };
        let mut record = SessionRecord {
            sessions: BTreeMap::new(),
            version: "v1".to_string(),
        };
        record.sessions.insert("bob-session".to_string(), entry);
        session::serialize(&record).unwrap()
    }

    #[test]
    fn closed_receiving_chain_is_rejected() {
        // A chain emptied by a DH ratchet step must not remain usable. libsignal
        // expresses that by deleting the key, so the record carries no key at
        // all; a blank key is the same condition. Both must fail closed, because
        // HMAC under an empty key is public knowledge and a forgery would then
        // satisfy the real MAC.
        for key in [None, Some(String::new())] {
            let mut chain = Chain {
                chainKey: ChainKey { counter: 0, key },
                chainType: RECEIVING,
                messageKeys: BTreeMap::new(),
            };
            assert!(
                fill_message_keys(&mut chain, 2).is_err(),
                "a chain key that is absent or blank must never derive message keys"
            );
        }
    }

    #[test]
    fn a_libsignal_retired_chain_is_readable() {
        // session_cipher.js retires a chain with `delete
        // previousRatchet.chainKey.key` and session_record.js serialises
        // `key: c.chainKey.key && ...`, so JSON.stringify omits it. oktz-signal
        // has to read that shape or every bidirectional libsignal session
        // becomes unreadable after its second ratchet step.
        let (_, bob, _, _) = build_pair();
        let mut record: SessionRecord = session::deserialize(&bob).unwrap();
        let retired = record.sessions.values().next().unwrap().currentRatchet.lastRemoteEphemeralKey.clone();
        record
            .sessions
            .values_mut()
            .next()
            .unwrap()
            .chains
            .get_mut(&retired)
            .unwrap()
            .chainKey
            .key = None;
        let json = session::serialize(&record).unwrap();
        assert!(
            !json.contains("\"key\":null"),
            "an absent chain key must not be written back as null"
        );
        let reparsed: SessionRecord = session::deserialize(&json).unwrap();
        assert!(
            reparsed.sessions.values().next().unwrap().chains[&retired]
                .chainKey
                .is_closed(),
            "the retired chain must round-trip still closed"
        );
    }

    #[test]
    fn ratchet_step_retires_the_previous_receiving_chain() {
        // libsignal's maybeStepRatchet empties the retired receiving chain's key
        // and leaves it in the map. Either way the keys it derives for
        // previousCounter are discarded, so oktz-signal drops the chain: what
        // must not happen is the chain surviving with a usable key.
        let (_, bob, _, _) = build_pair();
        let mut record: SessionRecord = session::deserialize(&bob).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        let prev_recv_key = entry.currentRatchet.lastRemoteEphemeralKey.clone();
        assert!(
            entry.chains.contains_key(&prev_recv_key),
            "fixture must start with the retired receiving chain present"
        );

        let (remote_pub, _) = curve::generate_keypair(&[0x9Au8; 32]).unwrap();
        let remote_ids = chain_key_ids(&remote_pub);
        let before = entry.clone();
        let plan = plan_ratchet(entry, &remote_ids, 0).unwrap().unwrap();
        assert_eq!(
            before, *entry,
            "planning a ratchet step must not touch the entry"
        );
        apply_ratchet(entry, plan);

        assert!(
            !entry.chains.contains_key(&prev_recv_key),
            "retired receiving chain must not survive the step"
        );
    }

    // Both map-key widths name the same chain: the 33-byte wire form libsignal
    // stores, and the 32-byte X25519 form oktz-signal releases before this
    // alignment wrote. A record in either shape has to decrypt.
    #[test]
    fn a_chain_keyed_by_either_width_is_found() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let enc = encrypt(&alice, b"either width", &alice_id, 42).unwrap();
        let (msg, msg_buf, mac_bytes) = split_wire(&enc.ciphertext);

        for width in [32usize, 33] {
            let mut record: SessionRecord = session::deserialize(&bob).unwrap();
            let entry = record.sessions.values_mut().next().unwrap();
            let old_id = entry
                .chains
                .keys()
                .next()
                .cloned()
                .expect("fixture must have a receiving chain");
            let chain = entry.chains.remove(&old_id).unwrap();
            let mut raw = crate::util::unb64(&old_id).unwrap();
            if raw.len() == 33 {
                raw.remove(0);
            }
            if width == 33 {
                raw.insert(0, 0x05);
            }
            let new_id = crate::util::b64(&raw);
            entry.chains.insert(new_id.clone(), chain);
            entry.currentRatchet.lastRemoteEphemeralKey = new_id;

            let json = session::serialize(&record).unwrap();
            let dec = decrypt_whisper(&json, &enc.ciphertext, &bob_id)
                .unwrap_or_else(|e| panic!("a chain keyed by {} bytes must decrypt: {}", width, e));
            assert_eq!(dec.plaintext, b"either width");
        }
        let _ = (msg, msg_buf, mac_bytes);
    }

    #[test]
    fn derived_keys_are_zeroized() {
        // Compile-time assertion: the AES/MAC keys and IV must be Zeroizing, so
        // they are scrubbed when the caller's scope ends. Zeroization is a
        // drop-time property with no runtime observable, hence the trait bound
        // on the production signature rather than a value assertion.
        fn chunks_are_zeroizing(_v: &Vec<Zeroizing<Vec<u8>>>) {}
        let secrets = derive_secrets_n(b"input", b"salt", b"info", 2).unwrap();
        chunks_are_zeroizing(&secrets);
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].len(), 32);
    }

    #[test]
    fn encrypt_rejects_counter_overflow() {
        let (alice, _, alice_id, _) = build_pair();
        let mut record: SessionRecord = session::deserialize(&alice).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        entry
            .chains
            .values_mut()
            .find(|c| c.is_sending())
            .unwrap()
            .chainKey
            .counter = i64::MAX;
        let json = session::serialize(&record).unwrap();
        assert!(
            encrypt(&json, b"overflow", &alice_id, 42).is_err(),
            "counter overflow must return an error, not panic or wrap"
        );
    }

    #[test]
    fn encrypt_rejects_counter_beyond_wire_range() {
        let (alice, _, alice_id, _) = build_pair();
        let mut record: SessionRecord = session::deserialize(&alice).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        entry
            .chains
            .values_mut()
            .find(|c| c.is_sending())
            .unwrap()
            .chainKey
            .counter = 0x1_0000_0000;
        let json = session::serialize(&record).unwrap();
        let err = match encrypt(&json, b"truncation", &alice_id, 42) {
            Ok(_) => panic!("a counter that does not fit the u32 wire field must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("counter"),
            "a counter that does not fit the u32 wire field must be named, got: {}",
            err
        );
    }

    // Two sending chains can only appear in a hand-mangled or mixed-provenance
    // record, but libsignal asserts the invariant rather than trusting map
    // order, and the failure mode — encrypting under a chain key the peer will
    // not use — is a silently undeliverable message.
    #[test]
    fn encrypt_refuses_an_ambiguous_record_with_two_sending_chains() {
        // Replays the OLD selection — `chains.values().find(|c| c.is_sending())`,
        // which walks the BTreeMap in ascending key order — against whatever map
        // a half has just built, and returns the chain key it lands on. This is
        // what makes the fixture non-vacuous. A decoy that map order never
        // reaches cannot catch the regression, and that is exactly the mistake
        // this test was first written with: the decoy id began with 'd' (0x64),
        // which sorts ABOVE base64's alphabet, so it sat second and half (b)
        // passed against the unfixed code. Asserting on the replay rather than
        // on a key comparison means that cannot pass unnoticed again.
        fn old_map_order_picks(record: &SessionRecord) -> String {
            record
                .sessions
                .values()
                .next()
                .unwrap()
                .chains
                .values()
                .find(|c| c.is_sending())
                .and_then(|c| c.chainKey.key.clone())
                .expect("fixture must have a sending chain")
        }

        let (alice, bob, alice_id, bob_id) = build_pair();
        let mut record: SessionRecord = session::deserialize(&alice).unwrap();
        let pub_key = record.sessions.values().next().unwrap().currentRatchet.ephemeralKeyPair.pubKey.clone();
        let real = record
            .sessions
            .values()
            .next()
            .unwrap()
            .chains
            .get(&pub_key)
            .cloned()
            .expect("fixture must have a sending chain keyed by the ephemeral public key");
        // Same position, a chain key Bob holds no copy of: whatever comes out
        // encrypted under it reaches him and fails his MAC.
        let decoy_key = crate::util::b64(&[0xA5u8; 32]);
        let decoy_chain = |real: &Chain| {
            let mut decoy = real.clone();
            decoy.chainKey.key = Some(decoy_key.clone());
            decoy
        };
        // '!' (0x21) is below every character base64 can produce, so a decoy
        // named this way sorts first whatever pubKey encodes to.
        let decoy_id = format!("!decoy:{}", pub_key);

        // Half (a) — nothing keyed by pubKey. The record cannot say which chain
        // the peer is on, so the fallback must refuse rather than guess. Catches
        // the fallback rule: against the original map-order selection this half
        // sees `encrypt` return Ok, and against the brief's literal step 3
        // ("fall back to find(|c| c.is_sending())" when no id resolves) it does
        // too.
        {
            let entry = record.sessions.values_mut().next().unwrap();
            entry.chains.clear();
            entry
                .chains
                .insert(decoy_id.clone(), decoy_chain(&real));
            entry
                .chains
                .insert(format!("real:{}", pub_key), real.clone());
        }
        assert_eq!(
            old_map_order_picks(&record),
            decoy_key,
            "half (a): map order must reach the decoy, or this half cannot detect the bug"
        );
        let err = match encrypt(&session::serialize(&record).unwrap(), b"ambiguous", &alice_id, 42) {
            Ok(_) => panic!("two sending chains must not be resolved by map order"),
            Err(e) => e,
        };
        assert!(
            err.contains("ambiguous"),
            "the refusal must name the ambiguity, got: {}",
            err
        );

        // Half (b) — pubKey names a sending chain. Catches the NAMED-selection rule,
        // which half (a) does not: here the record is unambiguous and the
        // message must go out under the NAMED chain's key, because Bob's
        // receiving chain mirrors it. Under map order it reaches Bob and fails
        // his MAC — the silently-undeliverable outcome, end to end.
        {
            let entry = record.sessions.values_mut().next().unwrap();
            entry.chains.clear();
            entry
                .chains
                .insert(decoy_id.clone(), decoy_chain(&real));
            entry.chains.insert(pub_key.clone(), real);
        }
        assert_eq!(
            old_map_order_picks(&record),
            decoy_key,
            "half (b): map order must reach the decoy, or this half cannot detect the bug"
        );
        let enc = encrypt(&session::serialize(&record).unwrap(), b"named", &alice_id, 42)
            .unwrap_or_else(|e| panic!("a named sending chain must be selected: {}", e));
        let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id)
            .unwrap_or_else(|e| panic!("the named chain's message must decrypt: {}", e));
        assert_eq!(dec.plaintext, b"named");
    }

    #[test]
    fn the_counter_bound_is_skip_distance_not_absolute_position() {
        // The sender is unauthenticated here and controls msg.counter, so what
        // bounds the work is how far AHEAD OF THE CHAIN the counter is.
        // libsignal bounds it the same way and with the same number
        // (session_cipher.js fillMessageKeys). An absolute ceiling on the counter
        // dropped every message past counter 2000 of an epoch while the peer
        // could still send them, losing them until the next ratchet step.
        let (_, bob, _, bob_id) = build_pair();
        let record: SessionRecord = session::deserialize(&bob).unwrap();
        let entry = record.sessions.values().next().unwrap();
        let recv_id = entry
            .chains
            .iter()
            .find(|(_, c)| c.is_receiving())
            .map(|(k, _)| k.clone())
            .unwrap();
        let recv_key = crate::util::unb64(&recv_id).unwrap();
        let position = entry.chains[&recv_id].chainKey.counter;

        // One past the skip bound is refused, and the refusal moves nothing.
        let far = proto::WhisperMessage {
            ephemeral_key: recv_key.clone(),
            counter: (position + MAX_SKIP + 1) as u32,
            previous_counter: 0,
            ciphertext: vec![0u8; 32],
        };
        let err = match decrypt_whisper(&bob, &wire_with_bad_mac(&far), &bob_id) {
            Ok(_) => panic!("a counter far past the chain must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("future"),
            "an unauthenticated counter must be bounded before any key derivation, got: {}",
            err
        );
        let after: SessionRecord = session::deserialize(&bob).unwrap();
        assert_eq!(record, after, "a refused counter must not move the record");

        // A counter well past 2000 is fine once the chain has legitimately
        // walked there: the bound is relative, so the MAC is what rejects.
        let mut walked: SessionRecord = session::deserialize(&bob).unwrap();
        {
            let entry = walked.sessions.values_mut().next().unwrap();
            entry.chains.get_mut(&recv_id).unwrap().chainKey.counter = 99_000;
        }
        let far_but_legal = proto::WhisperMessage {
            ephemeral_key: recv_key,
            counter: 100_000,
            previous_counter: 0,
            ciphertext: vec![0u8; 32],
        };
        let err = match decrypt_whisper(
            &session::serialize(&walked).unwrap(),
            &wire_with_bad_mac(&far_but_legal),
            &bob_id,
        ) {
            Ok(_) => panic!("a wrong MAC must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("MAC"),
            "counter 100_000 on a chain at 99_000 must reach the MAC, not a range check, got: {}",
            err
        );
    }

    fn wire_with_bad_mac(msg: &proto::WhisperMessage) -> Vec<u8> {
        let mut wire = vec![0x33];
        wire.extend_from_slice(&proto::encode_whisper(msg).unwrap());
        wire.extend_from_slice(&[0u8; 8]); // deliberately wrong MAC
        wire
    }

    // MAX_SKIP is a distance bound; nothing bounded the store. A peer that
    // already holds the chain key could send counters MAX_SKIP apart, for ever,
    // and every one of those messages would retain a full complement of skipped
    // keys. build_pair gives Bob a receiving chain at counter -1 with a real
    // chain key, which is what the jump arithmetic below is measured against.
    #[test]
    fn retained_message_keys_are_capped_across_many_jumps() {
        let (_, bob, _, _) = build_pair();
        let mut record: SessionRecord = session::deserialize(&bob).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        let chain = entry
            .chains
            .values_mut()
            .find(|c| c.is_receiving())
            .expect("fixture must have a receiving chain");
        assert_eq!(
            chain.chainKey.counter, -1,
            "the receiving chain must start at -1 for the jump arithmetic below"
        );

        // Every jump is the largest MAX_SKIP permits, so under a store with no
        // cap each message adds MAX_SKIP retained keys.
        for _ in 0..5 {
            let target = chain.chainKey.counter + MAX_SKIP;
            fill_message_keys(chain, target).unwrap();
            assert!(
                chain.messageKeys.len() <= MAX_RETAINED_MESSAGE_KEYS,
                "skipped-key store grew to {} entries",
                chain.messageKeys.len()
            );
        }

        // The cap says nothing about WHICH keys go, so pin the direction down:
        // the store must hold the newest counters and drop the oldest. Evicting
        // the newest instead would leave every incoming message without the key
        // it needs — the counter a message arrives on is always the newest one
        // the fill derived, so it is the last thing that may be discarded.
        assert_eq!(
            chain.messageKeys.len(),
            MAX_RETAINED_MESSAGE_KEYS,
            "a chain filling past the cap must sit exactly at it"
        );
        let newest = *chain.messageKeys.keys().next_back().unwrap();
        let oldest = *chain.messageKeys.keys().next().unwrap();
        assert_eq!(
            newest, chain.chainKey.counter,
            "the newest derived key must be retained"
        );
        assert_eq!(
            oldest,
            chain.chainKey.counter - (MAX_RETAINED_MESSAGE_KEYS as i64 - 1),
            "the oldest counters must be the ones evicted"
        );
    }

    #[test]
    fn a_single_2000_message_jump_is_still_accepted() {
        // The cap is a TOTAL bound on the store, not a tighter distance bound.
        // Bob's receiving chain sits at -1, so his furthest legal counter is
        // -1 + MAX_SKIP; a message arriving exactly there must still decrypt.
        // If the cap were enforced as a tighter per-jump limit, or if eviction
        // took the newest keys instead of the oldest, this is the test that
        // would catch it.
        let (alice, bob, alice_id, bob_id) = build_pair();
        let far_counter = MAX_SKIP - 1; // the furthest Bob can be sent
        let mut alice: SessionRecord = session::deserialize(&alice).unwrap();
        {
            let entry = alice.sessions.values_mut().next().unwrap();
            let sending = entry
                .chains
                .values_mut()
                .find(|c| c.is_sending())
                .expect("fixture must have a sending chain");
            // Walk Alice to the counter before the far one; encrypt then emits
            // far_counter itself. Doing it through fill_message_keys rather than
            // by hand means Alice's own store goes through the same cap.
            fill_message_keys(sending, far_counter - 1).unwrap();
        }
        let enc = encrypt(
            &session::serialize(&alice).unwrap(),
            b"far jump",
            &alice_id,
            42,
        )
        .unwrap();
        let (msg, _, _) = split_wire(&enc.ciphertext);
        assert_eq!(
            msg.counter as i64, far_counter,
            "the message must sit at the furthest legal counter"
        );

        let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id)
            .unwrap_or_else(|e| panic!("a MAX_SKIP jump must still decrypt: {}", e));
        assert_eq!(dec.plaintext, b"far jump");

        let rec: SessionRecord = session::deserialize(&dec.session_json).unwrap();
        let entry = rec.sessions.values().next().unwrap();
        let chain = entry.chains.values().find(|c| c.is_receiving()).unwrap();
        assert_eq!(
            chain.chainKey.counter, far_counter,
            "the chain must advance to the message it just decrypted"
        );
        assert!(
            !chain.messageKeys.contains_key(&far_counter),
            "the message's own key must have been consumed"
        );
        // That jump derived MAX_SKIP keys and the cap is MAX_SKIP, so a single
        // legal jump must evict nothing at all: every key it derived is still
        // here, less the one just used.
        assert_eq!(
            chain.messageKeys.len(),
            MAX_RETAINED_MESSAGE_KEYS - 1,
            "a single legal jump must not evict any key it derived"
        );
    }

    #[test]
    fn unpad_rejects_inconsistent_pad_bytes() {
        let key = [0x11u8; 32];
        let iv = [0u8; 16];
        // 16 bytes of plaintext get a full 16-byte 0x10 pad block. Flipping a bit
        // in the *first* block desynchronises the first pad byte of the final
        // block from the last one; only the last byte is read today, so this
        // malformed padding is accepted.
        let mut ct = aes_cbc_encrypt(&key, &iv, &[0xAAu8; 16]).unwrap();
        ct[1] ^= 0xFF;
        assert!(
            aes_cbc_decrypt(&key, &iv, &ct).is_err(),
            "PKCS#7 unpad must check every pad byte, not just the last"
        );
    }

    #[test]
    fn unpad_failures_share_one_error_string() {
        let key = [0x11u8; 32];
        let iv = [0u8; 16];
        // pad byte of 0 (out of range) versus pad bytes that disagree (invalid
        // content). One string, so the error cannot tell an attacker which
        // condition tripped.
        let mut zero_pad = aes_cbc_encrypt(&key, &iv, &[0xAAu8; 15]).unwrap();
        zero_pad[14] ^= 0x01;
        let a = aes_cbc_decrypt(&key, &iv, &zero_pad).unwrap_err();

        let mut bad_pad = aes_cbc_encrypt(&key, &iv, &[0xAAu8; 16]).unwrap();
        bad_pad[1] ^= 0xFF;
        let b = aes_cbc_decrypt(&key, &iv, &bad_pad).unwrap_err();

        assert_eq!(a, b, "unpad failures must not be distinguishable");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"hello signal";

        let enc = encrypt(&alice, plaintext, &alice_id, 42).unwrap();
        assert_eq!(enc.message_type, 1);
        assert_eq!(enc.ciphertext[0], 0x33, "version byte");
        assert!(enc.ciphertext.len() >= 1 + 8, "version + msgBuf + 8B mac");
        // Parsable as WhisperMessage between version byte and 8-byte MAC.
        proto::decode_whisper(&enc.ciphertext[1..enc.ciphertext.len() - 8]).unwrap();

        let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_multi_message_ratchet() {
        let (alice0, bob0, alice_id, bob_id) = build_pair();
        let mut alice = alice0;
        let mut bob = bob0;
        let msgs: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("msg {}", i).into_bytes())
            .collect();

        for (i, m) in msgs.iter().enumerate() {
            let enc = encrypt(&alice, m, &alice_id, 42).unwrap();
            alice = enc.session_json;
            let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id).unwrap();
            bob = dec.session_json;
            assert_eq!(&dec.plaintext, m);

            // Verify counter increments
            let rec: SessionRecord = session::deserialize(&alice).unwrap();
            let entry = rec.sessions.values().next().unwrap();
            let chain = entry.chains.values().find(|c| c.is_sending()).unwrap();
            assert_eq!(chain.chainKey.counter, i as i64);
        }
    }

    #[test]
    fn test_tamper_fails() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"integrity check";

        let enc = encrypt(&alice, plaintext, &alice_id, 42).unwrap();
        let mut tampered = enc.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let result = decrypt_whisper(&bob, &tampered, &bob_id);
        match result {
            Ok(_) => panic!("tampered message must fail"),
            Err(err) => assert!(
                err.contains("MAC") || err.contains("ciphertext"),
                "expected MAC or ciphertext error, got: {}",
                err
            ),
        }
    }

    // Decode a wire message the way decrypt_whisper does, so a test can drive
    // decrypt_entry with an arbitrary MAC.
    fn split_wire(ciphertext: &[u8]) -> (proto::WhisperMessage, Vec<u8>, Vec<u8>) {
        let msg_buf = ciphertext[1..ciphertext.len() - 8].to_vec();
        let mac_bytes = ciphertext[ciphertext.len() - 8..].to_vec();
        let msg = proto::decode_whisper(&msg_buf).unwrap();
        (msg, msg_buf, mac_bytes)
    }

    #[test]
    fn bad_mac_leaves_the_record_untouched() {
        // The record mutation (ratchet step + message-key consumption) happens
        // before the MAC is checked, so a forged message could advance the chain
        // and burn a key that a later retry of the *same* message would need.
        // The record must come back out of a failed decrypt bit for bit as it
        // went in.
        let (alice, bob, alice_id, bob_id) = build_pair();
        let enc = encrypt(&alice, b"transactional", &alice_id, 42).unwrap();

        let mut tampered = enc.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let (msg, msg_buf, mac_bytes) = split_wire(&tampered);

        let mut record: SessionRecord = session::deserialize(&bob).unwrap();
        let before = session::serialize(&record).unwrap();
        {
            let entry = session::current_session_mut(&mut record).unwrap();
            let err = match decrypt_entry(entry, &msg, &msg_buf, &mac_bytes, &bob_id) {
                Ok(_) => panic!("a forged MAC must not decrypt"),
                Err(e) => e,
            };
            assert!(err.contains("MAC"), "expected MAC failure, got: {}", err);
        }
        assert_eq!(
            before,
            session::serialize(&record).unwrap(),
            "a MAC failure must not advance the receiving chain or consume a message key"
        );
    }

    #[test]
    fn bad_mac_does_not_step_the_ratchet() {
        // Same invariant on the other branch: an unknown remote ephemeral key
        // makes decrypt perform a DH ratchet step, which swaps the ephemeral
        // keypair, rewrites the root key and installs a fresh sending chain. A
        // forged message must not be able to do that.
        let (_, bob, _, bob_id) = build_pair();

        let (remote_pub, _) = curve::generate_keypair(&[0x9Au8; 32]).unwrap();
        let mut eph = vec![0x05u8];
        eph.extend_from_slice(&remote_pub);
        let msg = proto::WhisperMessage {
            ephemeral_key: eph,
            counter: 0,
            previous_counter: 0,
            ciphertext: vec![0u8; 32],
        };
        let msg_buf = proto::encode_whisper(&msg).unwrap();
        let mac_bytes = vec![0u8; 8]; // deliberately wrong MAC

        let mut record: SessionRecord = session::deserialize(&bob).unwrap();
        let before = session::serialize(&record).unwrap();
        {
            let entry = session::current_session_mut(&mut record).unwrap();
            let err = match decrypt_entry(entry, &msg, &msg_buf, &mac_bytes, &bob_id) {
                Ok(_) => panic!("a forged MAC must not decrypt"),
                Err(e) => e,
            };
            assert!(err.contains("MAC"), "expected MAC failure, got: {}", err);
        }
        assert_eq!(
            before,
            session::serialize(&record).unwrap(),
            "a MAC failure must not apply the DH ratchet step"
        );
    }

    #[test]
    fn test_chain_key_advances() {
        let (alice, _, alice_id, bob_id) = build_pair();

        let enc1 = encrypt(&alice, b"first", &alice_id, 42).unwrap();
        let rec1: SessionRecord = session::deserialize(&enc1.session_json).unwrap();
        let e1 = rec1.sessions.values().next().unwrap();
        let c1 = e1.chains.values().find(|c| c.is_sending()).unwrap();
        assert_eq!(c1.chainKey.counter, 0);

        let enc2 = encrypt(&enc1.session_json, b"second", &alice_id, 42).unwrap();
        let rec2: SessionRecord = session::deserialize(&enc2.session_json).unwrap();
        let e2 = rec2.sessions.values().next().unwrap();
        let c2 = e2.chains.values().find(|c| c.is_sending()).unwrap();
        assert_eq!(c2.chainKey.counter, 1);
    }

    #[test]
    fn test_decrypt_pkmsg_with_session() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"pkmsg payload";

let enc = encrypt(&alice, plaintext, &alice_id, 42).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: alice_id.clone(),
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let mut wire = vec![0x33];
        wire.extend_from_slice(&pk_bytes);
        let dec = decrypt_pkmsg(&bob, &wire, &bob_id).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_decrypt_pkmsg_no_session_fails() {
        let (alice, _, alice_id, bob_id) = build_pair();
        let plaintext = b"pkmsg payload";
        let enc = encrypt(&alice, plaintext, &alice_id, 42).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: alice_id,
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let mut wire = vec![0x33];
        wire.extend_from_slice(&pk_bytes);
        let result = decrypt_pkmsg("{}", &wire, &bob_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_then_decrypt_as_self() {
        // Self-session: same identity as both sender and recipient. The record
        // keeps a sending chain (chainType 1) and a mirrored receiving chain
        // (chainType 0) so the SAME session can decrypt its own output.
        let sk = [0x42u8; 32];
        let identity = identity_keypair(&sk);
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let params = x3dh::X3dhParams {
            identity_priv: &sk,
            identity_pub: &identity,
            signed_prekey_pub: &spk,
            signed_prekey_sig: &sig,
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: &identity,
            recipient_prekey: &spk,
            registration_id: 42,
            signed_key_id: 1,
        };
        let fixed_eph = [0x55u8; 32];
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let mut record = session::deserialize(&alice).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        entry.pendingPreKey = None; // bare-ratchet self test (no type-3 wrap)
        let eph_pub = entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
        let send_chain = entry.chains.remove(&eph_pub).unwrap();
        let recv_chain = Chain {
            chainKey: send_chain.chainKey.clone(),
            chainType: RECEIVING,
            messageKeys: BTreeMap::new(),
        };
        entry.chains.insert(eph_pub.clone() + ":send", send_chain);
        entry.chains.insert(eph_pub, recv_chain);
        let self_session = session::serialize(&record).unwrap();

        let plaintext = b"self roundtrip";
        let enc = encrypt(&self_session, plaintext, &identity, 42).unwrap();
        let dec = decrypt_whisper(&self_session, &enc.ciphertext, &identity).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_full_x3dh_roundtrip_with_recipient_session() {
        // Alice initiates X3DH, Bob builds session as recipient from the wire
        // message. Alice's first message is type-3 (pendingPreKey set). Bob
        // decrypts it (sending chain created by ratchet step) and replies.
        let (alice, bob, alice_id, bob_id) = build_handshake(None);

        // Alice's first message → type 3 (PreKeyWhisperMessage).
        let enc1 = encrypt(&alice, b"first", &alice_id, 42).unwrap();
        assert_eq!(enc1.message_type, 3, "first message wraps as PKMsg");
        assert_eq!(enc1.ciphertext[0], 0x33);

        // Bob decrypts the PKMsg directly (enc1.ciphertext is [0x33] || pkmsg).
        let dec1 = decrypt_pkmsg(&bob, &enc1.ciphertext, &bob_id).unwrap();
        assert_eq!(dec1.plaintext, b"first");

        // Bob's session now has a sending chain (created by ratchet step).
        let bob_rec: SessionRecord = session::deserialize(&dec1.session_json).unwrap();
        let bob_entry = bob_rec.sessions.values().next().unwrap();
        assert!(
            bob_entry.chains.values().any(|c| c.is_sending()),
            "recipient must have a sending chain after first decrypt"
        );
        // And a receiving chain.
        assert!(
            bob_entry.chains.values().any(|c| c.is_receiving()),
            "recipient must have a receiving chain after first decrypt"
        );

        // Bob replies → type 1 (no pendingPreKey on recipient).
        let enc2 = encrypt(&dec1.session_json, b"reply", &bob_id, 42).unwrap();
        assert_eq!(enc2.message_type, 1, "recipient reply is plain WhisperMessage");

        // Alice decrypts the reply — her pendingPreKey is now cleared.
        let dec2 = decrypt_whisper(&enc1.session_json, &enc2.ciphertext, &alice_id).unwrap();
        assert_eq!(dec2.plaintext, b"reply");
        let alice_rec: SessionRecord = session::deserialize(&dec2.session_json).unwrap();
        let alice_entry = alice_rec.sessions.values().next().unwrap();
        assert!(alice_entry.pendingPreKey.is_none(), "pendingPreKey cleared on decrypt");
    }

    #[test]
    fn test_full_x3dh_roundtrip_with_one_time_prekey() {
        // Same as above, but Alice uses Bob's one-time prekey (DH4 in X3DH).
        let opk_priv = [0x99u8; 32];
        let (alice, bob, alice_id, bob_id) = build_handshake(Some(opk_priv));

        let enc1 = encrypt(&alice, b"opk first", &alice_id, 42).unwrap();
        assert_eq!(enc1.message_type, 3);
        let dec1 = decrypt_pkmsg(&bob, &enc1.ciphertext, &bob_id).unwrap();
        assert_eq!(dec1.plaintext, b"opk first");

        let enc2 = encrypt(&dec1.session_json, b"opk reply", &bob_id, 42).unwrap();
        let dec2 = decrypt_whisper(&enc1.session_json, &enc2.ciphertext, &alice_id).unwrap();
        assert_eq!(dec2.plaintext, b"opk reply");
    }

    // Build Alice (initiator) + Bob (recipient) sessions via real X3DH paths.
    // Returns (alice, bob, alice_id, bob_id).
    fn build_handshake(opk_priv: Option<[u8; 32]>) -> (String, String, Vec<u8>, Vec<u8>) {
        let alice_sk = [0x42u8; 32];
        let bob_sk = [0x77u8; 32];
        let (alice_pk32, _) = curve::generate_keypair(&alice_sk).unwrap();
        let (bob_pk32, bob_sk2) = curve::generate_keypair(&bob_sk).unwrap();
        let mut alice_id = vec![0x05u8];
        alice_id.extend_from_slice(&alice_pk32);
        let mut bob_id = vec![0x05u8];
        bob_id.extend_from_slice(&bob_pk32);

        let spk_priv = [0x43u8; 32];
        let (spk_pub, _) = curve::generate_keypair(&spk_priv).unwrap();
        let sig = curve::sign(&bob_sk, &spk_pub, None).unwrap();

        let fixed_eph = [0x55u8; 32];
        let (eph_pub, _) = curve::generate_keypair(&fixed_eph).unwrap();

        // One-time prekey (optional).
        let opk_seed = [0x99u8; 32];
        let (opk_pub, _) = curve::generate_keypair(&opk_seed).unwrap();
        let use_opk = opk_priv.is_some();

        let params = x3dh::X3dhParams {
            identity_priv: &alice_sk,
            identity_pub: &alice_id,
            signed_prekey_pub: &spk_pub,
            signed_prekey_sig: &sig,
            prekey_pub: if use_opk { Some(&opk_pub) } else { None },
            prekey_id: if use_opk { Some(7) } else { None },
            recipient_pub: &bob_id,
            recipient_prekey: &spk_pub,
            registration_id: 42,
            signed_key_id: 4,
        };
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let bob = x3dh::build_recipient_session(
            &bob_sk2,
            &spk_priv,
            &spk_pub,
            if use_opk { Some(&opk_seed) } else { None },
            &alice_id,
            &eph_pub,
            42,
        )
        .unwrap();
        (alice, bob, alice_id, bob_id)
    }
}
