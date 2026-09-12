#![deny(unsafe_code)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

pub mod curve;
pub mod proto;
pub mod session;
pub mod util;
pub mod x3dh;
pub mod ratchet;

// ── curve ──

#[napi]
pub fn curve_sign(secret_key: Buffer, message: Buffer, random: Option<Buffer>) -> Result<Buffer> {
    let sig = curve::sign(
        secret_key.as_ref(),
        message.as_ref(),
        random.as_deref().map(|b| b.as_ref()),
    )
    .map_err(|e| Error::from_reason(e))?;
    Ok(Buffer::from(&sig[..]))
}

#[napi]
pub fn curve_verify(public_key: Buffer, message: Buffer, signature: Buffer) -> Result<bool> {
    curve::verify(public_key.as_ref(), message.as_ref(), signature.as_ref())
        .map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn curve_scalar_multiply(secret_key: Buffer, public_key: Buffer) -> Result<Buffer> {
    let result = curve::scalar_multiply(secret_key.as_ref(), public_key.as_ref())
        .map_err(|e| Error::from_reason(e))?;
    Ok(Buffer::from(&result[..]))
}

#[napi]
pub fn curve_generate_keypair(seed: Buffer) -> Result<Vec<Buffer>> {
    let (pub_key, priv_key) = curve::generate_keypair(seed.as_ref())
        .map_err(|e| Error::from_reason(e))?;
    Ok(vec![Buffer::from(&pub_key[..]), Buffer::from(&priv_key[..])])
}

// ── proto ──

// Decoded results cross the boundary as napi objects with Buffer fields:
// no JSON string round-trip, no byte-array→number→Buffer copies on JS side.
#[napi(object)]
pub struct WhisperMessageObj {
    pub ephemeral_key: Buffer,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Buffer,
}

#[napi(object)]
pub struct PkmsgObj {
    pub pre_key_id: Option<u32>,
    pub base_key: Buffer,
    pub identity_key: Buffer,
    pub message: Buffer,
    pub registration_id: u32,
    pub signed_pre_key_id: Option<u32>,
}

#[napi]
pub fn proto_encode_whisper(
    ephemeral_key: Buffer,
    counter: u32,
    previous_counter: u32,
    ciphertext: Buffer,
) -> Result<Buffer> {
    let msg = proto::WhisperMessage {
        ephemeral_key: ephemeral_key.to_vec(),
        counter,
        previous_counter,
        ciphertext: ciphertext.to_vec(),
    };
    let encoded = proto::encode_whisper(&msg).map_err(|e| Error::from_reason(e))?;
    Ok(Buffer::from(encoded))
}

#[napi]
pub fn proto_decode_whisper(bytes: Buffer) -> Result<WhisperMessageObj> {
    let msg = proto::decode_whisper(bytes.as_ref()).map_err(|e| Error::from_reason(e))?;
    Ok(WhisperMessageObj {
        ephemeral_key: Buffer::from(msg.ephemeral_key),
        counter: msg.counter,
        previous_counter: msg.previous_counter,
        ciphertext: Buffer::from(msg.ciphertext),
    })
}

#[napi]
pub fn proto_encode_pkmsg(json: String) -> Result<Buffer> {
    let msg: proto::PreKeyWhisperMessage = serde_json::from_str(&json)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let encoded = proto::encode_pkmsg(&msg).map_err(|e| Error::from_reason(e))?;
    Ok(Buffer::from(encoded))
}

#[napi]
pub fn proto_decode_pkmsg(bytes: Buffer) -> Result<PkmsgObj> {
    let msg = proto::decode_pkmsg(bytes.as_ref()).map_err(|e| Error::from_reason(e))?;
    Ok(PkmsgObj {
        pre_key_id: msg.pre_key_id,
        base_key: Buffer::from(msg.base_key),
        identity_key: Buffer::from(msg.identity_key),
        message: Buffer::from(msg.message),
        registration_id: msg.registration_id,
        signed_pre_key_id: msg.signed_pre_key_id,
    })
}

// ── session ──

#[napi]
pub fn session_deserialize(json: String) -> Result<String> {
    let record = session::deserialize(&json).map_err(|e| Error::from_reason(e))?;
    session::serialize(&record).map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn session_serialize(json: String) -> Result<String> {
    let record = session::deserialize(&json).map_err(|e| Error::from_reason(e))?;
    session::serialize(&record).map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn session_have_open_session(json: String) -> Result<bool> {
    let record = session::deserialize(&json).map_err(|e| Error::from_reason(e))?;
    Ok(session::have_open_session(&record))
}

// ── x3dh ──

#[napi]
pub fn x3dh_build_initial_session(
    identity_priv: Buffer,
    identity_pub: Buffer,
    signed_prekey_pub: Buffer,
    signed_prekey_sig: Buffer,
    prekey_pub: Option<Buffer>,
    prekey_id: Option<u32>,
    recipient_pub: Buffer,
    recipient_prekey: Buffer,
    registration_id: u32,
    signed_key_id: u32,
) -> Result<String> {
    let params = x3dh::X3dhParams {
        identity_priv: identity_priv.as_ref(),
        identity_pub: identity_pub.as_ref(),
        signed_prekey_pub: signed_prekey_pub.as_ref(),
        signed_prekey_sig: signed_prekey_sig.as_ref(),
        prekey_pub: prekey_pub.as_ref().map(|b| b.as_ref()),
        prekey_id,
        recipient_pub: recipient_pub.as_ref(),
        recipient_prekey: recipient_prekey.as_ref(),
        registration_id,
        signed_key_id,
    };
    x3dh::build_initial_session(&params).map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn x3dh_build_recipient_session(
    our_identity_priv: Buffer,
    our_signed_prekey_priv: Buffer,
    our_signed_prekey_pub: Buffer,
    our_prekey_priv: Option<Buffer>,
    sender_identity: Buffer,
    sender_ephemeral: Buffer,
    registration_id: u32,
) -> Result<String> {
    x3dh::build_recipient_session(
        our_identity_priv.as_ref(),
        our_signed_prekey_priv.as_ref(),
        our_signed_prekey_pub.as_ref(),
        our_prekey_priv.as_ref().map(|b| b.as_ref()),
        sender_identity.as_ref(),
        sender_ephemeral.as_ref(),
        registration_id,
    )
    .map_err(|e| Error::from_reason(e))
}

// ── ratchet ──

#[napi(object)]
pub struct EncryptResultObj {
    pub session_json: String,
    pub message_type: u8,
    pub ciphertext: Buffer,
}

#[napi(object)]
pub struct DecryptResultObj {
    pub session_json: String,
    pub plaintext: Buffer,
}

#[napi]
pub fn ratchet_encrypt(
    session_json: String,
    plaintext: Buffer,
    our_identity_pub: Buffer,
    our_registration_id: u32,
) -> Result<EncryptResultObj> {
    let result = ratchet::encrypt(
        &session_json,
        plaintext.as_ref(),
        our_identity_pub.as_ref(),
        our_registration_id,
    )
    .map_err(|e| Error::from_reason(e))?;
    Ok(EncryptResultObj {
        session_json: result.session_json,
        message_type: result.message_type,
        ciphertext: Buffer::from(result.ciphertext),
    })
}

#[napi]
pub fn ratchet_decrypt_whisper(
    session_json: String,
    ciphertext: Buffer,
    our_identity_pub: Buffer,
) -> Result<DecryptResultObj> {
    let result = ratchet::decrypt_whisper(
        &session_json,
        ciphertext.as_ref(),
        our_identity_pub.as_ref(),
    )
    .map_err(|e| Error::from_reason(e))?;
    Ok(DecryptResultObj {
        session_json: result.session_json,
        plaintext: Buffer::from(result.plaintext),
    })
}

#[napi]
pub fn ratchet_decrypt_pkmsg(
    session_json: String,
    ciphertext: Buffer,
    our_identity_pub: Buffer,
) -> Result<DecryptResultObj> {
    let result = ratchet::decrypt_pkmsg(
        &session_json,
        ciphertext.as_ref(),
        our_identity_pub.as_ref(),
    )
    .map_err(|e| Error::from_reason(e))?;
    Ok(DecryptResultObj {
        session_json: result.session_json,
        plaintext: Buffer::from(result.plaintext),
    })
}
