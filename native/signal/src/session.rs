#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

// `Zeroize`/`ZeroizeOnDrop` scrub the record's key material — root key, ratchet
// private key, chain keys, every derived message key — when it is released.
// Public fields (keys already in the clear, counters, indices, identifiers) are
// `#[zeroize(skip)]`: there is nothing to scrub and skipping keeps the
// derivation free of bounds on types that carry no secret.
//
// `zeroize` implements no `BTreeMap` impl, and the map field types cannot become
// a wrapper because the ratchet and x3dh modules construct them as `BTreeMap`
// directly, so the three structs holding a secret map carry hand-written impls
// that walk it; everything else derives.

fn zeroize_map<K, V: Zeroize>(map: &mut BTreeMap<K, V>) {
    for value in map.values_mut() {
        value.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    #[serde(rename = "_sessions", default)]
    pub sessions: BTreeMap<String, SessionEntry>,
    #[serde(default = "default_version")]
    pub version: String,
}

impl Zeroize for SessionRecord {
    fn zeroize(&mut self) {
        zeroize_map(&mut self.sessions);
    }
}

impl ZeroizeOnDrop for SessionRecord {}

impl Drop for SessionRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionEntry {
    pub registrationId: u32,
    pub currentRatchet: Ratchet,
    pub indexInfo: IndexInfo,
    #[serde(rename = "_chains")]
    pub chains: BTreeMap<String, Chain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pendingPreKey: Option<PendingPreKey>,
}

impl Zeroize for SessionEntry {
    fn zeroize(&mut self) {
        self.currentRatchet.zeroize();
        zeroize_map(&mut self.chains);
    }
}

impl ZeroizeOnDrop for SessionEntry {}

impl Drop for SessionEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Ratchet {
    pub ephemeralKeyPair: KeyPair,
    #[zeroize(skip)]
    pub lastRemoteEphemeralKey: String,
    #[zeroize(skip)]
    pub previousCounter: u32,
    pub rootKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub pubKey: String,
    pub privKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndexInfo {
    pub baseKey: String,
    pub baseKeyType: u32,
    pub closed: i64,
    pub used: i64,
    pub created: i64,
    pub remoteIdentityKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub chainKey: ChainKey,
    pub chainType: u32,
    pub messageKeys: BTreeMap<i64, String>,
}

impl Zeroize for Chain {
    fn zeroize(&mut self) {
        self.chainKey.zeroize();
        for value in self.messageKeys.values_mut() {
            value.zeroize();
        }
    }
}

impl ZeroizeOnDrop for Chain {}

impl Drop for Chain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ChainKey {
    #[zeroize(skip)]
    pub counter: i64,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PendingPreKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signedKeyId: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preKeyId: Option<u32>,
    pub baseKey: String,
}

fn default_version() -> String {
    "v1".to_string()
}

// Parse without validating, for callers that want the raw projection.
// serde reads a struct from a JSON array positionally and both SessionRecord
// fields are `default`, so "[]" used to yield an empty record with no error —
// a silent state reset. Require a JSON object before handing it to serde.
pub fn parse(json: &str) -> Result<SessionRecord, String> {
    if !json.trim_start().starts_with('{') {
        return Err("session record must be a JSON object".to_string());
    }
    serde_json::from_str(json).map_err(|e| e.to_string())
}

// `deny_unknown_fields` already refuses an unmodelled field at any level. This
// refuses the other way state can be unrecognised: a record that labels itself
// with a version this build does not model, which would otherwise be used as
// though it were v1.
pub fn validate(record: &SessionRecord) -> Result<(), String> {
    if record.version != "v1" {
        return Err(format!(
            "unsupported session record version {:?}, this build reads only \"v1\"",
            record.version
        ));
    }
    Ok(())
}

pub fn deserialize(json: &str) -> Result<SessionRecord, String> {
    let record = parse(json)?;
    validate(&record)?;
    Ok(record)
}

pub fn serialize(record: &SessionRecord) -> Result<String, String> {
    serde_json::to_string(record).map_err(|e| e.to_string())
}

pub fn have_open_session(record: &SessionRecord) -> bool {
    record.sessions.values().any(|s| s.indexInfo.closed == -1)
}

/// Select the ACTIVE session entry for encrypt/decrypt — mirrors libsignal
/// `getOpenSession()` semantics: prefer the entry with `closed == -1`; among
/// multiple open entries (shouldn't happen, but be robust) pick the most
/// recently `used`. Fallback: the entry with the highest `used` (newest
/// archived) so legacy single-entry and migrated records keep working.
/// Returns `None` only when the record is empty.
pub fn current_session_mut(record: &mut SessionRecord) -> Option<&mut SessionEntry> {
    if record.sessions.is_empty() {
        return None;
    }
    // Fast path: exactly one entry (the overwhelmingly common case).
    if record.sessions.len() == 1 {
        return record.sessions.values_mut().next();
    }
    let best_key = record
        .sessions
        .iter()
        .max_by_key(|(_, s)| {
            let open = s.indexInfo.closed == -1;
            (open, s.indexInfo.used)
        })
        .map(|(k, _)| k.clone())?;
    record.sessions.get_mut(&best_key)
}

pub fn archive_current(record: &mut SessionRecord) -> Result<(), String> {
    for session in record.sessions.values_mut() {
        if session.indexInfo.closed == -1 {
            session.indexInfo.closed = 1;
            return Ok(());
        }
    }
    Err("no open session to archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    const FIXTURE: &str = include_str!("../../../fixtures/libsignal-session.json");

    #[test]
    fn session_secrets_are_zeroized() {
        // Compile-time assertion: the structs carrying the root key, the
        // ratchet private key, the chain keys and every derived message key
        // must scrub themselves on drop, so a record the ratchet releases does
        // not leave key material behind in the heap. Zeroization is a drop-time
        // property with no runtime observable, hence the trait bound on each
        // secret-carrying type rather than a value assertion.
        fn zeroizes_on_drop<T: Zeroize + ZeroizeOnDrop>(_v: &T) {}
        let record = deserialize(FIXTURE).unwrap();
        zeroizes_on_drop(&record);
        let entry = record.sessions.values().next().unwrap();
        zeroizes_on_drop(entry);
        zeroizes_on_drop(&entry.currentRatchet);
        zeroizes_on_drop(&entry.currentRatchet.ephemeralKeyPair);
        let chain = entry.chains.values().next().unwrap();
        zeroizes_on_drop(chain);
        zeroizes_on_drop(&chain.chainKey);
    }

    #[test]
    fn test_fixture_deserialize() {
        let record = deserialize(FIXTURE).unwrap();
        assert_eq!(record.version, "v1");
        assert_eq!(record.sessions.len(), 1);
        let entry = record.sessions.values().next().unwrap();
        assert_eq!(entry.registrationId, 42);
        assert_eq!(entry.indexInfo.closed, -1);
        assert_eq!(entry.indexInfo.used, 1788180594198);
        assert_eq!(entry.indexInfo.created, 1788180594198);
        assert_eq!(entry.currentRatchet.previousCounter, 0);
        assert_eq!(entry.chains.len(), 1);
        let chain = entry.chains.values().next().unwrap();
        assert_eq!(chain.chainKey.counter, -1);
        assert!(chain.messageKeys.is_empty());
        assert!(entry.pendingPreKey.is_some());
    }

    #[test]
    fn test_fixture_roundtrip_semantic() {
        let v1: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let record = deserialize(FIXTURE).unwrap();
        let serialized = serialize(&record).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(v1, v2, "semantic roundtrip: values must match");
    }

    #[test]
    fn test_have_open_session_on_fixture() {
        let record = deserialize(FIXTURE).unwrap();
        assert!(have_open_session(&record), "fixture session is fresh (closed=-1)");
    }

    #[test]
    fn test_archive_current_closes_session() {
        let mut record = deserialize(FIXTURE).unwrap();
        assert!(have_open_session(&record));
        archive_current(&mut record).unwrap();
        assert!(!have_open_session(&record), "after archive, no open session");
    }

    #[test]
    fn test_empty_session_record() {
        let record = deserialize("{}").unwrap();
        assert!(record.sessions.is_empty());
        assert_eq!(record.version, "v1");
        assert!(!have_open_session(&record));
    }

    #[test]
    fn test_archive_on_empty_fails() {
        let mut record = deserialize("{}").unwrap();
        let result = archive_current(&mut record);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_sessions_archive_one() {
        let mut record = deserialize(FIXTURE).unwrap();
        let base_key = record.sessions.keys().next().unwrap().clone();
        archive_current(&mut record).unwrap();
        assert!(!have_open_session(&record));
        let entry = record.sessions.get(&base_key).unwrap();
        assert_eq!(entry.indexInfo.closed, 1);
    }

    #[test]
    fn test_serialize_reparse_matches() {
        let record = deserialize(FIXTURE).unwrap();
        let json = serialize(&record).unwrap();
        let record2 = deserialize(&json).unwrap();
        assert_eq!(record, record2);
    }

    // --- strict parse ---

    // Round-trip the fixture through a serde_json::Value so an unmodelled field
    // can be injected at each level, and assert it is refused. Silently
    // dropping it destroys session state that the next write persists.
    // A `serde_json::Value` string index is a literal key, not a path, so the
    // walk is explicit. `{entry}` and `{chain}` resolve to the fixture's keys.
    fn with_injected(path: &[&str], key: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let entry = v["_sessions"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let chain = v["_sessions"][&entry]["_chains"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let path: Vec<String> = path
            .iter()
            .map(|s| s.replace("{entry}", &entry).replace("{chain}", &chain))
            .chain(std::iter::once(key.to_string()))
            .collect();
        let (last, parents) = path.split_last().unwrap();
        let mut cur = &mut v;
        for seg in parents {
            cur = cur
                .as_object_mut()
                .unwrap()
                .entry(seg.clone())
                .or_insert_with(|| serde_json::json!({}));
        }
        cur.as_object_mut()
            .unwrap()
            .insert(last.clone(), serde_json::json!("unmodelled"));
        v.to_string()
    }

    #[test]
    fn unmodelled_top_level_field_is_rejected() {
        let err = deserialize(&with_injected(&[], "futureField")).unwrap_err();
        assert!(
            err.contains("futureField"),
            "an unmodelled top-level field must be named, got: {}",
            err
        );
    }

    #[test]
    fn unmodelled_entry_field_is_rejected() {
        let err = deserialize(&with_injected(&["_sessions", "{entry}"], "futureField")).unwrap_err();
        assert!(
            err.contains("futureField"),
            "an unmodelled session-entry field must be named, got: {}",
            err
        );
    }

    #[test]
    fn unmodelled_chain_field_is_rejected() {
        let json = with_injected(&["_sessions", "{entry}", "_chains", "{chain}"], "futureField");
        let err = deserialize(&json).unwrap_err();
        assert!(
            err.contains("futureField"),
            "an unmodelled chain field must be named, got: {}",
            err
        );
    }

    #[test]
    fn unmodelled_pending_pre_key_field_is_rejected() {
        let json = with_injected(&["_sessions", "{entry}", "pendingPreKey"], "extraKey");
        let err = deserialize(&json).unwrap_err();
        assert!(
            err.contains("extraKey"),
            "an unmodelled pendingPreKey field must be named, got: {}",
            err
        );
    }

    #[test]
    fn unmodelled_ratchet_field_is_rejected() {
        let json = with_injected(&["_sessions", "{entry}", "currentRatchet"], "futureRatchetField");
        let err = deserialize(&json).unwrap_err();
        assert!(
            err.contains("futureRatchetField"),
            "an unmodelled currentRatchet field must be named, got: {}",
            err
        );
    }

    #[test]
    fn unmodelled_field_is_rejected_at_every_level() {
        // The parse must not merely refuse the top level: an unmodelled field
        // nested inside an entry, a chain or pendingPreKey is the same loss.
        for path in [
            vec!["_sessions", "{entry}"],
            vec!["_sessions", "{entry}", "_chains", "{chain}"],
            vec!["_sessions", "{entry}", "currentRatchet"],
            vec!["_sessions", "{entry}", "pendingPreKey"],
        ] {
            let json = with_injected(&path, "futureField");
            assert!(
                deserialize(&json).is_err(),
                "an unmodelled futureField at {} must be rejected",
                path.join(".")
            );
        }
    }

    #[test]
    fn unmodelled_version_is_rejected() {
        let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        v["version"] = serde_json::json!("v2");
        let err = deserialize(&v.to_string()).unwrap_err();
        assert!(
            err.contains("version"),
            "a version this build does not model must be named, got: {}",
            err
        );
    }

    #[test]
    fn missing_version_still_defaults_to_v1() {
        let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        v.as_object_mut().unwrap().remove("version");
        let record = deserialize(&v.to_string()).unwrap();
        assert_eq!(record.version, "v1");
    }

    #[test]
    fn non_object_session_json_is_rejected() {
        // serde reads a struct from a JSON array positionally, and both
        // SessionRecord fields are `default`, so "[]" filled both of them and
        // produced an empty record with no error — a silent state reset.
        for input in ["[]", "[ ]", "[\"v1\"]", "[1, 2, 3]", "  []  "] {
            assert!(
                parse(input).is_err(),
                "{} must not parse as a session record",
                input
            );
        }
    }

    #[test]
    fn an_object_is_still_parsed() {
        let record = parse(r#"{"version":"v1"}"#).unwrap();
        assert_eq!(record.version, "v1");
        assert!(record.sessions.is_empty());
    }
}
