#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionRecord {
    #[serde(rename = "_sessions", default)]
    pub sessions: BTreeMap<String, SessionEntry>,
    #[serde(default = "default_version")]
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionEntry {
    pub registrationId: u32,
    pub currentRatchet: Ratchet,
    pub indexInfo: IndexInfo,
    #[serde(rename = "_chains")]
    pub chains: BTreeMap<String, Chain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pendingPreKey: Option<PendingPreKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Ratchet {
    pub ephemeralKeyPair: KeyPair,
    pub lastRemoteEphemeralKey: String,
    pub previousCounter: u32,
    pub rootKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyPair {
    pub pubKey: String,
    pub privKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IndexInfo {
    pub baseKey: String,
    pub baseKeyType: u32,
    pub closed: i64,
    pub used: i64,
    pub created: i64,
    pub remoteIdentityKey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Chain {
    pub chainKey: ChainKey,
    pub chainType: u32,
    pub messageKeys: BTreeMap<i64, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChainKey {
    pub counter: i64,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PendingPreKey {
    pub baseKey: String,
}

fn default_version() -> String {
    "v1".to_string()
}

pub fn deserialize(json: &str) -> Result<SessionRecord, String> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

pub fn serialize(record: &SessionRecord) -> Result<String, String> {
    serde_json::to_string(record).map_err(|e| e.to_string())
}

pub fn have_open_session(record: &SessionRecord) -> bool {
    record.sessions.values().any(|s| s.indexInfo.closed == -1)
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

    const FIXTURE: &str = include_str!("../../../fixtures/libsignal-session.json");

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
}