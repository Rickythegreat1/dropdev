//! Strict bounded proposals. TLS authenticates peers; these digests identify
//! exact proposal bytes for durable ordering, review and retry receipts only.
use crate::{
    pairing::{hash, is_hash, validate_path, Paired, Scope},
    PeerError, PeerResult,
};
use devdrop_core::file_permissions::FilePermissions;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, fmt};

pub const VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_DATA_BYTES: usize = 16 * 1024;
pub const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Put {
        path: String,
        hash: String,
        bytes: Vec<u8>,
        #[serde(deserialize_with = "strict_permissions")]
        permissions: FilePermissions,
    },
    Delete {
        path: String,
        previous_hash: String,
    },
}
impl Change {
    pub fn path(&self) -> &str {
        match self {
            Self::Put { path, .. } | Self::Delete { path, .. } => path,
        }
    }
}
impl fmt::Debug for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put { bytes, .. } => f
                .debug_struct("Put")
                .field("bytes_count", &bytes.len())
                .finish_non_exhaustive(),
            Self::Delete { .. } => f.write_str("Delete { path: [REDACTED] }"),
        }
    }
}
fn strict_permissions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<FilePermissions, D::Error> {
    #[derive(Deserialize)]
    #[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
    enum Strict {
        Unix { mode: u32 },
        Windows { readonly: bool },
    }
    Ok(match Strict::deserialize(deserializer)? {
        Strict::Unix { mode } => FilePermissions::Unix { mode },
        Strict::Windows { readonly } => FilePermissions::Windows { readonly },
    })
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub pairing_id: String,
    pub sender_fingerprint: String,
    pub receiver_fingerprint: String,
    pub channel: String,
    pub sequence: u64,
    pub previous_digest: String,
    pub changes: Vec<Change>,
}
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &self.version)
            .field("pairing_id", &self.pairing_id)
            .field("sequence", &self.sequence)
            .field("changes_count", &self.changes.len())
            .finish_non_exhaustive()
    }
}
impl Envelope {
    pub fn new(
        pair: &Paired,
        sequence: u64,
        previous_digest: &str,
        changes: Vec<Change>,
    ) -> PeerResult<Self> {
        let envelope = Self {
            version: VERSION,
            pairing_id: pair.id().into(),
            sender_fingerprint: pair.local_fingerprint().into(),
            receiver_fingerprint: pair.remote_fingerprint().into(),
            channel: pair.scope().channel.clone(),
            sequence,
            previous_digest: previous_digest.into(),
            changes,
        };
        envelope.validate_outgoing(pair)?;
        Ok(envelope)
    }
    pub fn encoded_len(&self) -> PeerResult<usize> {
        Ok(self.encode()?.len())
    }
    pub fn payload_bytes(&self) -> usize {
        self.changes
            .iter()
            .map(|change| match change {
                Change::Put { bytes, .. } => bytes.len(),
                Change::Delete { .. } => 0,
            })
            .sum()
    }
    pub(crate) fn encode(&self) -> PeerResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| PeerError("Proposal encoding failed."))
    }
    pub fn digest(&self) -> PeerResult<String> {
        Ok(hash(&self.encode()?))
    }
    pub fn validate_incoming(&self, pair: &Paired) -> PeerResult<()> {
        self.validate(pair, pair.remote_fingerprint(), pair.local_fingerprint())
    }
    pub fn validate_outgoing(&self, pair: &Paired) -> PeerResult<()> {
        self.validate(pair, pair.local_fingerprint(), pair.remote_fingerprint())
    }
    fn validate(&self, pair: &Paired, sender: &str, receiver: &str) -> PeerResult<()> {
        pair.ensure_active()?;
        self.validate_stored(pair.id(), pair.scope(), sender, receiver)
    }
    /// Local-only revalidation of an already admitted queue entry. This does
    /// not grant network admission or require an expired RAM identity to survive.
    pub(crate) fn validate_stored(
        &self,
        pairing_id: &str,
        scope: &Scope,
        sender: &str,
        receiver: &str,
    ) -> PeerResult<()> {
        scope.validate()?;
        if !is_hash(pairing_id) || !is_hash(sender) || !is_hash(receiver) || sender == receiver {
            return Err(PeerError("Stored proposal identity context is invalid."));
        }
        if self.version != VERSION
            || self.pairing_id != pairing_id
            || self.sender_fingerprint != sender
            || self.receiver_fingerprint != receiver
            || self.channel != scope.channel
        {
            return Err(PeerError(
                "Proposal is outside the approved pairing context.",
            ));
        }
        if self.sequence == 0
            || self.sequence > u64::from(scope.max_messages)
            || !is_hash(&self.previous_digest)
            || (self.sequence == 1 && self.previous_digest != ZERO_DIGEST)
        {
            return Err(PeerError(
                "Invalid proposal sequence or predecessor digest.",
            ));
        }
        if self.changes.is_empty()
            || self.changes.len() > scope.paths.len()
            || self.payload_bytes() > MAX_DATA_BYTES
        {
            return Err(PeerError("Proposal exceeds change or data limits."));
        }
        let mut unique = BTreeSet::new();
        for change in &self.changes {
            validate_path(change.path())?;
            if !scope.paths.contains(change.path())
                || !unique.insert(change.path().to_ascii_lowercase())
            {
                return Err(PeerError(
                    "Proposal contains unapproved or duplicate paths.",
                ));
            }
            match change {
                Change::Put {
                    hash: expected,
                    bytes,
                    permissions,
                    ..
                } => {
                    if !is_hash(expected) || *expected != hash(bytes) || secret_content(bytes) {
                        return Err(PeerError(
                            "Proposal content hash or non-secret policy check failed.",
                        ));
                    }
                    match permissions {
                        #[cfg(unix)]
                        FilePermissions::Unix { mode } if *mode <= 0o777 => {}
                        #[cfg(windows)]
                        FilePermissions::Windows { .. } => {}
                        _ => {
                            return Err(PeerError(
                                "Unsupported or mismatched operating-system permissions.",
                            ))
                        }
                    }
                }
                Change::Delete { previous_hash, .. } => {
                    if !scope.allow_delete || !is_hash(previous_hash) {
                        return Err(PeerError("Delete intent is outside the approved scope."));
                    }
                }
            }
        }
        if self.encoded_len()? > scope.max_bytes_per_proposal as usize
            || self.encoded_len()? > 32 * 1024
        {
            return Err(PeerError("Canonical proposal exceeds approved byte limit."));
        }
        Ok(())
    }
}
fn secret_content(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
        || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| {
                (word.starts_with("AKIA") && word.len() == 20)
                    || (word.starts_with("ghp_") && word.len() >= 36)
                    || (word.starts_with("github_pat_") && word.len() > 30)
            })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Queued,
    Duplicate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub pairing_id: String,
    pub sequence: u64,
    pub digest: String,
    pub status: ReceiptStatus,
    pub pending_count: u32,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::pairing::tests::pair;
    pub fn permissions() -> FilePermissions {
        #[cfg(unix)]
        {
            FilePermissions::Unix { mode: 0o644 }
        }
        #[cfg(windows)]
        {
            FilePermissions::Windows { readonly: false }
        }
    }
    pub fn put(bytes: &[u8]) -> Change {
        Change::Put {
            path: "src/shared.txt".into(),
            hash: hash(bytes),
            bytes: bytes.to_vec(),
            permissions: permissions(),
        }
    }
    #[test]
    fn bounded_proposals_context_hash_scope_and_redaction() {
        let (a, b) = pair();
        let valid =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"disposable payload canary")]).unwrap();
        assert!(valid.validate_incoming(&b).is_ok());
        assert!(valid.validate_incoming(&a).is_err());
        let mut tampered = valid.clone();
        if let Change::Put { bytes, .. } = &mut tampered.changes[0] {
            bytes.push(0);
        }
        assert!(tampered.validate_outgoing(&a).is_err());
        let mut duplicate = valid.clone();
        duplicate.changes.push(duplicate.changes[0].clone());
        assert!(duplicate.validate_outgoing(&a).is_err());
        assert!(!format!("{valid:?}").contains("disposable payload canary"));
        assert!(!format!("{:?}", valid.changes[0]).contains("disposable payload canary"));
        assert!(
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(&vec![0; MAX_DATA_BYTES + 1])]).is_err()
        );
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["apply"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Envelope>(unknown).is_err());
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["changes"][0]["permissions"]["acl"] = serde_json::json!("PRIVATE_METADATA_CANARY");
        assert!(serde_json::from_value::<Envelope>(unknown).is_err());
    }
    #[test]
    fn secret_special_and_foreign_permission_fields_fail_closed() {
        let (a, _) = pair();
        assert!(Envelope::new(
            &a,
            1,
            ZERO_DIGEST,
            vec![put(b"-----BEGIN PRIVATE KEY-----")]
        )
        .is_err());
        assert!(Envelope::new(
            &a,
            1,
            ZERO_DIGEST,
            vec![put(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")]
        )
        .is_err());
        let mut change = put(b"fixture");
        if let Change::Put { permissions, .. } = &mut change {
            #[cfg(unix)]
            {
                *permissions = FilePermissions::Unix { mode: 0o4755 };
            }
            #[cfg(windows)]
            {
                *permissions = FilePermissions::Unix { mode: 0o644 };
            }
        }
        assert!(Envelope::new(&a, 1, ZERO_DIGEST, vec![change]).is_err());
        #[cfg(unix)]
        {
            let mut change = put(b"fixture");
            if let Change::Put { permissions, .. } = &mut change {
                *permissions = FilePermissions::Windows { readonly: false };
            }
            assert!(Envelope::new(&a, 1, ZERO_DIGEST, vec![change]).is_err());
        }
    }
}
