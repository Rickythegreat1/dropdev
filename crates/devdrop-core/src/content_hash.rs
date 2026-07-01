use serde::{Deserialize, Serialize};

/// Supported content hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Default MVP content hash algorithm.
    Blake3,
    /// Future-compatible modeled option.
    Sha256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

/// Content hash value for object identity and fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHash {
    /// Hash algorithm used.
    pub algorithm: HashAlgorithm,
    /// Hex digest.
    pub digest: String,
}

impl ContentHash {
    /// Hashes bytes with the default BLAKE3 algorithm.
    pub fn hash_bytes(bytes: &[u8]) -> Self {
        Self {
            algorithm: HashAlgorithm::Blake3,
            digest: blake3::hash(bytes).to_hex().to_string(),
        }
    }
}
