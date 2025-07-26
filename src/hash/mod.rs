//! hash functions
//!
//! crypto hash trait + implementations: blake3, sha256, keccak256
//! use registry to pick algorithms by name at runtime
//!
//! ```rust
//! use sylva::hash::{Hash, Blake3Hasher, HashRegistry};
//!
//! let hasher = Blake3Hasher::new();
//! let data = b"ledger entry data";
//! let hash_output = hasher.hash_bytes(data).unwrap();
//! println!("hash: {}", hash_output.to_hex());
//!
//! let registry = HashRegistry::default();
//! let hasher = registry.get_hasher("sha256").expect("SHA-256 should be available");
//! let hash_output = hasher.hash_bytes(data).unwrap();
//! println!("sha-256 hash: {}", hash_output.to_hex());
//! ```

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod blake3;
pub mod keccak;
pub mod registry;
pub mod sha256;

pub use self::blake3::Blake3Hasher;
pub use self::keccak::KeccakHasher;
pub use self::registry::{HashAlgorithm, HashRegistry};
pub use self::sha256::Sha256Hasher;

/// 32-byte hash output
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashOutput(pub [u8; 32]);

impl HashOutput {
    /// create hash output from 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// create hash output from byte slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(SylvaError::hash_error(format!(
                "Invalid hash length: expected 32, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// get hash as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// convert hash to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// create hash from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex).map_err(|e| SylvaError::hash_error(format!("Invalid hex: {}", e)))?;
        Self::from_slice(&bytes)
    }

    /// create zero hash (all zeros)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::Display for HashOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ledger entry metadata for hashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryHashContext {
    /// unique entry identifier
    pub entry_id: uuid::Uuid,
    /// entry version number
    pub version: u64,
    /// when entry was created
    pub timestamp: u64,
    /// id of previous version if any
    pub previous_id: Option<uuid::Uuid>,
    /// mime type or content type
    pub content_type: Option<String>,
    /// extra key-value metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// hash trait for different crypto hash functions
pub trait Hash: Send + Sync + Clone {
    /// create new hasher instance
    fn new() -> Self;

    /// hash arbitrary bytes
    fn hash_bytes(&self, data: &[u8]) -> Result<HashOutput>;

    // for merkle trees - combines two hashes with domain separation
    /// hash two existing hashes together
    fn hash_pair(&self, left: &HashOutput, right: &HashOutput) -> Result<HashOutput>;

    // hash entry data with metadata for ledger entries
    /// hash entry data with context
    fn hash_entry(&self, data: &[u8], context: &EntryHashContext) -> Result<HashOutput>;

    // hash multiple inputs in one go
    /// hash multiple byte arrays
    fn hash_many(&self, inputs: &[&[u8]]) -> Result<HashOutput> {
        let mut combined = Vec::new();
        for input in inputs {
            combined.extend_from_slice(input);
        }
        self.hash_bytes(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_hash_output_creation() {
        let bytes = [1u8; 32];
        let hash = HashOutput::new(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_output_from_slice() {
        let bytes = [2u8; 32];
        let hash = HashOutput::from_slice(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);

        let invalid = [0u8; 16];
        assert!(HashOutput::from_slice(&invalid).is_err());
    }

    #[test]
    fn test_hash_output_hex_conversion() {
        let bytes = [255u8; 32];
        let hash = HashOutput::new(bytes);
        let hex = hash.to_hex();
        let hash2 = HashOutput::from_hex(&hex).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_output_display() {
        let bytes = [170u8; 32];
        let hash = HashOutput::new(bytes);
        let display = format!("{}", hash);
        assert_eq!(display, "a".repeat(64));
    }

    #[test]
    fn test_hash_output_zero() {
        let zero = HashOutput::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_entry_hash_context_creation() {
        let context = EntryHashContext {
            entry_id: uuid::Uuid::new_v4(),
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("application/json".to_string()),
            metadata: HashMap::new(),
        };

        assert_eq!(context.version, 1);
        assert_eq!(context.timestamp, 1234567890);
        assert!(context.previous_id.is_none());
        assert_eq!(context.content_type, Some("application/json".to_string()));
    }
}

/// cross-implementation tests comparing all hash algorithms
#[cfg(test)]
mod cross_implementation_tests {
    use super::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// test that all hash algorithms produce different outputs for the same input
    #[test]
    fn test_all_algorithms_produce_different_outputs() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let test_data = b"cross-implementation test data";

        let blake3_hash = blake3_hasher.hash_bytes(test_data).unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(test_data).unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(test_data).unwrap();

        assert_ne!(
            blake3_hash, sha256_hash,
            "Blake3 and SHA-256 should produce different hashes"
        );
        assert_ne!(
            blake3_hash, keccak_hash,
            "Blake3 and Keccak-256 should produce different hashes"
        );
        assert_ne!(
            sha256_hash, keccak_hash,
            "SHA-256 and Keccak-256 should produce different hashes"
        );

        assert_ne!(blake3_hash, HashOutput::zero());
        assert_ne!(sha256_hash, HashOutput::zero());
        assert_ne!(keccak_hash, HashOutput::zero());
    }

    /// test that all algorithms are deterministic
    #[test]
    fn test_all_algorithms_deterministic() {
        let test_data = b"deterministic test data";

        let blake3_hasher = Blake3Hasher::new();
        let blake3_hash1 = blake3_hasher.hash_bytes(test_data).unwrap();
        let blake3_hash2 = blake3_hasher.hash_bytes(test_data).unwrap();
        assert_eq!(blake3_hash1, blake3_hash2, "Blake3 should be deterministic");

        let sha256_hasher = Sha256Hasher::new();
        let sha256_hash1 = sha256_hasher.hash_bytes(test_data).unwrap();
        let sha256_hash2 = sha256_hasher.hash_bytes(test_data).unwrap();
        assert_eq!(
            sha256_hash1, sha256_hash2,
            "SHA-256 should be deterministic"
        );

        let keccak_hasher = KeccakHasher::new();
        let keccak_hash1 = keccak_hasher.hash_bytes(test_data).unwrap();
        let keccak_hash2 = keccak_hasher.hash_bytes(test_data).unwrap();
        assert_eq!(
            keccak_hash1, keccak_hash2,
            "Keccak-256 should be deterministic"
        );
    }

    /// test hash_pair functionality across all algorithms
    #[test]
    fn test_all_algorithms_hash_pair_different() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let left_data = b"left child data";
        let right_data = b"right child data";

        let blake3_left = blake3_hasher.hash_bytes(left_data).unwrap();
        let blake3_right = blake3_hasher.hash_bytes(right_data).unwrap();
        let sha256_left = sha256_hasher.hash_bytes(left_data).unwrap();
        let sha256_right = sha256_hasher.hash_bytes(right_data).unwrap();
        let keccak_left = keccak_hasher.hash_bytes(left_data).unwrap();
        let keccak_right = keccak_hasher.hash_bytes(right_data).unwrap();

        let blake3_pair = blake3_hasher
            .hash_pair(&blake3_left, &blake3_right)
            .unwrap();
        let sha256_pair = sha256_hasher
            .hash_pair(&sha256_left, &sha256_right)
            .unwrap();
        let keccak_pair = keccak_hasher
            .hash_pair(&keccak_left, &keccak_right)
            .unwrap();

        assert_ne!(
            blake3_pair, sha256_pair,
            "Blake3 and SHA-256 pair hashes should differ"
        );
        assert_ne!(
            blake3_pair, keccak_pair,
            "Blake3 and Keccak-256 pair hashes should differ"
        );
        assert_ne!(
            sha256_pair, keccak_pair,
            "SHA-256 and Keccak-256 pair hashes should differ"
        );
    }

    /// test hash_entry functionality across all algorithms
    #[test]
    fn test_all_algorithms_hash_entry_different() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let entry_id = Uuid::new_v4();
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "test_user".to_string());
        metadata.insert("type".to_string(), "test_entry".to_string());

        let context = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("application/test".to_string()),
            metadata,
        };

        let test_data = b"entry data for cross-algorithm test";

        let blake3_entry = blake3_hasher.hash_entry(test_data, &context).unwrap();
        let sha256_entry = sha256_hasher.hash_entry(test_data, &context).unwrap();
        let keccak_entry = keccak_hasher.hash_entry(test_data, &context).unwrap();

        assert_ne!(
            blake3_entry, sha256_entry,
            "Blake3 and SHA-256 entry hashes should differ"
        );
        assert_ne!(
            blake3_entry, keccak_entry,
            "Blake3 and Keccak-256 entry hashes should differ"
        );
        assert_ne!(
            sha256_entry, keccak_entry,
            "SHA-256 and Keccak-256 entry hashes should differ"
        );
    }

    /// test hash_many functionality across all algorithms
    #[test]
    fn test_all_algorithms_hash_many_different() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let inputs = [
            b"first input".as_slice(),
            b"second input".as_slice(),
            b"third input".as_slice(),
        ];

        let blake3_many = blake3_hasher.hash_many(&inputs).unwrap();
        let sha256_many = sha256_hasher.hash_many(&inputs).unwrap();
        let keccak_many = keccak_hasher.hash_many(&inputs).unwrap();

        assert_ne!(
            blake3_many, sha256_many,
            "Blake3 and SHA-256 many hashes should differ"
        );
        assert_ne!(
            blake3_many, keccak_many,
            "Blake3 and Keccak-256 many hashes should differ"
        );
        assert_ne!(
            sha256_many, keccak_many,
            "SHA-256 and Keccak-256 many hashes should differ"
        );
    }

    /// test domain separation across algorithms
    #[test]
    fn test_cross_algorithm_domain_separation() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let test_data = b"domain separation test data";

        let blake3_bytes = blake3_hasher.hash_bytes(test_data).unwrap();
        let blake3_many = blake3_hasher.hash_many(&[test_data]).unwrap();
        assert_ne!(blake3_bytes, blake3_many, "Blake3 domain separation failed");

        let sha256_bytes = sha256_hasher.hash_bytes(test_data).unwrap();
        let sha256_many = sha256_hasher.hash_many(&[test_data]).unwrap();
        assert_ne!(
            sha256_bytes, sha256_many,
            "SHA-256 domain separation failed"
        );

        let keccak_bytes = keccak_hasher.hash_bytes(test_data).unwrap();
        let keccak_many = keccak_hasher.hash_many(&[test_data]).unwrap();
        assert_ne!(
            keccak_bytes, keccak_many,
            "Keccak-256 domain separation failed"
        );
    }

    /// test registry integration with all algorithms
    #[test]
    fn test_registry_integration() {
        let registry = HashRegistry::default();
        let test_data = b"registry integration test";

        let blake3_hasher = registry
            .get_hasher("blake3")
            .expect("Blake3 should be available");
        let sha256_hasher = registry
            .get_hasher("sha256")
            .expect("SHA-256 should be available");
        let keccak_hasher = registry
            .get_hasher("keccak256")
            .expect("Keccak-256 should be available");

        let blake3_hash = blake3_hasher.hash_bytes(test_data).unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(test_data).unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(test_data).unwrap();

        assert_ne!(blake3_hash, sha256_hash);
        assert_ne!(blake3_hash, keccak_hash);
        assert_ne!(sha256_hash, keccak_hash);

        let direct_blake3 = Blake3Hasher::new().hash_bytes(test_data).unwrap();
        let direct_sha256 = Sha256Hasher::new().hash_bytes(test_data).unwrap();
        let direct_keccak = KeccakHasher::new().hash_bytes(test_data).unwrap();

        assert_eq!(blake3_hash, direct_blake3);
        assert_eq!(sha256_hash, direct_sha256);
        assert_eq!(keccak_hash, direct_keccak);
    }

    /// test that all algorithms handle empty input consistently
    #[test]
    fn test_all_algorithms_empty_input() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let empty_data = &[];

        let blake3_empty = blake3_hasher.hash_bytes(empty_data).unwrap();
        let sha256_empty = sha256_hasher.hash_bytes(empty_data).unwrap();
        let keccak_empty = keccak_hasher.hash_bytes(empty_data).unwrap();

        assert_ne!(blake3_empty, HashOutput::zero());
        assert_ne!(sha256_empty, HashOutput::zero());
        assert_ne!(keccak_empty, HashOutput::zero());

        assert_ne!(blake3_empty, sha256_empty);
        assert_ne!(blake3_empty, keccak_empty);
        assert_ne!(sha256_empty, keccak_empty);

        assert_eq!(blake3_empty, blake3_hasher.hash_bytes(empty_data).unwrap());
        assert_eq!(sha256_empty, sha256_hasher.hash_bytes(empty_data).unwrap());
        assert_eq!(keccak_empty, keccak_hasher.hash_bytes(empty_data).unwrap());
    }

    /// test large input handling across all algorithms
    #[test]
    fn test_all_algorithms_large_input() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let large_data = vec![0xAB; 100_000]; // 100KB of data

        let blake3_large = blake3_hasher.hash_bytes(&large_data).unwrap();
        let sha256_large = sha256_hasher.hash_bytes(&large_data).unwrap();
        let keccak_large = keccak_hasher.hash_bytes(&large_data).unwrap();

        assert_ne!(blake3_large, HashOutput::zero());
        assert_ne!(sha256_large, HashOutput::zero());
        assert_ne!(keccak_large, HashOutput::zero());

        assert_ne!(blake3_large, sha256_large);
        assert_ne!(blake3_large, keccak_large);
        assert_ne!(sha256_large, keccak_large);

        assert_eq!(blake3_large, blake3_hasher.hash_bytes(&large_data).unwrap());
        assert_eq!(sha256_large, sha256_hasher.hash_bytes(&large_data).unwrap());
        assert_eq!(keccak_large, keccak_hasher.hash_bytes(&large_data).unwrap());
    }

    /// test that all algorithms produce standard-length output
    #[test]
    fn test_all_algorithms_output_length() {
        let blake3_hasher = Blake3Hasher::new();
        let sha256_hasher = Sha256Hasher::new();
        let keccak_hasher = KeccakHasher::new();

        let test_data = b"output length test";

        let blake3_hash = blake3_hasher.hash_bytes(test_data).unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(test_data).unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(test_data).unwrap();

        assert_eq!(blake3_hash.as_bytes().len(), 32);
        assert_eq!(sha256_hash.as_bytes().len(), 32);
        assert_eq!(keccak_hash.as_bytes().len(), 32);

        assert_eq!(blake3_hash.to_hex().len(), 64);
        assert_eq!(sha256_hash.to_hex().len(), 64);
        assert_eq!(keccak_hash.to_hex().len(), 64);
    }
}
