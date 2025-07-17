//! Hash function abstractions for the Sylva versioned ledger system.
//!
//! This module provides a generic hash trait and implementations for different
//! hash functions, with Blake3 as the default implementation.
//!
//! # Examples
//!
//! ```
//! use sylva::hash::{Hash, Blake3Hasher};
//!
//! let hasher = Blake3Hasher::new();
//! let data = b"Hello, Sylva!";
//! let hash = hasher.hash_bytes(data).unwrap();
//! println!("Hash: {}", hash);
//! ```
//!
//! # Security Considerations
//!
//! - All hash functions are deterministic by design
//! - Blake3 provides cryptographic security with 256-bit output
//! - Input sanitization is performed to prevent denial of service
//! - Thread-safe operations are guaranteed

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

pub mod blake3;
pub mod keccak;
pub mod poseidon;
pub mod registry;
pub mod sha256;

pub use self::blake3::Blake3Hasher;
pub use self::keccak::KeccakHasher;
pub use self::poseidon::{PoseidonConfig, PoseidonHasher};
pub use self::registry::{BoxedHasher, DynamicHasher, HashRegistry};
pub use self::sha256::Sha256Hasher;

/// Maximum allowed input size for hash operations (100MB)
pub const MAX_INPUT_SIZE: usize = 100 * 1024 * 1024;

/// Hash digest type representing the output of hash operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashDigest(pub [u8; 32]);

impl HashDigest {
    /// Create a new hash digest from a byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the hash digest
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to a hex string representation
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|_e| SylvaError::HashVerificationFailed)?;
        if bytes.len() != 32 {
            return Err(SylvaError::HashVerificationFailed);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl fmt::Display for HashDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Represents a ledger entry for hashing purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntryHashInput {
    pub id: Uuid,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub previous_hash: Option<HashDigest>,
}

/// Generic hash trait for different hash function implementations
///
/// This trait provides a consistent interface for hash operations
/// required by the Sylva versioned ledger system.
pub trait Hash {
    /// Create a new instance of the hasher
    fn new() -> Self
    where
        Self: Sized;

    /// Hash arbitrary bytes
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to hash
    ///
    /// # Returns
    ///
    /// A `Result<HashDigest>` containing the hash or an error
    ///
    /// # Errors
    ///
    /// Returns `SylvaError::HashVerificationFailed` if input is too large
    /// or other hash-related errors occur.
    fn hash_bytes(&self, data: &[u8]) -> Result<HashDigest>;

    /// Hash a pair of hash digests to create a parent node hash
    ///
    /// This is used for building Merkle trees where internal nodes
    /// are hashes of their child nodes.
    ///
    /// # Arguments
    ///
    /// * `left` - Left child hash
    /// * `right` - Right child hash
    ///
    /// # Returns
    ///
    /// A `Result<HashDigest>` containing the parent hash
    fn hash_pair(&self, left: &HashDigest, right: &HashDigest) -> Result<HashDigest>;

    /// Hash a ledger entry
    ///
    /// This method provides a standardized way to hash ledger entries,
    /// ensuring consistent hashing across the system.
    ///
    /// # Arguments
    ///
    /// * `entry` - The ledger entry to hash
    ///
    /// # Returns
    ///
    /// A `Result<HashDigest>` containing the entry hash
    fn hash_entry(&self, entry: &LedgerEntryHashInput) -> Result<HashDigest>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_hash_digest_creation() {
        let bytes = [1u8; 32];
        let digest = HashDigest::new(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_digest_hex_conversion() {
        let bytes = [0u8; 32];
        let digest = HashDigest::new(bytes);
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));

        let restored = HashDigest::from_hex(&hex).unwrap();
        assert_eq!(restored, digest);
    }

    #[test]
    fn test_hash_digest_display() {
        let bytes = [255u8; 32];
        let digest = HashDigest::new(bytes);
        let display = format!("{}", digest);
        assert_eq!(display, "f".repeat(64));
    }

    #[test]
    fn test_hash_digest_from_invalid_hex() {
        assert!(HashDigest::from_hex("invalid").is_err());
        assert!(HashDigest::from_hex("ff").is_err()); // Too short
        assert!(HashDigest::from_hex(&"f".repeat(70)).is_err()); // Too long
    }

    #[test]
    fn test_ledger_entry_hash_input_creation() {
        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"test data".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };
        assert_eq!(entry.data, b"test data");
    }
}
