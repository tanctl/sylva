//! Keccak-256 hash implementation for the Sylva versioned ledger system.
//!
//! This module provides a Keccak-256 based implementation of the Hash trait,
//! offering the same algorithm used in Ethereum and other blockchain systems.
//!
//! # Examples
//!
//! ```
//! use sylva::hash::{Hash, KeccakHasher};
//!
//! let hasher = KeccakHasher::new();
//! let data = b"Hello, Keccak-256!";
//! let hash = hasher.hash_bytes(data).unwrap();
//! println!("Keccak-256 Hash: {}", hash);
//! ```
//!
//! # Security Features
//!
//! - Keccak-256 algorithm (final SHA-3 standard)
//! - 256-bit cryptographically secure output
//! - Used in Ethereum and other blockchain systems
//! - Sponge construction for flexibility
//! - Thread-safe operations

use super::{Hash, HashDigest, LedgerEntryHashInput, MAX_INPUT_SIZE};
use crate::error::{Result, SylvaError};
use sha3::{Digest, Keccak256};

/// Keccak-256 hasher implementation
///
/// This struct provides a Keccak-256 based implementation of the Hash trait.
/// Keccak-256 is the algorithm used in Ethereum and other blockchain systems,
/// providing excellent security properties with a sponge construction.
#[derive(Debug, Clone)]
pub struct KeccakHasher {
    _marker: std::marker::PhantomData<()>,
}

impl KeccakHasher {
    /// Create a new Keccak-256 hasher instance
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    /// Internal method to validate input size
    fn validate_input_size(&self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_INPUT_SIZE {
            return Err(SylvaError::HashVerificationFailed);
        }
        Ok(())
    }

    /// Internal method to perform the actual hashing
    fn hash_internal(&self, data: &[u8]) -> Result<HashDigest> {
        self.validate_input_size(data)?;

        let mut hasher = Keccak256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Ok(HashDigest::new(hash.into()))
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for KeccakHasher {
    fn new() -> Self {
        KeccakHasher::new()
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashDigest> {
        self.hash_internal(data)
    }

    fn hash_pair(&self, left: &HashDigest, right: &HashDigest) -> Result<HashDigest> {
        let mut hasher = Keccak256::new();
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        let hash = hasher.finalize();

        Ok(HashDigest::new(hash.into()))
    }

    fn hash_entry(&self, entry: &LedgerEntryHashInput) -> Result<HashDigest> {
        // Serialize the entry in a deterministic way
        let mut hasher = Keccak256::new();

        // Hash the UUID
        hasher.update(entry.id.as_bytes());

        // Hash the data length first, then the data (prevents length extension attacks)
        hasher.update((entry.data.len() as u64).to_le_bytes());
        self.validate_input_size(&entry.data)?;
        hasher.update(&entry.data);

        // Hash the timestamp
        hasher.update(entry.timestamp.to_le_bytes());

        // Hash the previous hash if present
        if let Some(prev_hash) = &entry.previous_hash {
            hasher.update([1u8]); // Presence marker
            hasher.update(prev_hash.as_bytes());
        } else {
            hasher.update([0u8]); // Absence marker
        }

        let hash = hasher.finalize();
        Ok(HashDigest::new(hash.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;
    use uuid::Uuid;

    #[test]
    fn test_keccak_hasher_creation() {
        let hasher = KeccakHasher::new();
        assert_eq!(std::mem::size_of_val(&hasher), 0); // Zero-sized type
    }

    #[test]
    fn test_keccak_default() {
        let hasher1 = KeccakHasher::new();
        let hasher2 = KeccakHasher::default();

        let data = b"test data";
        let hash1 = hasher1.hash_bytes(data).unwrap();
        let hash2 = hasher2.hash_bytes(data).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak_hash_bytes_empty() {
        let hasher = KeccakHasher::new();
        let hash = hasher.hash_bytes(b"").unwrap();

        // Keccak-256 hash of empty input is well-defined
        assert_eq!(hash.as_bytes().len(), 32);
        // Known Keccak-256 hash of empty string
        assert_eq!(
            hash.to_hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak_hash_bytes_deterministic() {
        let hasher = KeccakHasher::new();
        let data = b"Hello, Keccak-256!";

        let hash1 = hasher.hash_bytes(data).unwrap();
        let hash2 = hasher.hash_bytes(data).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak_hash_bytes_different_inputs() {
        let hasher = KeccakHasher::new();

        let hash1 = hasher.hash_bytes(b"data1").unwrap();
        let hash2 = hasher.hash_bytes(b"data2").unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keccak_hash_pair() {
        let hasher = KeccakHasher::new();

        let left = hasher.hash_bytes(b"left").unwrap();
        let right = hasher.hash_bytes(b"right").unwrap();

        let parent1 = hasher.hash_pair(&left, &right).unwrap();
        let parent2 = hasher.hash_pair(&left, &right).unwrap();

        assert_eq!(parent1, parent2);
    }

    #[test]
    fn test_keccak_hash_pair_order_matters() {
        let hasher = KeccakHasher::new();

        let left = hasher.hash_bytes(b"left").unwrap();
        let right = hasher.hash_bytes(b"right").unwrap();

        let parent1 = hasher.hash_pair(&left, &right).unwrap();
        let parent2 = hasher.hash_pair(&right, &left).unwrap();

        assert_ne!(parent1, parent2);
    }

    #[test]
    fn test_keccak_hash_entry() {
        let hasher = KeccakHasher::new();

        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"test entry data".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };

        let hash1 = hasher.hash_entry(&entry).unwrap();
        let hash2 = hasher.hash_entry(&entry).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak_hash_entry_with_previous_hash() {
        let hasher = KeccakHasher::new();

        let prev_hash = hasher.hash_bytes(b"previous").unwrap();
        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"test entry data".to_vec(),
            timestamp: 1234567890,
            previous_hash: Some(prev_hash),
        };

        let hash = hasher.hash_entry(&entry).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_keccak_hash_entry_different_entries() {
        let hasher = KeccakHasher::new();

        let entry1 = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"entry1".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };

        let entry2 = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"entry2".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };

        let hash1 = hasher.hash_entry(&entry1).unwrap();
        let hash2 = hasher.hash_entry(&entry2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keccak_max_input_size() {
        let hasher = KeccakHasher::new();
        let large_data = vec![0u8; MAX_INPUT_SIZE + 1];

        let result = hasher.hash_bytes(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_keccak_max_input_size_entry() {
        let hasher = KeccakHasher::new();

        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: vec![0u8; MAX_INPUT_SIZE + 1],
            timestamp: 1234567890,
            previous_hash: None,
        };

        let result = hasher.hash_entry(&entry);
        assert!(result.is_err());
    }

    // Property-based tests
    proptest! {
        #[test]
        fn prop_keccak_hash_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hasher = KeccakHasher::new();
            let hash1 = hasher.hash_bytes(&data).unwrap();
            let hash2 = hasher.hash_bytes(&data).unwrap();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_keccak_hash_different_inputs_different_outputs(
            data1 in prop::collection::vec(any::<u8>(), 1..1000),
            data2 in prop::collection::vec(any::<u8>(), 1..1000)
        ) {
            prop_assume!(data1 != data2);
            let hasher = KeccakHasher::new();
            let hash1 = hasher.hash_bytes(&data1).unwrap();
            let hash2 = hasher.hash_bytes(&data2).unwrap();
            assert_ne!(hash1, hash2);
        }

        #[test]
        fn prop_keccak_hash_pair_deterministic(
            left_data in prop::collection::vec(any::<u8>(), 0..100),
            right_data in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let hasher = KeccakHasher::new();
            let left = hasher.hash_bytes(&left_data).unwrap();
            let right = hasher.hash_bytes(&right_data).unwrap();

            let parent1 = hasher.hash_pair(&left, &right).unwrap();
            let parent2 = hasher.hash_pair(&left, &right).unwrap();
            assert_eq!(parent1, parent2);
        }

        #[test]
        fn prop_keccak_hash_entry_deterministic(
            data in prop::collection::vec(any::<u8>(), 0..1000),
            timestamp in any::<u64>()
        ) {
            let hasher = KeccakHasher::new();
            let entry = LedgerEntryHashInput {
                id: Uuid::new_v4(),
                data,
                timestamp,
                previous_hash: None,
            };

            let hash1 = hasher.hash_entry(&entry).unwrap();
            let hash2 = hasher.hash_entry(&entry).unwrap();
            assert_eq!(hash1, hash2);
        }
    }
}
