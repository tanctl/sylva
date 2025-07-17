//! Poseidon hash implementation for Zero-Knowledge applications.
//!
//! This module provides a ZK-friendly Poseidon hash function implementation
//! using the light-poseidon crate with BN254 curve parameters. Poseidon is
//! specifically designed for efficient verification in zero-knowledge circuits.
//!
//! # Examples
//!
//! ```
//! use sylva::hash::{Hash, PoseidonHasher};
//!
//! let hasher = PoseidonHasher::new();
//! let data = b"Hello, ZK world!";
//! let hash = hasher.hash_bytes(data).unwrap();
//! println!("Poseidon Hash: {}", hash);
//! ```
//!
//! # ZK-Friendly Features
//!
//! - Optimized for SNARK/STARK proof systems
//! - BN254 curve parameters for Ethereum compatibility
//! - Configurable arity (2-13 inputs)
//! - Circom circuit compatibility
//! - Audited implementation by Veridise

use super::{Hash, HashDigest, LedgerEntryHashInput, MAX_INPUT_SIZE};
use crate::error::{Result, SylvaError};
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use serde::{Deserialize, Serialize};

/// Poseidon hash function configuration for different use cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoseidonConfig {
    /// Arity of the Poseidon function (number of inputs, 2-13)
    pub arity: usize,
    /// Whether to use big-endian or little-endian byte ordering
    pub big_endian: bool,
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        Self {
            arity: 2,         // Default to binary tree arity for Merkle trees
            big_endian: true, // Default to big-endian for consistency
        }
    }
}

impl PoseidonConfig {
    /// Create a new Poseidon configuration
    pub fn new(arity: usize, big_endian: bool) -> Result<Self> {
        if !(2..=13).contains(&arity) {
            return Err(SylvaError::ConfigError {
                message: format!("Poseidon arity must be between 2 and 13, got {}", arity),
            });
        }
        Ok(Self { arity, big_endian })
    }

    /// Configuration optimized for Merkle trees (binary)
    pub fn merkle_tree() -> Self {
        Self {
            arity: 2,
            big_endian: true,
        }
    }

    /// Configuration optimized for batch hashing
    pub fn batch_hash(arity: usize) -> Result<Self> {
        Self::new(arity, true)
    }

    /// Configuration for Ethereum compatibility
    pub fn ethereum() -> Self {
        Self {
            arity: 2,
            big_endian: false, // Ethereum uses little-endian
        }
    }
}

/// ZK-friendly Poseidon hasher implementation
///
/// This hasher uses the BN254 curve parameters and is optimized for
/// zero-knowledge proof systems. It provides configurable arity and
/// byte ordering to suit different ZK circuit requirements.
#[derive(Clone, Debug)]
pub struct PoseidonHasher {
    config: PoseidonConfig,
}

impl PoseidonHasher {
    /// Create a new Poseidon hasher with custom configuration
    pub fn with_config(config: PoseidonConfig) -> Result<Self> {
        // Validate that the configuration is valid by attempting to create a Poseidon instance
        let _test_poseidon =
            Poseidon::<Fr>::new_circom(config.arity).map_err(|e| SylvaError::ConfigError {
                message: format!("Failed to create Poseidon hasher: {}", e),
            })?;

        Ok(Self { config })
    }

    /// Create a Poseidon hasher optimized for Merkle trees
    pub fn for_merkle_tree() -> Result<Self> {
        Self::with_config(PoseidonConfig::merkle_tree())
    }

    /// Create a Poseidon hasher for batch operations
    pub fn for_batch_hash(arity: usize) -> Result<Self> {
        Self::with_config(PoseidonConfig::batch_hash(arity)?)
    }

    /// Create a Poseidon hasher for Ethereum compatibility
    pub fn for_ethereum() -> Result<Self> {
        Self::with_config(PoseidonConfig::ethereum())
    }

    /// Get the current configuration
    pub fn config(&self) -> &PoseidonConfig {
        &self.config
    }

    /// Hash multiple inputs in a single operation (ZK-optimized)
    ///
    /// This method is more efficient for ZK circuits than multiple
    /// hash_pair operations when dealing with more than 2 inputs.
    pub fn hash_multiple(&self, inputs: &[&[u8]]) -> Result<HashDigest> {
        if inputs.is_empty() {
            return Err(SylvaError::HashVerificationFailed);
        }

        if inputs.len() > self.config.arity {
            return Err(SylvaError::ConfigError {
                message: format!(
                    "Too many inputs ({}) for configured arity ({})",
                    inputs.len(),
                    self.config.arity
                ),
            });
        }

        // Check input size limits
        for input in inputs {
            if input.len() > MAX_INPUT_SIZE {
                return Err(SylvaError::HashVerificationFailed);
            }
        }

        // Pad inputs to match arity if needed
        let mut padded_inputs = inputs.to_vec();
        while padded_inputs.len() < self.config.arity {
            padded_inputs.push(&[0u8; 32]); // Pad with zero bytes
        }

        // Convert inputs to 32-byte arrays, ensuring they fit in the BN254 field
        let mut input_arrays = Vec::new();
        for input in padded_inputs {
            let mut array = [0u8; 32];

            // Always hash inputs first to ensure they fit in the field
            // This is safer for ZK applications and ensures consistency
            use super::Blake3Hasher;
            let blake3 = Blake3Hasher::new();
            let preliminary_hash = blake3.hash_bytes(input)?;
            array.copy_from_slice(preliminary_hash.as_bytes());

            // Ensure the value fits in the BN254 field by clearing the top bits
            // BN254 field modulus is about 2^254, so we clear the top 8 bits to be safe
            array[0] = 0; // Clear the first byte entirely to ensure we're well below the modulus

            input_arrays.push(array);
        }

        // Perform Poseidon hash - need to create a mutable copy since the methods require &mut self
        let mut poseidon_copy =
            Poseidon::<Fr>::new_circom(self.config.arity).map_err(|e| SylvaError::ConfigError {
                message: format!("Failed to create Poseidon hasher: {}", e),
            })?;

        let hash_result = if self.config.big_endian {
            poseidon_copy.hash_bytes_be(
                &input_arrays
                    .iter()
                    .map(|a| a.as_slice())
                    .collect::<Vec<_>>(),
            )
        } else {
            poseidon_copy.hash_bytes_le(
                &input_arrays
                    .iter()
                    .map(|a| a.as_slice())
                    .collect::<Vec<_>>(),
            )
        };

        match hash_result {
            Ok(hash_bytes) => {
                let mut result = [0u8; 32];
                result.copy_from_slice(&hash_bytes);
                Ok(HashDigest::new(result))
            }
            Err(e) => Err(SylvaError::ConfigError {
                message: format!("Poseidon hash failed: {}", e),
            }),
        }
    }

    /// Check if this hasher is ZK-compatible
    pub fn is_zk_compatible(&self) -> bool {
        true // Poseidon is always ZK-compatible
    }

    /// Get the field size used by this Poseidon implementation
    pub fn field_size_bits(&self) -> usize {
        254 // BN254 field size
    }
}

impl Hash for PoseidonHasher {
    fn new() -> Self {
        Self::with_config(PoseidonConfig::default()).unwrap()
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashDigest> {
        if data.len() > MAX_INPUT_SIZE {
            return Err(SylvaError::HashVerificationFailed);
        }

        // For single input, use it directly
        self.hash_multiple(&[data])
    }

    fn hash_pair(&self, left: &HashDigest, right: &HashDigest) -> Result<HashDigest> {
        self.hash_multiple(&[left.as_bytes().as_slice(), right.as_bytes().as_slice()])
    }

    fn hash_entry(&self, entry: &LedgerEntryHashInput) -> Result<HashDigest> {
        if entry.data.len() > MAX_INPUT_SIZE {
            return Err(SylvaError::HashVerificationFailed);
        }

        // Serialize entry components for hashing
        let id_bytes = entry.id.as_bytes();
        let timestamp_bytes = entry.timestamp.to_be_bytes();

        // Combine all entry data
        let mut entry_data = Vec::new();
        entry_data.extend_from_slice(id_bytes);
        entry_data.extend_from_slice(&entry.data);
        entry_data.extend_from_slice(&timestamp_bytes);

        // Include previous hash if present
        if let Some(prev_hash) = &entry.previous_hash {
            entry_data.extend_from_slice(prev_hash.as_bytes());
        }

        self.hash_bytes(&entry_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use uuid::Uuid;

    #[test]
    fn test_poseidon_config_creation() {
        let config = PoseidonConfig::new(3, true).unwrap();
        assert_eq!(config.arity, 3);
        assert!(config.big_endian);

        // Test invalid arity
        assert!(PoseidonConfig::new(1, true).is_err());
        assert!(PoseidonConfig::new(14, true).is_err());
    }

    #[test]
    fn test_poseidon_config_presets() {
        let merkle_config = PoseidonConfig::merkle_tree();
        assert_eq!(merkle_config.arity, 2);
        assert!(merkle_config.big_endian);

        let batch_config = PoseidonConfig::batch_hash(5).unwrap();
        assert_eq!(batch_config.arity, 5);
        assert!(batch_config.big_endian);

        let eth_config = PoseidonConfig::ethereum();
        assert_eq!(eth_config.arity, 2);
        assert!(!eth_config.big_endian);
    }

    #[test]
    fn test_poseidon_hasher_creation() {
        let hasher = PoseidonHasher::new();
        assert_eq!(hasher.config().arity, 2);
        assert!(hasher.config().big_endian);

        let merkle_hasher = PoseidonHasher::for_merkle_tree().unwrap();
        assert_eq!(merkle_hasher.config().arity, 2);

        let batch_hasher = PoseidonHasher::for_batch_hash(4).unwrap();
        assert_eq!(batch_hasher.config().arity, 4);

        let eth_hasher = PoseidonHasher::for_ethereum().unwrap();
        assert!(!eth_hasher.config().big_endian);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let hasher = PoseidonHasher::new();
        let data = b"test data for poseidon";
        let hash = hasher.hash_bytes(data).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);

        // Test determinism
        let hash2 = hasher.hash_bytes(data).unwrap();
        assert_eq!(hash, hash2);

        // Test different data produces different hash
        let different_hash = hasher.hash_bytes(b"different data").unwrap();
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_poseidon_hash_pair() {
        let hasher = PoseidonHasher::new();
        let left_data = b"left node data";
        let right_data = b"right node data";

        let left_hash = hasher.hash_bytes(left_data).unwrap();
        let right_hash = hasher.hash_bytes(right_data).unwrap();

        let pair_hash = hasher.hash_pair(&left_hash, &right_hash).unwrap();
        assert_eq!(pair_hash.as_bytes().len(), 32);

        // Test determinism
        let pair_hash2 = hasher.hash_pair(&left_hash, &right_hash).unwrap();
        assert_eq!(pair_hash, pair_hash2);

        // Test order matters
        let reversed_pair = hasher.hash_pair(&right_hash, &left_hash).unwrap();
        assert_ne!(pair_hash, reversed_pair);
    }

    #[test]
    fn test_poseidon_hash_multiple() {
        let hasher = PoseidonHasher::for_batch_hash(3).unwrap();
        let inputs = [
            b"input1".as_slice(),
            b"input2".as_slice(),
            b"input3".as_slice(),
        ];

        let hash = hasher.hash_multiple(&inputs).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);

        // Test with fewer inputs (should pad)
        let fewer_inputs = [b"input1".as_slice(), b"input2".as_slice()];
        let padded_hash = hasher.hash_multiple(&fewer_inputs).unwrap();
        assert_eq!(padded_hash.as_bytes().len(), 32);

        // Different number of inputs should produce different hashes
        assert_ne!(hash, padded_hash);
    }

    #[test]
    fn test_poseidon_hash_multiple_too_many_inputs() {
        let hasher = PoseidonHasher::for_batch_hash(2).unwrap();
        let inputs = [
            b"input1".as_slice(),
            b"input2".as_slice(),
            b"input3".as_slice(),
        ];

        // Should fail with too many inputs
        assert!(hasher.hash_multiple(&inputs).is_err());
    }

    #[test]
    fn test_poseidon_hash_entry() {
        let hasher = PoseidonHasher::new();
        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"entry data".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };

        let hash = hasher.hash_entry(&entry).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);

        // Test with previous hash
        let entry_with_prev = LedgerEntryHashInput {
            id: entry.id,
            data: entry.data.clone(),
            timestamp: entry.timestamp,
            previous_hash: Some(hash.clone()),
        };

        let hash_with_prev = hasher.hash_entry(&entry_with_prev).unwrap();
        assert_ne!(hash, hash_with_prev);
    }

    #[test]
    fn test_poseidon_zk_properties() {
        let hasher = PoseidonHasher::new();
        assert!(hasher.is_zk_compatible());
        assert_eq!(hasher.field_size_bits(), 254);
    }

    #[test]
    fn test_poseidon_large_input() {
        let hasher = PoseidonHasher::new();
        let large_data = vec![0u8; 1000];
        let hash = hasher.hash_bytes(&large_data).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_poseidon_empty_input() {
        let hasher = PoseidonHasher::new();
        let empty_data = b"";
        let hash = hasher.hash_bytes(empty_data).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_poseidon_max_input_size() {
        let hasher = PoseidonHasher::new();
        let max_data = vec![0u8; MAX_INPUT_SIZE];
        assert!(hasher.hash_bytes(&max_data).is_ok());

        let oversized_data = vec![0u8; MAX_INPUT_SIZE + 1];
        assert!(hasher.hash_bytes(&oversized_data).is_err());
    }

    #[test]
    fn test_poseidon_different_configs_produce_different_hashes() {
        let merkle_hasher = PoseidonHasher::for_merkle_tree().unwrap();
        let batch_hasher = PoseidonHasher::for_batch_hash(3).unwrap();

        let data = b"test data";
        let merkle_hash = merkle_hasher.hash_bytes(data).unwrap();
        let batch_hash = batch_hasher.hash_bytes(data).unwrap();

        // Different arity should produce different hashes due to different padding
        assert_ne!(merkle_hash, batch_hash);
    }

    #[test]
    fn test_poseidon_cross_compatibility() {
        // Test that our implementation produces consistent results
        let hasher1 = PoseidonHasher::new();
        let hasher2 = PoseidonHasher::new();

        let data = b"cross compatibility test";
        let hash1 = hasher1.hash_bytes(data).unwrap();
        let hash2 = hasher2.hash_bytes(data).unwrap();

        assert_eq!(hash1, hash2);
    }
}
