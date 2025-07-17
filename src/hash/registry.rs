//! Hash registry system for the Sylva versioned ledger system.
//!
//! This module provides a registry system for selecting hash functions by name,
//! allowing for flexible configuration and easy switching between different
//! hash implementations.
//!
//! # Examples
//!
//! ```
//! use sylva::hash::{HashRegistry, Hash};
//!
//! let registry = HashRegistry::new();
//! let hasher = registry.get_hasher("blake3").unwrap();
//! let data = b"Hello, registry!";
//! let hash = hasher.hash_bytes(data).unwrap();
//! println!("Hash: {}", hash);
//! ```
//!
//! # Supported Hash Functions
//!
//! - `blake3` - Blake3 hasher (default, fastest)
//! - `sha256` - SHA-256 hasher (NIST standard)
//! - `keccak` - Keccak-256 hasher (Ethereum compatible)
//! - `poseidon` - Poseidon hasher (ZK-friendly)
//! - `poseidon-merkle` - Poseidon optimized for Merkle trees
//! - `poseidon-ethereum` - Poseidon for Ethereum compatibility

use super::{
    Blake3Hasher, Hash, HashDigest, KeccakHasher, LedgerEntryHashInput, PoseidonHasher,
    Sha256Hasher,
};
use crate::error::{Result, SylvaError};
use std::collections::HashMap;

/// A boxed hash trait object for dynamic dispatch
pub type BoxedHasher = Box<dyn Hash + Send + Sync>;

/// Hash registry for selecting hash functions by name
///
/// The registry provides a centralized way to create and manage different
/// hash function implementations. It supports registration of new hashers
/// and selection by string name.
pub struct HashRegistry {
    hashers: HashMap<String, Box<dyn Fn() -> BoxedHasher + Send + Sync>>,
}

impl HashRegistry {
    /// Create a new hash registry with default hashers
    pub fn new() -> Self {
        let mut registry = Self {
            hashers: HashMap::new(),
        };

        // Register default hashers
        registry.register("blake3", || Box::new(Blake3Hasher::new()));
        registry.register("sha256", || Box::new(Sha256Hasher::new()));
        registry.register("keccak", || Box::new(KeccakHasher::new()));

        // Register Poseidon variants
        registry.register("poseidon", || Box::new(PoseidonHasher::new()));
        registry.register("poseidon-merkle", || {
            Box::new(PoseidonHasher::for_merkle_tree().unwrap())
        });
        registry.register("poseidon-ethereum", || {
            Box::new(PoseidonHasher::for_ethereum().unwrap())
        });

        registry
    }

    /// Register a new hasher with the given name
    pub fn register<F>(&mut self, name: &str, factory: F)
    where
        F: Fn() -> BoxedHasher + Send + Sync + 'static,
    {
        self.hashers.insert(name.to_string(), Box::new(factory));
    }

    /// Get a hasher by name
    pub fn get_hasher(&self, name: &str) -> Result<BoxedHasher> {
        self.hashers
            .get(name)
            .map(|factory| factory())
            .ok_or_else(|| SylvaError::ConfigError {
                message: format!("Unknown hash function: {}", name),
            })
    }

    /// Get all available hasher names
    pub fn available_hashers(&self) -> Vec<String> {
        self.hashers.keys().cloned().collect()
    }

    /// Get the default hasher (Blake3)
    pub fn default_hasher(&self) -> BoxedHasher {
        self.get_hasher("blake3").unwrap()
    }

    /// Check if a hasher is available
    pub fn is_available(&self, name: &str) -> bool {
        self.hashers.contains_key(name)
    }
}

impl Default for HashRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A trait object wrapper that implements Hash for dynamic dispatch
pub struct DynamicHasher {
    hasher: BoxedHasher,
    name: String,
}

impl DynamicHasher {
    /// Create a new dynamic hasher from a registry
    pub fn new(registry: &HashRegistry, name: &str) -> Result<Self> {
        let hasher = registry.get_hasher(name)?;
        Ok(Self {
            hasher,
            name: name.to_string(),
        })
    }

    /// Get the name of this hasher
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Hash for DynamicHasher {
    fn new() -> Self {
        let registry = HashRegistry::new();
        Self::new(&registry, "blake3").unwrap()
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashDigest> {
        self.hasher.hash_bytes(data)
    }

    fn hash_pair(&self, left: &HashDigest, right: &HashDigest) -> Result<HashDigest> {
        self.hasher.hash_pair(left, right)
    }

    fn hash_entry(&self, entry: &LedgerEntryHashInput) -> Result<HashDigest> {
        self.hasher.hash_entry(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use uuid::Uuid;

    #[test]
    fn test_registry_creation() {
        let registry = HashRegistry::new();
        let available = registry.available_hashers();
        assert!(available.contains(&"blake3".to_string()));
        assert!(available.contains(&"sha256".to_string()));
        assert!(available.contains(&"keccak".to_string()));
    }

    #[test]
    fn test_registry_default() {
        let registry1 = HashRegistry::new();
        let registry2 = HashRegistry::default();
        let mut hashers1 = registry1.available_hashers();
        let mut hashers2 = registry2.available_hashers();
        hashers1.sort();
        hashers2.sort();
        assert_eq!(hashers1, hashers2);
    }

    #[test]
    fn test_registry_get_hasher() {
        let registry = HashRegistry::new();

        let blake3_hasher = registry.get_hasher("blake3").unwrap();
        let sha256_hasher = registry.get_hasher("sha256").unwrap();
        let keccak_hasher = registry.get_hasher("keccak").unwrap();

        let data = b"test data";
        let blake3_hash = blake3_hasher.hash_bytes(data).unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(data).unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(data).unwrap();

        // All should produce valid hashes
        assert_eq!(blake3_hash.as_bytes().len(), 32);
        assert_eq!(sha256_hash.as_bytes().len(), 32);
        assert_eq!(keccak_hash.as_bytes().len(), 32);

        // All should produce different hashes
        assert_ne!(blake3_hash, sha256_hash);
        assert_ne!(blake3_hash, keccak_hash);
        assert_ne!(sha256_hash, keccak_hash);
    }

    #[test]
    fn test_registry_get_unknown_hasher() {
        let registry = HashRegistry::new();
        let result = registry.get_hasher("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_is_available() {
        let registry = HashRegistry::new();
        assert!(registry.is_available("blake3"));
        assert!(registry.is_available("sha256"));
        assert!(registry.is_available("keccak"));
        assert!(!registry.is_available("unknown"));
    }

    #[test]
    fn test_registry_default_hasher() {
        let registry = HashRegistry::new();
        let default_hasher = registry.default_hasher();
        let blake3_hasher = registry.get_hasher("blake3").unwrap();

        let data = b"test data";
        let default_hash = default_hasher.hash_bytes(data).unwrap();
        let blake3_hash = blake3_hasher.hash_bytes(data).unwrap();

        assert_eq!(default_hash, blake3_hash);
    }

    #[test]
    fn test_registry_register_custom_hasher() {
        let mut registry = HashRegistry::new();

        // Register a custom hasher (just uses Blake3 internally for this test)
        registry.register("custom", || Box::new(Blake3Hasher::new()));

        assert!(registry.is_available("custom"));
        let custom_hasher = registry.get_hasher("custom").unwrap();
        let hash = custom_hasher.hash_bytes(b"test").unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_dynamic_hasher_creation() {
        let registry = HashRegistry::new();
        let dynamic = DynamicHasher::new(&registry, "blake3").unwrap();
        assert_eq!(dynamic.name(), "blake3");
    }

    #[test]
    fn test_dynamic_hasher_hash_operations() {
        let registry = HashRegistry::new();
        let dynamic = DynamicHasher::new(&registry, "sha256").unwrap();

        let data = b"test data";
        let hash = dynamic.hash_bytes(data).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);

        let left = dynamic.hash_bytes(b"left").unwrap();
        let right = dynamic.hash_bytes(b"right").unwrap();
        let pair_hash = dynamic.hash_pair(&left, &right).unwrap();
        assert_eq!(pair_hash.as_bytes().len(), 32);

        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: b"entry data".to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };
        let entry_hash = dynamic.hash_entry(&entry).unwrap();
        assert_eq!(entry_hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_dynamic_hasher_new() {
        let registry = HashRegistry::new();
        let dynamic = DynamicHasher::new(&registry, "blake3").unwrap();
        assert_eq!(dynamic.name(), "blake3");
    }

    #[test]
    fn test_cross_implementation_comparison() {
        let registry = HashRegistry::new();
        let blake3_hasher = registry.get_hasher("blake3").unwrap();
        let sha256_hasher = registry.get_hasher("sha256").unwrap();
        let keccak_hasher = registry.get_hasher("keccak").unwrap();

        let test_data = b"cross-implementation test data";

        // Test hash_bytes
        let blake3_hash = blake3_hasher.hash_bytes(test_data).unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(test_data).unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(test_data).unwrap();

        // All should produce different outputs
        assert_ne!(blake3_hash, sha256_hash);
        assert_ne!(blake3_hash, keccak_hash);
        assert_ne!(sha256_hash, keccak_hash);

        // Test hash_pair
        let left = blake3_hasher.hash_bytes(b"left").unwrap();
        let right = blake3_hasher.hash_bytes(b"right").unwrap();

        let blake3_pair = blake3_hasher.hash_pair(&left, &right).unwrap();
        let sha256_pair = sha256_hasher.hash_pair(&left, &right).unwrap();
        let keccak_pair = keccak_hasher.hash_pair(&left, &right).unwrap();

        // All should produce different outputs
        assert_ne!(blake3_pair, sha256_pair);
        assert_ne!(blake3_pair, keccak_pair);
        assert_ne!(sha256_pair, keccak_pair);

        // Test hash_entry
        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: test_data.to_vec(),
            timestamp: 1234567890,
            previous_hash: None,
        };

        let blake3_entry = blake3_hasher.hash_entry(&entry).unwrap();
        let sha256_entry = sha256_hasher.hash_entry(&entry).unwrap();
        let keccak_entry = keccak_hasher.hash_entry(&entry).unwrap();

        // All should produce different outputs
        assert_ne!(blake3_entry, sha256_entry);
        assert_ne!(blake3_entry, keccak_entry);
        assert_ne!(sha256_entry, keccak_entry);
    }

    #[test]
    fn test_deterministic_across_implementations() {
        let registry = HashRegistry::new();

        for hasher_name in &["blake3", "sha256", "keccak"] {
            let hasher1 = registry.get_hasher(hasher_name).unwrap();
            let hasher2 = registry.get_hasher(hasher_name).unwrap();

            let data = b"deterministic test";
            let hash1 = hasher1.hash_bytes(data).unwrap();
            let hash2 = hasher2.hash_bytes(data).unwrap();

            assert_eq!(
                hash1, hash2,
                "Hasher {} should be deterministic",
                hasher_name
            );
        }
    }
}
