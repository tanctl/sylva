//! hash algorithm registry
//!
//! pick hash algorithms by name at runtime
//! supports: blake3, sha256, keccak256
//!
//! ```rust
//! use sylva::hash::{HashRegistry, Hash};
//!
//! let registry = HashRegistry::default();
//! let hasher = registry.get_hasher("blake3").expect("Blake3 should be available");
//! let hash = hasher.hash_bytes(b"test data").unwrap();
//! ```

use super::{Blake3Hasher, EntryHashContext, Hash, HashOutput, KeccakHasher, Sha256Hasher};
use crate::error::{Result, SylvaError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// all hash algorithms we support
#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    /// blake3 hash algorithm
    Blake3(Blake3Hasher),
    /// sha-256 hash algorithm
    Sha256(Sha256Hasher),
    /// keccak-256 hash algorithm
    Keccak256(KeccakHasher),
}

impl HashAlgorithm {
    /// get algorithm name as string
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Blake3(_) => "blake3",
            HashAlgorithm::Sha256(_) => "sha256",
            HashAlgorithm::Keccak256(_) => "keccak256",
        }
    }
}

impl Hash for HashAlgorithm {
    fn new() -> Self {
        // default to blake3
        HashAlgorithm::Blake3(Blake3Hasher::new())
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashOutput> {
        match self {
            HashAlgorithm::Blake3(hasher) => hasher.hash_bytes(data),
            HashAlgorithm::Sha256(hasher) => hasher.hash_bytes(data),
            HashAlgorithm::Keccak256(hasher) => hasher.hash_bytes(data),
        }
    }

    fn hash_pair(&self, left: &HashOutput, right: &HashOutput) -> Result<HashOutput> {
        match self {
            HashAlgorithm::Blake3(hasher) => hasher.hash_pair(left, right),
            HashAlgorithm::Sha256(hasher) => hasher.hash_pair(left, right),
            HashAlgorithm::Keccak256(hasher) => hasher.hash_pair(left, right),
        }
    }

    fn hash_entry(&self, data: &[u8], context: &EntryHashContext) -> Result<HashOutput> {
        match self {
            HashAlgorithm::Blake3(hasher) => hasher.hash_entry(data, context),
            HashAlgorithm::Sha256(hasher) => hasher.hash_entry(data, context),
            HashAlgorithm::Keccak256(hasher) => hasher.hash_entry(data, context),
        }
    }

    fn hash_many(&self, inputs: &[&[u8]]) -> Result<HashOutput> {
        match self {
            HashAlgorithm::Blake3(hasher) => hasher.hash_many(inputs),
            HashAlgorithm::Sha256(hasher) => hasher.hash_many(inputs),
            HashAlgorithm::Keccak256(hasher) => hasher.hash_many(inputs),
        }
    }
}

/// thread-safe hash registry
#[derive(Debug)]
pub struct HashRegistry {
    algorithms: Arc<Mutex<HashMap<String, HashAlgorithm>>>,
}

impl HashRegistry {
    /// create empty registry
    pub fn new() -> Self {
        Self {
            algorithms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// register algorithm with name
    pub fn register(&self, name: &str, algorithm: HashAlgorithm) {
        let mut algorithms = self.algorithms.lock().unwrap();
        algorithms.insert(name.to_lowercase(), algorithm);
    }

    /// get hasher by name
    pub fn get_hasher(&self, name: &str) -> Option<HashAlgorithm> {
        let algorithms = self.algorithms.lock().unwrap();
        algorithms.get(&name.to_lowercase()).cloned()
    }

    /// get hasher or return error
    pub fn get_hasher_or_error(&self, name: &str) -> Result<HashAlgorithm> {
        self.get_hasher(name).ok_or_else(|| {
            SylvaError::hash_error(format!("Hash algorithm '{}' not found in registry", name))
        })
    }

    /// list all registered algorithm names
    pub fn list_algorithms(&self) -> Vec<String> {
        let algorithms = self.algorithms.lock().unwrap();
        let mut names: Vec<String> = algorithms.keys().cloned().collect();
        names.sort();
        names
    }

    /// check if algorithm is registered
    pub fn has_algorithm(&self, name: &str) -> bool {
        let algorithms = self.algorithms.lock().unwrap();
        algorithms.contains_key(&name.to_lowercase())
    }

    /// remove algorithm from registry
    pub fn unregister(&self, name: &str) -> bool {
        let mut algorithms = self.algorithms.lock().unwrap();
        algorithms.remove(&name.to_lowercase()).is_some()
    }

    /// get registry statistics
    pub fn stats(&self) -> RegistryStats {
        let algorithms = self.algorithms.lock().unwrap();
        let algorithm_count = algorithms.len();
        let algorithm_names = algorithms.keys().cloned().collect();

        RegistryStats {
            algorithm_count,
            algorithms: algorithm_names,
        }
    }
}

/// registry stats
#[derive(Debug, Clone)]
pub struct RegistryStats {
    /// number of registered algorithms
    pub algorithm_count: usize,
    /// list of algorithm names
    pub algorithms: Vec<String>,
}

impl Default for HashRegistry {
    fn default() -> Self {
        let registry = Self::new();
        registry.register("blake3", HashAlgorithm::Blake3(Blake3Hasher::new()));
        registry.register("sha256", HashAlgorithm::Sha256(Sha256Hasher::new()));
        registry.register("keccak256", HashAlgorithm::Keccak256(KeccakHasher::new()));
        registry
    }
}

impl Clone for HashRegistry {
    fn clone(&self) -> Self {
        Self {
            algorithms: Arc::clone(&self.algorithms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = HashRegistry::new();
        assert_eq!(registry.list_algorithms().len(), 0);

        let default_registry = HashRegistry::default();
        assert!(default_registry.list_algorithms().len() > 0);
    }

    #[test]
    fn test_default_registry_algorithms() {
        let registry = HashRegistry::default();
        let algorithms = registry.list_algorithms();

        assert!(algorithms.contains(&"blake3".to_string()));
        assert!(algorithms.contains(&"sha256".to_string()));
        assert!(algorithms.contains(&"keccak256".to_string()));
        assert_eq!(algorithms.len(), 3);
    }

    #[test]
    fn test_get_hasher_by_name() {
        let registry = HashRegistry::default();

        let blake3_hasher = registry.get_hasher("blake3");
        assert!(blake3_hasher.is_some());

        let sha256_hasher = registry.get_hasher("sha256");
        assert!(sha256_hasher.is_some());

        let keccak_hasher = registry.get_hasher("keccak256");
        assert!(keccak_hasher.is_some());

        let unknown_hasher = registry.get_hasher("unknown");
        assert!(unknown_hasher.is_none());
    }

    #[test]
    fn test_case_insensitive_names() {
        let registry = HashRegistry::default();

        assert!(registry.get_hasher("BLAKE3").is_some());
        assert!(registry.get_hasher("Blake3").is_some());
        assert!(registry.get_hasher("SHA256").is_some());
        assert!(registry.get_hasher("Sha256").is_some());
        assert!(registry.get_hasher("KECCAK256").is_some());
        assert!(registry.get_hasher("Keccak256").is_some());
    }

    #[test]
    fn test_hasher_functionality() {
        let registry = HashRegistry::default();
        let data = b"test data for all algorithms";

        let blake3_hasher = registry.get_hasher("blake3").unwrap();
        let blake3_hash = blake3_hasher.hash_bytes(data).unwrap();

        let sha256_hasher = registry.get_hasher("sha256").unwrap();
        let sha256_hash = sha256_hasher.hash_bytes(data).unwrap();

        let keccak_hasher = registry.get_hasher("keccak256").unwrap();
        let keccak_hash = keccak_hasher.hash_bytes(data).unwrap();

        assert_ne!(blake3_hash, sha256_hash);
        assert_ne!(blake3_hash, keccak_hash);
        assert_ne!(sha256_hash, keccak_hash);
        let blake3_hash2 = registry
            .get_hasher("blake3")
            .unwrap()
            .hash_bytes(data)
            .unwrap();
        let sha256_hash2 = registry
            .get_hasher("sha256")
            .unwrap()
            .hash_bytes(data)
            .unwrap();
        let keccak_hash2 = registry
            .get_hasher("keccak256")
            .unwrap()
            .hash_bytes(data)
            .unwrap();

        assert_eq!(blake3_hash, blake3_hash2);
        assert_eq!(sha256_hash, sha256_hash2);
        assert_eq!(keccak_hash, keccak_hash2);
    }

    #[test]
    fn test_get_hasher_or_error() {
        let registry = HashRegistry::default();

        let hasher = registry.get_hasher_or_error("blake3");
        assert!(hasher.is_ok());

        let error = registry.get_hasher_or_error("nonexistent");
        assert!(error.is_err());
        assert!(error.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_has_algorithm() {
        let registry = HashRegistry::default();

        assert!(registry.has_algorithm("blake3"));
        assert!(registry.has_algorithm("BLAKE3"));
        assert!(registry.has_algorithm("sha256"));
        assert!(registry.has_algorithm("SHA256"));
        assert!(registry.has_algorithm("keccak256"));
        assert!(registry.has_algorithm("KECCAK256"));
        assert!(!registry.has_algorithm("unknown"));
    }

    #[test]
    fn test_unregister() {
        let registry = HashRegistry::default();

        assert!(registry.has_algorithm("blake3"));

        let removed = registry.unregister("blake3");
        assert!(removed);

        assert!(!registry.has_algorithm("blake3"));
        assert!(registry.get_hasher("blake3").is_none());

        let removed_again = registry.unregister("blake3");
        assert!(!removed_again);
    }

    #[test]
    fn test_registry_stats() {
        let registry = HashRegistry::default();
        let stats = registry.stats();

        assert_eq!(stats.algorithm_count, 3);
        assert!(stats.algorithms.contains(&"blake3".to_string()));
        assert!(stats.algorithms.contains(&"sha256".to_string()));
        assert!(stats.algorithms.contains(&"keccak256".to_string()));
    }

    #[test]
    fn test_registry_clone() {
        let registry1 = HashRegistry::default();
        let registry2 = registry1.clone();

        assert_eq!(registry1.list_algorithms(), registry2.list_algorithms());

        registry1.unregister("blake3");
        assert!(!registry2.has_algorithm("blake3"));
    }

    #[test]
    fn test_empty_registry() {
        let registry = HashRegistry::new();

        assert_eq!(registry.list_algorithms().len(), 0);
        assert!(!registry.has_algorithm("blake3"));
        assert!(registry.get_hasher("blake3").is_none());

        let stats = registry.stats();
        assert_eq!(stats.algorithm_count, 0);
        assert!(stats.algorithms.is_empty());
    }

    #[test]
    fn test_cross_algorithm_different_outputs() {
        let registry = HashRegistry::default();
        let test_data = b"cross-algorithm test data";

        let blake3_hash = registry
            .get_hasher("blake3")
            .unwrap()
            .hash_bytes(test_data)
            .unwrap();
        let sha256_hash = registry
            .get_hasher("sha256")
            .unwrap()
            .hash_bytes(test_data)
            .unwrap();
        let keccak_hash = registry
            .get_hasher("keccak256")
            .unwrap()
            .hash_bytes(test_data)
            .unwrap();

        assert_ne!(blake3_hash, sha256_hash);
        assert_ne!(blake3_hash, keccak_hash);
        assert_ne!(sha256_hash, keccak_hash);

        use crate::hash::HashOutput;
        assert_ne!(blake3_hash, HashOutput::zero());
        assert_ne!(sha256_hash, HashOutput::zero());
        assert_ne!(keccak_hash, HashOutput::zero());
    }

    #[test]
    fn test_algorithm_name_normalization() {
        let registry = HashRegistry::default();

        let test_cases = [
            ("blake3", "BLAKE3", "Blake3"),
            ("sha256", "SHA256", "Sha256"),
            ("keccak256", "KECCAK256", "Keccak256"),
        ];

        for (lower, upper, mixed) in test_cases.iter() {
            let hasher1 = registry.get_hasher(lower).unwrap();
            let hasher2 = registry.get_hasher(upper).unwrap();
            let hasher3 = registry.get_hasher(mixed).unwrap();

            let data = b"normalization test";
            let hash1 = hasher1.hash_bytes(data).unwrap();
            let hash2 = hasher2.hash_bytes(data).unwrap();
            let hash3 = hasher3.hash_bytes(data).unwrap();

            assert_eq!(hash1, hash2);
            assert_eq!(hash1, hash3);
        }
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let registry = Arc::new(HashRegistry::default());
        let mut handles = vec![];

        for i in 0..10 {
            let registry_clone = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                let algorithm = match i % 3 {
                    0 => "blake3",
                    1 => "sha256",
                    _ => "keccak256",
                };

                let hasher = registry_clone.get_hasher(algorithm).unwrap();
                let data = format!("thread {} data", i);
                hasher.hash_bytes(data.as_bytes()).unwrap()
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registry.list_algorithms().len(), 3);
    }

    #[test]
    fn test_registry_persistence() {
        let registry = HashRegistry::default();
        let original_count = registry.stats().algorithm_count;

        registry.unregister("blake3");
        assert_eq!(registry.stats().algorithm_count, original_count - 1);

        let cloned_registry = registry.clone();
        assert_eq!(cloned_registry.stats().algorithm_count, original_count - 1);
        assert!(!cloned_registry.has_algorithm("blake3"));
    }
}
