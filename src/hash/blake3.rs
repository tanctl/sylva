//! blake3 implementation
//!
//! fast crypto hash with good performance
//!
//! ```rust
//! use sylva::hash::{Hash, Blake3Hasher};
//!
//! let hasher = Blake3Hasher::new();
//! let hash = hasher.hash_bytes(b"test data").unwrap();
//! println!("blake3 hash: {}", hash.to_hex());
//! ```

use super::{EntryHashContext, Hash, HashOutput};
use crate::error::{Result, SylvaError};
use blake3::{Hash as Blake3Hash, Hasher as Blake3InternalHasher};

/// blake3 hasher
#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    const MERKLE_PAIR_DOMAIN: &'static [u8] = b"SYLVA_MERKLE_PAIR";
    const ENTRY_DOMAIN: &'static [u8] = b"SYLVA_LEDGER_ENTRY";
    const BYTES_DOMAIN: &'static [u8] = b"SYLVA_BYTES";

    fn blake3_to_hash_output(blake3_hash: Blake3Hash) -> HashOutput {
        let bytes: [u8; 32] = *blake3_hash.as_bytes();
        HashOutput::new(bytes)
    }

    // add domain prefix to prevent collisions between different hash contexts
    fn create_domain_hasher(domain: &[u8]) -> Blake3InternalHasher {
        let mut hasher = Blake3InternalHasher::new();
        hasher.update(domain);
        hasher.update(&[0u8]);
        hasher
    }

    // serialize context to bytes for hashing - needs to be deterministic
    fn serialize_entry_context(context: &EntryHashContext) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(context.entry_id.as_bytes());
        buffer.extend_from_slice(&context.version.to_be_bytes());
        buffer.extend_from_slice(&context.timestamp.to_be_bytes());

        match context.previous_id {
            Some(prev_id) => buffer.extend_from_slice(prev_id.as_bytes()),
            None => buffer.extend_from_slice(&[0u8; 16]),
        }

        match &context.content_type {
            Some(content_type) => {
                let bytes = content_type.as_bytes();
                buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buffer.extend_from_slice(bytes);
            }
            None => buffer.extend_from_slice(&[0u8; 4]),
        }

        // sort metadata for determinism
        let mut sorted_metadata: Vec<_> = context.metadata.iter().collect();
        sorted_metadata.sort_by_key(|(key, _)| *key);

        buffer.extend_from_slice(&(sorted_metadata.len() as u32).to_be_bytes());
        for (key, value) in sorted_metadata {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();

            buffer.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
            buffer.extend_from_slice(key_bytes);
            buffer.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
            buffer.extend_from_slice(value_bytes);
        }

        Ok(buffer)
    }
}

impl Hash for Blake3Hasher {
    fn new() -> Self {
        Self
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashOutput> {
        let mut hasher = Self::create_domain_hasher(Self::BYTES_DOMAIN);
        hasher.update(data);
        let hash = hasher.finalize();
        Ok(Self::blake3_to_hash_output(hash))
    }

    fn hash_pair(&self, left: &HashOutput, right: &HashOutput) -> Result<HashOutput> {
        let mut hasher = Self::create_domain_hasher(Self::MERKLE_PAIR_DOMAIN);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        let hash = hasher.finalize();
        Ok(Self::blake3_to_hash_output(hash))
    }

    fn hash_entry(&self, data: &[u8], context: &EntryHashContext) -> Result<HashOutput> {
        let context_bytes = Self::serialize_entry_context(context).map_err(|e| {
            SylvaError::hash_error(format!("Failed to serialize entry context: {}", e))
        })?;

        let mut hasher = Self::create_domain_hasher(Self::ENTRY_DOMAIN);

        hasher.update(&context_bytes);
        hasher.update(data);

        let hash = hasher.finalize();
        Ok(Self::blake3_to_hash_output(hash))
    }

    fn hash_many(&self, inputs: &[&[u8]]) -> Result<HashOutput> {
        let mut hasher = Self::create_domain_hasher(Self::BYTES_DOMAIN);

        hasher.update(&(inputs.len() as u64).to_be_bytes());

        for input in inputs {
            hasher.update(&(input.len() as u64).to_be_bytes());
            hasher.update(input);
        }

        let hash = hasher.finalize();
        Ok(Self::blake3_to_hash_output(hash))
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_blake3_hasher_creation() {
        let hasher = Blake3Hasher::new();
        let hasher2 = Blake3Hasher::default();

        let data = b"test data";
        let hash1 = hasher.hash_bytes(data).unwrap();
        let hash2 = hasher2.hash_bytes(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let hasher = Blake3Hasher::new();
        let data = b"deterministic test data";

        let hash1 = hasher.hash_bytes(data).unwrap();
        let hash2 = hasher.hash_bytes(data).unwrap();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, HashOutput::zero());
    }

    #[test]
    fn test_hash_bytes_different_inputs() {
        let hasher = Blake3Hasher::new();

        let hash1 = hasher.hash_bytes(b"input1").unwrap();
        let hash2 = hasher.hash_bytes(b"input2").unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let hasher = Blake3Hasher::new();

        let left = hasher.hash_bytes(b"left").unwrap();
        let right = hasher.hash_bytes(b"right").unwrap();

        let pair_hash1 = hasher.hash_pair(&left, &right).unwrap();
        let pair_hash2 = hasher.hash_pair(&left, &right).unwrap();

        assert_eq!(pair_hash1, pair_hash2);
    }

    #[test]
    fn test_hash_pair_order_matters() {
        let hasher = Blake3Hasher::new();

        let left = hasher.hash_bytes(b"left").unwrap();
        let right = hasher.hash_bytes(b"right").unwrap();

        let pair_lr = hasher.hash_pair(&left, &right).unwrap();
        let pair_rl = hasher.hash_pair(&right, &left).unwrap();

        assert_ne!(pair_lr, pair_rl);
    }

    #[test]
    fn test_hash_entry_with_context() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let context = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("text/plain".to_string()),
            metadata: HashMap::new(),
        };

        let data = b"ledger entry data";
        let hash = hasher.hash_entry(data, &context).unwrap();

        assert_ne!(hash, HashOutput::zero());

        let hash2 = hasher.hash_entry(data, &context).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_entry_context_affects_hash() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();
        let data = b"same data";

        let context1 = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("text/plain".to_string()),
            metadata: HashMap::new(),
        };

        let context2 = EntryHashContext {
            entry_id,
            version: 2, // different version
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("text/plain".to_string()),
            metadata: HashMap::new(),
        };

        let hash1 = hasher.hash_entry(data, &context1).unwrap();
        let hash2 = hasher.hash_entry(data, &context2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_entry_with_metadata() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "test_user".to_string());
        metadata.insert("category".to_string(), "document".to_string());

        let context = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("application/json".to_string()),
            metadata,
        };

        let hash = hasher.hash_entry(b"test data", &context).unwrap();
        assert_ne!(hash, HashOutput::zero());
    }

    #[test]
    fn test_hash_entry_metadata_order_independence() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let mut metadata1 = HashMap::new();
        metadata1.insert("z_key".to_string(), "value1".to_string());
        metadata1.insert("a_key".to_string(), "value2".to_string());

        let mut metadata2 = HashMap::new();
        metadata2.insert("a_key".to_string(), "value2".to_string());
        metadata2.insert("z_key".to_string(), "value1".to_string());

        let context1 = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: metadata1,
        };

        let context2 = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: metadata2,
        };

        let hash1 = hasher.hash_entry(b"test", &context1).unwrap();
        let hash2 = hasher.hash_entry(b"test", &context2).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_many_deterministic() {
        let hasher = Blake3Hasher::new();

        let inputs = [
            b"input1".as_slice(),
            b"input2".as_slice(),
            b"input3".as_slice(),
        ];

        let hash1 = hasher.hash_many(&inputs).unwrap();
        let hash2 = hasher.hash_many(&inputs).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_many_order_matters() {
        let hasher = Blake3Hasher::new();

        let inputs1 = [b"first".as_slice(), b"second".as_slice()];
        let inputs2 = [b"second".as_slice(), b"first".as_slice()];

        let hash1 = hasher.hash_many(&inputs1).unwrap();
        let hash2 = hasher.hash_many(&inputs2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_domain_separation() {
        let hasher = Blake3Hasher::new();
        let data = b"same data for all methods";

        let bytes_hash = hasher.hash_bytes(data).unwrap();

        let dummy_hash = hasher.hash_bytes(b"dummy").unwrap();
        let pair_hash = hasher.hash_pair(&dummy_hash, &dummy_hash).unwrap();

        let context = EntryHashContext {
            entry_id: Uuid::new_v4(),
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: HashMap::new(),
        };
        let entry_hash = hasher.hash_entry(data, &context).unwrap();

        assert_ne!(bytes_hash, pair_hash);
        assert_ne!(bytes_hash, entry_hash);
        assert_ne!(pair_hash, entry_hash);
    }

    #[test]
    fn test_empty_input_handling() {
        let hasher = Blake3Hasher::new();

        let empty_hash = hasher.hash_bytes(&[]).unwrap();
        assert_ne!(empty_hash, HashOutput::zero());

        let empty_many = hasher.hash_many(&[]).unwrap();
        assert_ne!(empty_many, HashOutput::zero());

        assert_ne!(empty_hash, empty_many);
    }

    #[test]
    fn test_context_serialization_deterministic() {
        let entry_id = Uuid::new_v4();
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        let context = EntryHashContext {
            entry_id,
            version: 42,
            timestamp: 1234567890,
            previous_id: Some(Uuid::new_v4()),
            content_type: Some("application/json".to_string()),
            metadata,
        };

        let bytes1 = Blake3Hasher::serialize_entry_context(&context).unwrap();
        let bytes2 = Blake3Hasher::serialize_entry_context(&context).unwrap();

        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    proptest! {
        #[test]
        fn prop_hash_bytes_deterministic(data: Vec<u8>) {
            let hasher = Blake3Hasher::new();
            let hash1 = hasher.hash_bytes(&data).unwrap();
            let hash2 = hasher.hash_bytes(&data).unwrap();
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_hash_bytes_different_inputs_different_outputs(
            data1: Vec<u8>,
            data2: Vec<u8>
        ) {
            prop_assume!(data1 != data2);
            let hasher = Blake3Hasher::new();
            let hash1 = hasher.hash_bytes(&data1).unwrap();
            let hash2 = hasher.hash_bytes(&data2).unwrap();
            prop_assert_ne!(hash1, hash2);
        }

        #[test]
        fn prop_hash_pair_deterministic(left_data: Vec<u8>, right_data: Vec<u8>) {
            let hasher = Blake3Hasher::new();
            let left = hasher.hash_bytes(&left_data).unwrap();
            let right = hasher.hash_bytes(&right_data).unwrap();

            let pair1 = hasher.hash_pair(&left, &right).unwrap();
            let pair2 = hasher.hash_pair(&left, &right).unwrap();
            prop_assert_eq!(pair1, pair2);
        }

        #[test]
        fn prop_hash_pair_order_sensitivity(
            left_data: Vec<u8>,
            right_data: Vec<u8>
        ) {
            prop_assume!(left_data != right_data);
            let hasher = Blake3Hasher::new();
            let left = hasher.hash_bytes(&left_data).unwrap();
            let right = hasher.hash_bytes(&right_data).unwrap();

            let pair_lr = hasher.hash_pair(&left, &right).unwrap();
            let pair_rl = hasher.hash_pair(&right, &left).unwrap();
            prop_assert_ne!(pair_lr, pair_rl);
        }

        #[test]
        fn prop_hash_entry_deterministic(
            data: Vec<u8>,
            version: u64,
            timestamp: u64,
            content_type in prop::option::of("[a-zA-Z0-9/]+"),
            metadata_size in 0usize..10
        ) {
            let hasher = Blake3Hasher::new();
            let entry_id = Uuid::new_v4();

            let mut metadata = HashMap::new();
            for i in 0..metadata_size {
                metadata.insert(format!("key{}", i), format!("value{}", i));
            }

            let context = EntryHashContext {
                entry_id,
                version,
                timestamp,
                previous_id: None,
                content_type,
                metadata,
            };

            let hash1 = hasher.hash_entry(&data, &context).unwrap();
            let hash2 = hasher.hash_entry(&data, &context).unwrap();
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_hash_entry_version_sensitivity(
            data: Vec<u8>,
            version1: u64,
            version2: u64,
            timestamp: u64
        ) {
            prop_assume!(version1 != version2);
            let hasher = Blake3Hasher::new();
            let entry_id = Uuid::new_v4();

            let context1 = EntryHashContext {
                entry_id,
                version: version1,
                timestamp,
                previous_id: None,
                content_type: None,
                metadata: HashMap::new(),
            };

            let context2 = EntryHashContext {
                entry_id,
                version: version2,
                timestamp,
                previous_id: None,
                content_type: None,
                metadata: HashMap::new(),
            };

            let hash1 = hasher.hash_entry(&data, &context1).unwrap();
            let hash2 = hasher.hash_entry(&data, &context2).unwrap();
            prop_assert_ne!(hash1, hash2);
        }

        #[test]
        fn prop_hash_many_deterministic(inputs: Vec<Vec<u8>>) {
            let hasher = Blake3Hasher::new();
            let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

            let hash1 = hasher.hash_many(&input_refs).unwrap();
            let hash2 = hasher.hash_many(&input_refs).unwrap();
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_hash_many_order_sensitivity(
            input1: Vec<u8>,
            input2: Vec<u8>,
            input3: Vec<u8>
        ) {
            prop_assume!(input1 != input2 || input1 != input3 || input2 != input3);
            let hasher = Blake3Hasher::new();

            let inputs1 = [input1.as_slice(), input2.as_slice(), input3.as_slice()];
            let inputs2 = [input3.as_slice(), input1.as_slice(), input2.as_slice()];

            let hash1 = hasher.hash_many(&inputs1).unwrap();
            let hash2 = hasher.hash_many(&inputs2).unwrap();
            prop_assert_ne!(hash1, hash2);
        }

        #[test]
        fn prop_domain_separation_effectiveness(data: Vec<u8>) {
            let hasher = Blake3Hasher::new();

            let bytes_hash = hasher.hash_bytes(&data).unwrap();
            let many_hash = hasher.hash_many(&[&data]).unwrap();

            prop_assert_ne!(bytes_hash, many_hash);
        }

        #[test]
        fn prop_context_serialization_consistency(
            version: u64,
            timestamp: u64,
            has_previous: bool,
            content_type in prop::option::of("[a-zA-Z0-9/.-_]+"),
            metadata_pairs: Vec<(String, String)>
        ) {
            let entry_id = Uuid::new_v4();
            let previous_id = if has_previous { Some(Uuid::new_v4()) } else { None };

            let mut metadata = HashMap::new();
            for (key, value) in metadata_pairs {
                metadata.insert(key, value);
            }

            let context = EntryHashContext {
                entry_id,
                version,
                timestamp,
                previous_id,
                content_type,
                metadata,
            };

            let bytes1 = Blake3Hasher::serialize_entry_context(&context).unwrap();
            let bytes2 = Blake3Hasher::serialize_entry_context(&context).unwrap();

            prop_assert_eq!(bytes1, bytes2);
        }

        #[test]
        fn prop_hash_output_properties(data: Vec<u8>) {
            let hasher = Blake3Hasher::new();
            let hash = hasher.hash_bytes(&data).unwrap();

            prop_assert_eq!(hash.as_bytes().len(), 32);

            prop_assert_eq!(hash.to_hex().len(), 64);

            prop_assert_ne!(hash, HashOutput::zero());
        }

        #[test]
        fn prop_hash_collision_resistance(
            data1: Vec<u8>,
            data2: Vec<u8>,
            seed: u64
        ) {
            prop_assume!(data1 != data2);
            prop_assume!(data1.len() > 0 || data2.len() > 0); // at least one non-empty

            let hasher = Blake3Hasher::new();

            let mut modified_data1 = data1;
            let mut modified_data2 = data2;
            modified_data1.extend_from_slice(&seed.to_be_bytes());
            modified_data2.extend_from_slice(&(seed + 1).to_be_bytes());

            let hash1 = hasher.hash_bytes(&modified_data1).unwrap();
            let hash2 = hasher.hash_bytes(&modified_data2).unwrap();

            prop_assert_ne!(hash1, hash2);
        }
    }

    #[test]
    fn test_hash_very_large_input() {
        let hasher = Blake3Hasher::new();
        let large_data = vec![0xAA; 1_000_000]; // 1mb of data

        let hash = hasher.hash_bytes(&large_data).unwrap();
        assert_ne!(hash, HashOutput::zero());

        let hash2 = hasher.hash_bytes(&large_data).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_context_with_unicode_metadata() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "Alice 👩‍💻".to_string());
        metadata.insert(
            "title".to_string(),
            "Document with émojis and açcénts".to_string(),
        );
        metadata.insert("tags".to_string(), "🏷️ test, 📝 document".to_string());

        let context = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("text/markdown".to_string()),
            metadata,
        };

        let hash = hasher
            .hash_entry("Unicode test data 🦀".as_bytes(), &context)
            .unwrap();
        assert_ne!(hash, HashOutput::zero());

        let hash2 = hasher
            .hash_entry("Unicode test data 🦀".as_bytes(), &context)
            .unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_extreme_metadata_sizes() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let mut large_metadata = HashMap::new();
        for i in 0..1000 {
            large_metadata.insert(
                format!("key_{:04}", i),
                format!("value_with_lots_of_data_{:04}_{}", i, "x".repeat(100)),
            );
        }

        let context = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: large_metadata,
        };

        let hash = hasher.hash_entry(b"test", &context).unwrap();
        assert_ne!(hash, HashOutput::zero());
    }

    #[test]
    fn test_metadata_key_ordering_determinism() {
        let hasher = Blake3Hasher::new();
        let entry_id = Uuid::new_v4();

        let mut metadata1 = HashMap::new();
        metadata1.insert("zzz".to_string(), "last".to_string());
        metadata1.insert("mmm".to_string(), "middle".to_string());
        metadata1.insert("aaa".to_string(), "first".to_string());

        let mut metadata2 = HashMap::new();
        metadata2.insert("aaa".to_string(), "first".to_string());
        metadata2.insert("mmm".to_string(), "middle".to_string());
        metadata2.insert("zzz".to_string(), "last".to_string());

        let context1 = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: metadata1,
        };

        let context2 = EntryHashContext {
            entry_id,
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: None,
            metadata: metadata2,
        };

        let hash1 = hasher.hash_entry(b"test", &context1).unwrap();
        let hash2 = hasher.hash_entry(b"test", &context2).unwrap();

        assert_eq!(hash1, hash2);
    }
}
