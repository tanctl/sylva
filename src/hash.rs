//! hash utilities

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex).map_err(|e| SylvaError::hash_error(format!("Invalid hex: {}", e)))?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

pub trait Hasher {
    fn hash(&self, data: &[u8]) -> Hash;

    fn hash_many(&self, inputs: &[&[u8]]) -> Hash {
        let mut combined = Vec::new();
        for input in inputs {
            combined.extend_from_slice(input);
        }
        self.hash(&combined)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Hash {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher as StdHasher};

        // todo: use sha2 crate in production
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash_value = hasher.finish();

        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&hash_value.to_be_bytes());
        Hash(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_creation() {
        let bytes = [1u8; 32];
        let hash = Hash::new(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_hex_conversion() {
        let bytes = [1u8; 32];
        let hash = Hash::new(bytes);
        let hex = hash.to_hex();
        let hash2 = Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hasher() {
        let hasher = Sha256Hasher;
        let data = b"test data";
        let hash1 = hasher.hash(data);
        let hash2 = hasher.hash(data);
        assert_eq!(hash1, hash2);
    }
}
