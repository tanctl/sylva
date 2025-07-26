//! proof system for the Sylva ledger

use crate::error::Result;
use crate::hash::{Blake3Hasher, Hash, HashOutput};
use crate::tree::MerkleProof;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// cryptographic proof for ledger entries
pub struct Proof {
    /// id of the entry this proof is for
    pub entry_id: Uuid,
    /// version of the entry
    pub version: u64,
    /// merkle tree proof
    pub merkle_proof: MerkleProof,
    /// when proof was generated
    pub timestamp: u64,
    /// additional proof metadata
    pub metadata: ProofMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// metadata for proofs
pub struct ProofMetadata {
    /// type of proof (existence, integrity, etc)
    pub proof_type: ProofType,
    /// hash algorithm used
    pub algorithm: String,
    /// extra proof properties
    pub properties: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// types of proofs we can generate
pub enum ProofType {
    /// proof that entry exists
    Existence,
    /// proof that entry does not exist
    NonExistence,
    /// proof of data integrity
    Integrity,
    /// proof of authenticity
    Authenticity,
}

impl Proof {
    /// create new proof
    pub fn new(
        entry_id: Uuid,
        version: u64,
        merkle_proof: MerkleProof,
        proof_type: ProofType,
    ) -> Self {
        Self {
            entry_id,
            version,
            merkle_proof,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata: ProofMetadata {
                proof_type,
                algorithm: "SHA256-Merkle".to_string(),
                properties: std::collections::HashMap::new(),
            },
        }
    }

    /// verify proof against given data
    pub fn verify(&self, data: &[u8]) -> Result<bool> {
        let merkle_valid = crate::tree::MerkleTree::verify_proof(&self.merkle_proof, data)?;

        if !merkle_valid {
            return Ok(false);
        }

        match self.metadata.proof_type {
            ProofType::Existence => Ok(true), // Merkle proof is sufficient
            ProofType::NonExistence => {
                // todo: implement non-existence proof verification
                Ok(false)
            }
            ProofType::Integrity => {
                // todo: implement integrity proof verification
                Ok(merkle_valid)
            }
            ProofType::Authenticity => {
                // todo: implement authenticity proof verification
                Ok(merkle_valid)
            }
        }
    }

    /// get hash of the proof itself
    pub fn proof_hash(&self) -> HashOutput {
        let proof_data = serde_json::to_vec(self).unwrap_or_default();
        let hasher = Blake3Hasher::new();
        hasher.hash_bytes(&proof_data).unwrap()
    }

    /// add custom property to proof
    pub fn add_property(&mut self, key: String, value: String) {
        self.metadata.properties.insert(key, value);
    }

    /// get custom property from proof
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.properties.get(key)
    }

    /// check if proof has expired
    pub fn is_expired(&self, ttl_seconds: u64) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        current_time > self.timestamp + ttl_seconds
    }
}

#[derive(Debug)]
/// generates cryptographic proofs
pub struct ProofGenerator {
    algorithm: String,
}

impl Default for ProofGenerator {
    fn default() -> Self {
        Self {
            algorithm: "SHA256-Merkle".to_string(),
        }
    }
}

impl ProofGenerator {
    /// create proof generator with specific algorithm
    pub fn new(algorithm: String) -> Self {
        Self { algorithm }
    }

    /// generate proof that entry exists
    pub fn generate_existence_proof(
        &self,
        entry_id: Uuid,
        version: u64,
        data: &[u8],
        merkle_proof: MerkleProof,
    ) -> Result<Proof> {
        let mut proof = Proof::new(entry_id, version, merkle_proof, ProofType::Existence);
        proof.metadata.algorithm = self.algorithm.clone();
        proof.add_property("data_size".to_string(), data.len().to_string());
        Ok(proof)
    }

    /// generate proof of data integrity
    pub fn generate_integrity_proof(
        &self,
        entry_id: Uuid,
        version: u64,
        data: &[u8],
        merkle_proof: MerkleProof,
    ) -> Result<Proof> {
        let mut proof = Proof::new(entry_id, version, merkle_proof, ProofType::Integrity);
        proof.metadata.algorithm = self.algorithm.clone();

        let hasher = Blake3Hasher::new();
        let data_hash = hasher.hash_bytes(data)?;
        proof.add_property("data_hash".to_string(), data_hash.to_hex());

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleProof;

    #[test]
    fn test_proof_creation() {
        let entry_id = Uuid::new_v4();
        let merkle_proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
            root: HashOutput::new([0u8; 32]),
        };

        let proof = Proof::new(entry_id, 1, merkle_proof, ProofType::Existence);
        assert_eq!(proof.entry_id, entry_id);
        assert_eq!(proof.version, 1);
    }

    #[test]
    fn test_proof_properties() {
        let entry_id = Uuid::new_v4();
        let merkle_proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
            root: HashOutput::new([0u8; 32]),
        };

        let mut proof = Proof::new(entry_id, 1, merkle_proof, ProofType::Existence);
        proof.add_property("test_key".to_string(), "test_value".to_string());

        assert_eq!(
            proof.get_property("test_key"),
            Some(&"test_value".to_string())
        );
        assert_eq!(proof.get_property("missing_key"), None);
    }

    #[test]
    fn test_proof_generator() {
        let generator = ProofGenerator::default();
        let entry_id = Uuid::new_v4();
        let data = b"test data";
        let merkle_proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
            root: HashOutput::new([0u8; 32]),
        };

        let proof = generator
            .generate_existence_proof(entry_id, 1, data, merkle_proof)
            .unwrap();
        assert_eq!(proof.entry_id, entry_id);
        assert!(matches!(proof.metadata.proof_type, ProofType::Existence));
    }
}
