use super::{utils, Direction, MerkleProof, ProofError, SiblingHash};
use crate::error::Result;
use crate::hash::{Blake3Hasher, Hash as HashTrait, HashDigest};
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Merkle inclusion proof for verifying that a specific entry exists in a Merkle tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The unique identifier of the entry this proof is for
    pub entry_id: Uuid,
    /// The index of the leaf in the tree (0-based)
    pub leaf_index: usize,
    /// The hash of the leaf node
    pub leaf_hash: HashDigest,
    /// The sibling hashes along the path from leaf to root
    pub sibling_hashes: Vec<SiblingHash>,
    /// The root hash this proof verifies against
    pub root_hash: HashDigest,
    /// Total number of leaves in the tree when this proof was generated
    pub tree_size: usize,
}

impl InclusionProof {
    /// Create a new inclusion proof
    pub fn new(
        entry_id: Uuid,
        leaf_index: usize,
        leaf_hash: HashDigest,
        sibling_hashes: Vec<SiblingHash>,
        root_hash: HashDigest,
        tree_size: usize,
    ) -> Self {
        Self {
            entry_id,
            leaf_index,
            leaf_hash,
            sibling_hashes,
            root_hash,
            tree_size,
        }
    }

    /// Generate an inclusion proof for a given leaf index in a binary tree
    pub fn generate_for_leaf_index(
        entry_id: Uuid,
        leaf_index: usize,
        leaves: &[HashDigest],
    ) -> Result<Self> {
        if leaves.is_empty() {
            return Err(ProofError::EmptyTree.into());
        }

        if leaf_index >= leaves.len() {
            return Err(ProofError::InvalidLeafIndex {
                index: leaf_index,
                total_leaves: leaves.len(),
            }
            .into());
        }

        let leaf_hash = leaves[leaf_index].clone();
        let tree_size = leaves.len();

        // Build the complete tree to generate the proof
        let (root_hash, sibling_hashes) = Self::build_tree_and_extract_proof(leaves, leaf_index)?;

        Ok(Self::new(
            entry_id,
            leaf_index,
            leaf_hash,
            sibling_hashes,
            root_hash,
            tree_size,
        ))
    }

    /// Build a complete binary tree and extract the proof path for a specific leaf
    fn build_tree_and_extract_proof(
        leaves: &[HashDigest],
        target_index: usize,
    ) -> Result<(HashDigest, Vec<SiblingHash>)> {
        if leaves.is_empty() {
            return Err(ProofError::EmptyTree.into());
        }

        // Handle single leaf case
        if leaves.len() == 1 {
            if target_index != 0 {
                return Err(ProofError::InvalidLeafIndex {
                    index: target_index,
                    total_leaves: leaves.len(),
                }
                .into());
            }
            return Ok((leaves[0].clone(), vec![]));
        }

        let mut current_level = leaves.to_vec();
        let mut sibling_hashes = Vec::new();
        let mut current_index = target_index;

        // Build tree level by level, tracking sibling hashes for the target path
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            // Process pairs of nodes
            for i in (0..current_level.len()).step_by(2) {
                let left_hash = current_level[i].clone();
                let right_hash = if i + 1 < current_level.len() {
                    current_level[i + 1].clone()
                } else {
                    // Odd number of nodes, duplicate the last one
                    left_hash.clone()
                };

                // Check if the target index is in this pair
                if current_index == i || current_index == i + 1 {
                    // This pair contains our target node, record the sibling
                    if current_index == i {
                        // Target is left node, sibling is right
                        sibling_hashes.push(SiblingHash::new(right_hash.clone(), Direction::Right));
                    } else {
                        // Target is right node, sibling is left
                        sibling_hashes.push(SiblingHash::new(left_hash.clone(), Direction::Left));
                    }
                    // Update index for next level (parent index)
                    current_index = i / 2;
                }

                // Combine left and right to create parent hash
                let parent_hash = Self::hash_pair(&left_hash, &right_hash)?;
                next_level.push(parent_hash);
            }

            current_level = next_level;
        }

        // The last remaining hash is the root
        let root_hash =
            current_level
                .into_iter()
                .next()
                .ok_or_else(|| ProofError::InvalidStructure {
                    reason: "Failed to compute root hash".to_string(),
                })?;

        Ok((root_hash, sibling_hashes))
    }

    /// Hash a pair of child hashes to create parent hash with security validations
    fn hash_pair(left: &HashDigest, right: &HashDigest) -> Result<HashDigest> {
        // Validate hash inputs are of correct length
        if left.as_bytes().len() != 32 {
            return Err(ProofError::InvalidHashFormat {
                reason: format!(
                    "Left hash has invalid length: {} bytes, expected 32",
                    left.as_bytes().len()
                ),
            }
            .into());
        }

        if right.as_bytes().len() != 32 {
            return Err(ProofError::InvalidHashFormat {
                reason: format!(
                    "Right hash has invalid length: {} bytes, expected 32",
                    right.as_bytes().len()
                ),
            }
            .into());
        }

        let hasher = Blake3Hasher::new();
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left.as_bytes());
        combined.extend_from_slice(right.as_bytes());

        hasher.hash_bytes(&combined).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: format!("Blake3 hash computation failed: {}", e),
            }
            .into()
        })
    }

    /// Cryptographically secure verification of the inclusion proof
    pub fn verify_against_root(&self, root_hash: &HashDigest) -> Result<bool> {
        // Comprehensive security validations first
        self.validate_proof_security(root_hash)?;

        // Perform constant-time root hash reconstruction
        let reconstructed_root = self.reconstruct_root_hash_secure()?;

        // Constant-time comparison to prevent timing attacks
        let root_matches = self.constant_time_hash_compare(&reconstructed_root, root_hash);

        if !root_matches {
            return Err(ProofError::VerificationFailed {
                computed: hex::encode(reconstructed_root.as_bytes()),
                expected: hex::encode(root_hash.as_bytes()),
            }
            .into());
        }

        Ok(true)
    }

    /// Perform comprehensive security validation of the proof
    fn validate_proof_security(&self, root_hash: &HashDigest) -> Result<()> {
        // Validate root hash format
        if root_hash.as_bytes().len() != 32 {
            return Err(ProofError::InvalidHashFormat {
                reason: format!(
                    "Root hash has invalid length: {} bytes, expected 32",
                    root_hash.as_bytes().len()
                ),
            }
            .into());
        }

        // Validate leaf hash format
        if self.leaf_hash.as_bytes().len() != 32 {
            return Err(ProofError::InvalidHashFormat {
                reason: format!(
                    "Leaf hash has invalid length: {} bytes, expected 32",
                    self.leaf_hash.as_bytes().len()
                ),
            }
            .into());
        }

        // Validate proof's internal root hash format
        if self.root_hash.as_bytes().len() != 32 {
            return Err(ProofError::InvalidHashFormat {
                reason: "Proof's internal root hash has invalid length".to_string(),
            }
            .into());
        }

        // Check for excessive proof depth (potential DoS attack)
        let max_reasonable_depth = 64; // 2^64 leaves should be more than enough
        if self.sibling_hashes.len() > max_reasonable_depth {
            return Err(ProofError::MaliciousProof {
                attack_type: format!(
                    "Excessive proof depth: {} > {}",
                    self.sibling_hashes.len(),
                    max_reasonable_depth
                ),
            }
            .into());
        }

        // Validate each sibling hash
        for (i, sibling) in self.sibling_hashes.iter().enumerate() {
            if sibling.hash.as_bytes().len() != 32 {
                return Err(ProofError::InvalidHashFormat {
                    reason: format!(
                        "Sibling hash {} has invalid length: {} bytes",
                        i,
                        sibling.hash.as_bytes().len()
                    ),
                }
                .into());
            }

            // Check for suspicious patterns that might indicate attacks
            if self.is_suspicious_hash(&sibling.hash) {
                return Err(ProofError::MaliciousProof {
                    attack_type: format!("Suspicious hash pattern detected in sibling {}", i),
                }
                .into());
            }
        }

        // Validate proof depth consistency
        let expected_max_depth = utils::tree_height(self.tree_size);
        if self.sibling_hashes.len() > expected_max_depth {
            return Err(ProofError::ProofDepthMismatch {
                expected: expected_max_depth,
                actual: self.sibling_hashes.len(),
            }
            .into());
        }

        // Check for leaf index bounds
        if self.leaf_index >= self.tree_size {
            return Err(ProofError::InvalidLeafIndex {
                index: self.leaf_index,
                total_leaves: self.tree_size,
            }
            .into());
        }

        // Additional security: Check for zero tree size
        if self.tree_size == 0 {
            return Err(ProofError::InvalidStructure {
                reason: "Proof claims tree size of zero".to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// Securely reconstruct root hash with validation at each step
    fn reconstruct_root_hash_secure(&self) -> Result<HashDigest> {
        // Start with validated leaf hash
        let mut current_hash = self.leaf_hash.clone();

        // Track path reconstruction for debugging
        let mut path_hashes = Vec::with_capacity(self.sibling_hashes.len() + 1);
        path_hashes.push(current_hash.clone());

        // Apply each sibling hash with validation
        for (step, sibling) in self.sibling_hashes.iter().enumerate() {
            // Validate the current computation step
            let next_hash = match sibling.direction {
                Direction::Left => {
                    // Sibling is on the left, current node is on the right
                    Self::hash_pair(&sibling.hash, &current_hash).map_err(|e| {
                        ProofError::PathReconstructionFailed {
                            reason: format!(
                                "Step {}: Failed to hash with left sibling: {}",
                                step, e
                            ),
                        }
                    })?
                }
                Direction::Right => {
                    // Sibling is on the right, current node is on the left
                    Self::hash_pair(&current_hash, &sibling.hash).map_err(|e| {
                        ProofError::PathReconstructionFailed {
                            reason: format!(
                                "Step {}: Failed to hash with right sibling: {}",
                                step, e
                            ),
                        }
                    })?
                }
            };

            // Validate intermediate hash
            if next_hash.as_bytes().len() != 32 {
                return Err(ProofError::PathReconstructionFailed {
                    reason: format!("Step {}: Intermediate hash has invalid length", step),
                }
                .into());
            }

            current_hash = next_hash;
            path_hashes.push(current_hash.clone());
        }

        // Final validation
        if current_hash.as_bytes().len() != 32 {
            return Err(ProofError::PathReconstructionFailed {
                reason: "Final reconstructed root hash has invalid length".to_string(),
            }
            .into());
        }

        Ok(current_hash)
    }

    /// Constant-time hash comparison to prevent timing attacks
    fn constant_time_hash_compare(&self, hash1: &HashDigest, hash2: &HashDigest) -> bool {
        let bytes1 = hash1.as_bytes();
        let bytes2 = hash2.as_bytes();

        if bytes1.len() != bytes2.len() {
            return false;
        }

        // Constant-time comparison using bitwise operations
        let mut result = 0u8;
        for i in 0..bytes1.len() {
            result |= bytes1[i] ^ bytes2[i];
        }

        result == 0
    }

    /// Check for suspicious hash patterns that might indicate attacks
    fn is_suspicious_hash(&self, hash: &HashDigest) -> bool {
        let bytes = hash.as_bytes();

        // Check for all-zero hash (potentially invalid)
        if bytes.iter().all(|&b| b == 0) {
            return true;
        }

        // Check for all-ones hash (potentially crafted)
        if bytes.iter().all(|&b| b == 0xFF) {
            return true;
        }

        // Check for repetitive patterns (might indicate weak randomness)
        if bytes.len() >= 4 {
            let pattern = &bytes[0..4];
            let chunks: Vec<&[u8]> = bytes.chunks(4).collect();
            if chunks.len() >= 4 && chunks[0..4].iter().all(|&chunk| chunk == pattern) {
                return true;
            }
        }

        false
    }

    /// Verify the proof structure is valid
    pub fn validate_structure(&self) -> Result<bool> {
        // Check tree size constraints
        if self.tree_size == 0 {
            return Err(ProofError::InvalidStructure {
                reason: "Tree size cannot be zero".to_string(),
            }
            .into());
        }

        // Check leaf index bounds
        if self.leaf_index >= self.tree_size {
            return Err(ProofError::InvalidLeafIndex {
                index: self.leaf_index,
                total_leaves: self.tree_size,
            }
            .into());
        }

        // Check proof depth is consistent with tree size
        let expected_max_depth = utils::tree_height(self.tree_size);
        if self.sibling_hashes.len() > expected_max_depth {
            return Err(ProofError::InvalidStructure {
                reason: format!(
                    "Proof depth {} exceeds maximum expected depth {} for tree size {}",
                    self.sibling_hashes.len(),
                    expected_max_depth,
                    self.tree_size
                ),
            }
            .into());
        }

        // For single leaf trees, there should be no sibling hashes
        if self.tree_size == 1 && !self.sibling_hashes.is_empty() {
            return Err(ProofError::InvalidStructure {
                reason: "Single leaf tree should have no sibling hashes".to_string(),
            }
            .into());
        }

        Ok(true)
    }

    /// Get the directions along the path from leaf to root
    pub fn get_path_directions(&self) -> Vec<Direction> {
        self.sibling_hashes
            .iter()
            .map(|sibling| sibling.direction.opposite())
            .collect()
    }

    /// Calculate the approximate memory size of this proof
    pub fn memory_footprint(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.sibling_hashes.len() * std::mem::size_of::<SiblingHash>())
    }

    /// Check if this proof can be used for the given tree size
    pub fn is_compatible_with_tree_size(&self, tree_size: usize) -> bool {
        self.tree_size == tree_size && self.leaf_index < tree_size
    }

    /// Convert to a compact binary representation
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            ProofError::InvalidStructure {
                reason: format!("Serialization failed: {}", e),
            }
            .into()
        })
    }

    /// Restore from compact binary representation
    pub fn from_compact_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            ProofError::InvalidStructure {
                reason: format!("Deserialization failed: {}", e),
            }
            .into()
        })
    }
}

impl MerkleProof for InclusionProof {
    fn verify(&self, root_hash: &HashDigest, entry: &LedgerEntry) -> Result<bool> {
        // Verify the entry ID matches
        if self.entry_id != entry.id {
            return Ok(false);
        }

        // Verify structure is valid
        self.validate_structure()?;

        // Compute the expected leaf hash from the entry
        let hasher = Blake3Hasher::new();
        let computed_leaf_hash = hasher.hash_bytes(&entry.data)?;

        // Verify the leaf hash matches
        if self.leaf_hash != computed_leaf_hash {
            return Ok(false);
        }

        // Verify the proof against the root
        self.verify_against_root(root_hash)
    }

    fn entry_id(&self) -> &Uuid {
        &self.entry_id
    }

    fn leaf_hash(&self) -> &HashDigest {
        &self.leaf_hash
    }

    fn depth(&self) -> usize {
        self.sibling_hashes.len()
    }

    fn is_valid(&self) -> bool {
        self.validate_structure().unwrap_or(false)
    }

    fn memory_size(&self) -> usize {
        self.memory_footprint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Blake3Hasher, Hash as HashTrait};

    fn create_test_leaf_hash(data: &[u8]) -> HashDigest {
        let hasher = Blake3Hasher::new();
        hasher.hash_bytes(data).unwrap()
    }

    #[test]
    fn test_single_leaf_proof() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"single leaf");
        let leaves = vec![leaf_hash.clone()];

        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        assert_eq!(proof.entry_id, entry_id);
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, leaf_hash);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.sibling_hashes.is_empty());
        assert_eq!(proof.root_hash, leaf_hash);
        assert!(proof.is_valid());
    }

    #[test]
    fn test_two_leaf_proof() {
        let entry_id = Uuid::new_v4();
        let leaf1 = create_test_leaf_hash(b"leaf 1");
        let leaf2 = create_test_leaf_hash(b"leaf 2");
        let leaves = vec![leaf1.clone(), leaf2.clone()];

        // Test proof for first leaf
        let proof1 = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        assert_eq!(proof1.leaf_index, 0);
        assert_eq!(proof1.leaf_hash, leaf1);
        assert_eq!(proof1.sibling_hashes.len(), 1);
        assert_eq!(proof1.sibling_hashes[0].hash, leaf2);
        assert_eq!(proof1.sibling_hashes[0].direction, Direction::Right);
        assert!(proof1.is_valid());

        // Test proof for second leaf
        let proof2 = InclusionProof::generate_for_leaf_index(entry_id, 1, &leaves).unwrap();

        assert_eq!(proof2.leaf_index, 1);
        assert_eq!(proof2.leaf_hash, leaf2);
        assert_eq!(proof2.sibling_hashes.len(), 1);
        assert_eq!(proof2.sibling_hashes[0].hash, leaf1);
        assert_eq!(proof2.sibling_hashes[0].direction, Direction::Left);
        assert!(proof2.is_valid());

        // Both proofs should have the same root
        assert_eq!(proof1.root_hash, proof2.root_hash);
    }

    #[test]
    fn test_four_leaf_proof() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        // Test proof for each leaf
        for i in 0..4 {
            let proof = InclusionProof::generate_for_leaf_index(entry_id, i, &leaves).unwrap();

            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.leaf_hash, leaves[i]);
            assert_eq!(proof.tree_size, 4);
            assert_eq!(proof.sibling_hashes.len(), 2); // Tree height for 4 leaves
            assert!(proof.is_valid());

            // Verify the proof
            assert!(proof.verify_against_root(&proof.root_hash).unwrap());
        }
    }

    #[test]
    fn test_odd_number_leaves() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..3)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        // Test proof for each leaf
        for i in 0..3 {
            let proof = InclusionProof::generate_for_leaf_index(entry_id, i, &leaves).unwrap();

            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.leaf_hash, leaves[i]);
            assert_eq!(proof.tree_size, 3);
            assert!(proof.is_valid());

            // Verify the proof
            assert!(proof.verify_against_root(&proof.root_hash).unwrap());
        }
    }

    #[test]
    fn test_large_tree_proof() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..8)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        // Test proof for first and last leaf
        let proof_first = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();
        let proof_last = InclusionProof::generate_for_leaf_index(entry_id, 7, &leaves).unwrap();

        assert_eq!(proof_first.sibling_hashes.len(), 3); // Tree height for 8 leaves
        assert_eq!(proof_last.sibling_hashes.len(), 3);
        assert!(proof_first.is_valid());
        assert!(proof_last.is_valid());

        // Both should have the same root
        assert_eq!(proof_first.root_hash, proof_last.root_hash);
    }

    #[test]
    fn test_invalid_leaf_index() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![create_test_leaf_hash(b"only leaf")];

        let result = InclusionProof::generate_for_leaf_index(entry_id, 1, &leaves);
        assert!(result.is_err());

        let error = result.unwrap_err();
        if let crate::error::SylvaError::ProofError { source } = error {
            if let ProofError::InvalidLeafIndex {
                index,
                total_leaves,
            } = source
            {
                assert_eq!(index, 1);
                assert_eq!(total_leaves, 1);
            } else {
                panic!("Expected InvalidLeafIndex error");
            }
        } else {
            panic!("Expected ProofError");
        }
    }

    #[test]
    fn test_empty_tree() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![];

        let result = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves);
        assert!(result.is_err());

        let error = result.unwrap_err();
        if let crate::error::SylvaError::ProofError { source } = error {
            if let ProofError::EmptyTree = source {
                // Expected
            } else {
                panic!("Expected EmptyTree error");
            }
        } else {
            panic!("Expected ProofError");
        }
    }

    #[test]
    fn test_proof_verification_with_entry() {
        let mut entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let entry_id = entry.id;

        // Create a leaf hash for this entry
        let hasher = Blake3Hasher::new();
        let leaf_hash = hasher.hash_bytes(&entry.data).unwrap();
        let leaves = vec![leaf_hash.clone()];

        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        // Verify with the correct entry
        assert!(proof.verify(&proof.root_hash, &entry).unwrap());

        // Verify with wrong entry ID fails
        entry.id = Uuid::new_v4();
        assert!(!proof.verify(&proof.root_hash, &entry).unwrap());

        // Verify with wrong entry data fails
        entry.id = entry_id;
        entry.data = b"wrong data".to_vec();
        assert!(!proof.verify(&proof.root_hash, &entry).unwrap());
    }

    #[test]
    fn test_path_directions() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();
        let directions = proof.get_path_directions();

        // For leaf index 0 in a 4-leaf tree, path should be [Left, Left]
        assert_eq!(directions, vec![Direction::Left, Direction::Left]);
    }

    #[test]
    fn test_memory_footprint() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![create_test_leaf_hash(b"test")];
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        let footprint = proof.memory_footprint();
        assert!(footprint > 0);
        assert_eq!(footprint, proof.memory_size());
    }

    #[test]
    fn test_compatibility_check() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![create_test_leaf_hash(b"test")];
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        assert!(proof.is_compatible_with_tree_size(1));
        assert!(!proof.is_compatible_with_tree_size(2));
        assert!(!proof.is_compatible_with_tree_size(0));
    }

    #[test]
    fn test_serialization() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![
            create_test_leaf_hash(b"leaf1"),
            create_test_leaf_hash(b"leaf2"),
        ];
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        // Test compact binary serialization
        let bytes = proof.to_compact_bytes().unwrap();
        let restored = InclusionProof::from_compact_bytes(&bytes).unwrap();

        assert_eq!(proof, restored);

        // Test JSON serialization
        let json = serde_json::to_string(&proof).unwrap();
        let restored_json: InclusionProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof, restored_json);
    }

    #[test]
    fn test_structure_validation() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Valid proof
        let valid_proof =
            InclusionProof::new(entry_id, 0, leaf_hash.clone(), vec![], leaf_hash.clone(), 1);
        assert!(valid_proof.validate_structure().unwrap());

        // Invalid: zero tree size
        let invalid_proof =
            InclusionProof::new(entry_id, 0, leaf_hash.clone(), vec![], leaf_hash.clone(), 0);
        assert!(invalid_proof.validate_structure().is_err());

        // Invalid: leaf index out of bounds
        let invalid_proof =
            InclusionProof::new(entry_id, 1, leaf_hash.clone(), vec![], leaf_hash.clone(), 1);
        assert!(invalid_proof.validate_structure().is_err());
    }

    #[test]
    fn test_proof_depth_consistency() {
        let entry_id = Uuid::new_v4();

        // Test various tree sizes
        for size in [1, 2, 3, 4, 5, 8, 15, 16] {
            let leaves: Vec<HashDigest> = (0..size)
                .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
                .collect();

            let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();
            let expected_max_depth = utils::tree_height(size);

            // Proof depth should not exceed the theoretical maximum
            assert!(proof.depth() <= expected_max_depth);

            // For a complete binary tree, depth should match tree height
            if utils::is_power_of_2(size) || size == 1 {
                if size == 1 {
                    assert_eq!(proof.depth(), 0);
                } else {
                    assert_eq!(proof.depth(), expected_max_depth);
                }
            }
        }
    }

    // ===== CRYPTOGRAPHIC SECURITY TESTS =====

    #[test]
    fn test_secure_verification_valid_proof() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let proof = InclusionProof::generate_for_leaf_index(entry_id, 1, &leaves).unwrap();

        // Valid proof should verify successfully
        assert!(proof.verify_against_root(&proof.root_hash).unwrap());
    }

    #[test]
    fn test_security_invalid_root_hash() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![create_test_leaf_hash(b"test leaf")];
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        // Create a different root hash
        let wrong_root = create_test_leaf_hash(b"wrong root");

        let result = proof.verify_against_root(&wrong_root);
        assert!(result.is_err());

        // Should get specific verification failed error
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::VerificationFailed { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected VerificationFailed error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_invalid_hash_lengths() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create proof with invalid sibling hash (simulate wrong length by manipulating internal structure)
        let mut invalid_bytes = [0u8; 32];
        invalid_bytes[0..16].copy_from_slice(&[0u8; 16]);
        let invalid_hash = HashDigest::new(invalid_bytes);
        let sibling = SiblingHash::new(invalid_hash, Direction::Right);

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![sibling],
            leaf_hash.clone(),
            2,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect suspicious hash pattern
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::MaliciousProof { .. } => {
                        // Expected - zero hash is detected as suspicious
                    }
                    _ => panic!("Expected MaliciousProof error, got: {:?}", source),
                }
            } else {
                panic!("Expected ProofError, got: {:?}", e);
            }
        }
    }

    #[test]
    fn test_security_excessive_proof_depth() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create proof with excessive depth (potential DoS attack)
        let excessive_siblings: Vec<SiblingHash> = (0..100)
            .map(|i| {
                SiblingHash::new(
                    create_test_leaf_hash(format!("sibling {}", i).as_bytes()),
                    if i % 2 == 0 {
                        Direction::Left
                    } else {
                        Direction::Right
                    },
                )
            })
            .collect();

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            excessive_siblings,
            leaf_hash.clone(),
            1,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect malicious proof
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::MaliciousProof { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected MaliciousProof error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_suspicious_hash_patterns() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Test all-zero hash (suspicious)
        let zero_hash = HashDigest::new([0u8; 32]);
        let sibling = SiblingHash::new(zero_hash, Direction::Right);

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![sibling],
            leaf_hash.clone(),
            2,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect malicious proof
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::MaliciousProof { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected MaliciousProof error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_all_ones_hash() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Test all-ones hash (suspicious)
        let ones_hash = HashDigest::new([0xFFu8; 32]);
        let sibling = SiblingHash::new(ones_hash, Direction::Right);

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![sibling],
            leaf_hash.clone(),
            2,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect malicious proof
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::MaliciousProof { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected MaliciousProof error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_repetitive_hash_pattern() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create hash with repetitive pattern
        let mut repetitive_bytes = [0u8; 32];
        let pattern = [0xAB, 0xCD, 0xEF, 0x12];
        for i in 0..8 {
            repetitive_bytes[i * 4..(i + 1) * 4].copy_from_slice(&pattern);
        }
        let repetitive_hash = HashDigest::new(repetitive_bytes);
        let sibling = SiblingHash::new(repetitive_hash, Direction::Right);

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![sibling],
            leaf_hash.clone(),
            2,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect malicious proof
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::MaliciousProof { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected MaliciousProof error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_proof_depth_mismatch() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create proof with too many siblings for claimed tree size
        let excessive_siblings: Vec<SiblingHash> = (0..10)
            .map(|i| {
                SiblingHash::new(
                    create_test_leaf_hash(format!("sibling {}", i).as_bytes()),
                    Direction::Right,
                )
            })
            .collect();

        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            excessive_siblings,
            leaf_hash.clone(),
            2, // Small tree size but many siblings
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect proof depth mismatch
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::ProofDepthMismatch { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected ProofDepthMismatch error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_invalid_leaf_index() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create proof with leaf index out of bounds
        let proof = InclusionProof::new(
            entry_id,
            5, // Index out of bounds
            leaf_hash.clone(),
            vec![],
            leaf_hash.clone(),
            2, // Tree size of 2, but index 5
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect invalid leaf index
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::InvalidLeafIndex { .. } => {
                        // Expected
                    }
                    _ => panic!("Expected InvalidLeafIndex error"),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_security_zero_tree_size() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Create proof with zero tree size
        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![],
            leaf_hash.clone(),
            0, // Zero tree size
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());

        // Should detect invalid structure or leaf index error
        if let Err(e) = result {
            if let crate::error::SylvaError::ProofError { source } = e {
                match source {
                    ProofError::InvalidStructure { .. } => {
                        // Expected
                    }
                    ProofError::InvalidLeafIndex { .. } => {
                        // Also acceptable - zero tree size means leaf index 0 is invalid
                    }
                    _ => panic!(
                        "Expected InvalidStructure or InvalidLeafIndex error, got: {:?}",
                        source
                    ),
                }
            } else {
                panic!("Expected ProofError");
            }
        }
    }

    #[test]
    fn test_constant_time_comparison() {
        let entry_id = Uuid::new_v4();
        let leaves = vec![create_test_leaf_hash(b"test leaf")];
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 0, &leaves).unwrap();

        let hash1 = create_test_leaf_hash(b"hash1");
        let hash2 = create_test_leaf_hash(b"hash2");
        let hash1_copy = create_test_leaf_hash(b"hash1");

        // Test constant-time comparison
        assert!(!proof.constant_time_hash_compare(&hash1, &hash2));
        assert!(proof.constant_time_hash_compare(&hash1, &hash1_copy));
        assert!(proof.constant_time_hash_compare(&hash1, &hash1));
    }

    #[test]
    fn test_comprehensive_security_validation() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..8)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        // Generate valid proof
        let proof = InclusionProof::generate_for_leaf_index(entry_id, 3, &leaves).unwrap();

        // Test that valid proof passes all security checks
        assert!(proof.verify_against_root(&proof.root_hash).unwrap());

        // Test validation against different but valid root
        let other_leaves: Vec<HashDigest> = (0..8)
            .map(|i| create_test_leaf_hash(format!("other leaf {}", i).as_bytes()))
            .collect();
        let other_proof =
            InclusionProof::generate_for_leaf_index(entry_id, 3, &other_leaves).unwrap();

        // Should fail verification against wrong root
        let result = proof.verify_against_root(&other_proof.root_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_reconstruction_security() {
        let entry_id = Uuid::new_v4();
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let proof = InclusionProof::generate_for_leaf_index(entry_id, 2, &leaves).unwrap();

        // Test secure path reconstruction
        let reconstructed = proof.reconstruct_root_hash_secure().unwrap();
        assert_eq!(reconstructed, proof.root_hash);

        // Test that reconstruction matches verification
        assert!(proof.verify_against_root(&reconstructed).unwrap());
    }

    #[test]
    fn test_error_message_quality() {
        let entry_id = Uuid::new_v4();
        let leaf_hash = create_test_leaf_hash(b"test");

        // Test various error conditions and verify error messages are helpful

        // 1. Invalid hash length (simulate by creating a zero hash which is detected as suspicious)
        let invalid_hash = HashDigest::new([0u8; 32]);
        let sibling = SiblingHash::new(invalid_hash, Direction::Right);
        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            vec![sibling],
            leaf_hash.clone(),
            2,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Malicious proof") || error_msg.contains("Suspicious hash"));

        // 2. Excessive depth
        let excessive_siblings: Vec<SiblingHash> = (0..100)
            .map(|i| {
                SiblingHash::new(
                    create_test_leaf_hash(format!("s{}", i).as_bytes()),
                    Direction::Right,
                )
            })
            .collect();
        let proof = InclusionProof::new(
            entry_id,
            0,
            leaf_hash.clone(),
            excessive_siblings,
            leaf_hash.clone(),
            1,
        );

        let result = proof.verify_against_root(&leaf_hash);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Excessive proof depth"));
        assert!(error_msg.contains("100"));
    }
}
