use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash as HashTrait, HashDigest};
use crate::proof::ProofError;
use crate::tree::sparse::{SparseKey, SparseMerkleTree, SPARSE_TREE_HEIGHT};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Element in a sparse Merkle proof path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseProofElement {
    /// Hash of the sibling node
    pub hash: HashDigest,
    /// Whether the sibling is to the left (true) or right (false) of the current path
    pub is_left: bool,
}

impl SparseProofElement {
    pub fn new(hash: HashDigest, is_left: bool) -> Self {
        Self { hash, is_left }
    }

    pub fn left(hash: HashDigest) -> Self {
        Self::new(hash, true)
    }

    pub fn right(hash: HashDigest) -> Self {
        Self::new(hash, false)
    }
}

/// Sparse Merkle inclusion proof for existing keys
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseInclusionProof {
    /// The key this proof is for
    pub key: SparseKey,
    /// The value associated with the key
    pub value: Vec<u8>,
    /// Path from leaf to root with sibling hashes
    pub path: Vec<SparseProofElement>,
    /// Root hash this proof verifies against
    pub root_hash: HashDigest,
    /// Leaf hash (computed from key and value)
    pub leaf_hash: HashDigest,
}

impl SparseInclusionProof {
    /// Create a new sparse inclusion proof
    pub fn new(
        key: SparseKey,
        value: Vec<u8>,
        path: Vec<SparseProofElement>,
        root_hash: HashDigest,
        leaf_hash: HashDigest,
    ) -> Self {
        Self {
            key,
            value,
            path,
            root_hash,
            leaf_hash,
        }
    }

    /// Generate an inclusion proof for an existing key in the sparse tree
    pub fn generate(tree: &SparseMerkleTree, key: &SparseKey) -> Result<Self> {
        // Verify the key exists
        let value = tree.get(key).ok_or_else(|| {
            SylvaError::ProofError {
                source: ProofError::LeafNotFound {
                    entry_id: Uuid::nil(), // Sparse proofs don't use UUIDs
                },
            }
        })?;

        // Generate the proof path
        let merkle_proof = tree.generate_proof(key)?;

        // Calculate leaf hash
        let hasher = Blake3Hasher::new();
        let key_bytes = key.as_bytes();
        let leaf_data = [key_bytes.as_slice(), value].concat();
        let leaf_hash = hasher.hash_bytes(&leaf_data)?;

        // Convert proof elements
        let path = merkle_proof
            .path
            .into_iter()
            .map(|element| SparseProofElement::new(element.hash, element.is_left))
            .collect();

        Ok(Self::new(
            *key,
            value.to_vec(),
            path,
            merkle_proof.root_hash,
            leaf_hash,
        ))
    }

    /// Verify the inclusion proof against a root hash
    pub fn verify(&self, root_hash: &HashDigest) -> Result<bool> {
        // Validate proof structure
        if self.path.len() != SPARSE_TREE_HEIGHT {
            return Err(SylvaError::ProofError {
                source: ProofError::ProofDepthMismatch {
                    expected: SPARSE_TREE_HEIGHT,
                    actual: self.path.len(),
                },
            });
        }

        // Verify leaf hash
        let hasher = Blake3Hasher::new();
        let key_bytes = self.key.as_bytes();
        let leaf_data = [key_bytes.as_slice(), &self.value].concat();
        let computed_leaf_hash = hasher.hash_bytes(&leaf_data)?;

        if self.leaf_hash != computed_leaf_hash {
            return Ok(false);
        }

        // Reconstruct root hash
        let reconstructed_root = self.reconstruct_root_hash()?;

        Ok(reconstructed_root == *root_hash)
    }

    /// Reconstruct the root hash from the proof path
    fn reconstruct_root_hash(&self) -> Result<HashDigest> {
        let hasher = Blake3Hasher::new();
        let mut current_hash = self.leaf_hash.clone();

        for element in &self.path {
            current_hash = if element.is_left {
                hasher.hash_pair(&element.hash, &current_hash)?
            } else {
                hasher.hash_pair(&current_hash, &element.hash)?
            };
        }

        Ok(current_hash)
    }

    /// Get the size of this proof in bytes
    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<SparseKey>()
            + self.value.len()
            + (self.path.len() * (32 + 1)) // 32 bytes for hash + 1 byte for direction
            + 32 // root hash
            + 32 // leaf hash
    }
}

/// Sparse Merkle exclusion proof for non-existing keys
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseExclusionProof {
    /// The key this proof demonstrates doesn't exist
    pub key: SparseKey,
    /// Path from the empty position to root with sibling hashes
    pub path: Vec<SparseProofElement>,
    /// Root hash this proof verifies against
    pub root_hash: HashDigest,
}

impl SparseExclusionProof {
    /// Create a new sparse exclusion proof
    pub fn new(key: SparseKey, path: Vec<SparseProofElement>, root_hash: HashDigest) -> Self {
        Self {
            key,
            path,
            root_hash,
        }
    }

    /// Generate an exclusion proof for a non-existing key in the sparse tree
    pub fn generate(tree: &SparseMerkleTree, key: &SparseKey) -> Result<Self> {
        // Verify the key doesn't exist
        if tree.contains_key(key) {
            return Err(SylvaError::InvalidInput {
                message: "Cannot generate exclusion proof for existing key".to_string(),
            });
        }

        // Generate the proof path using the tree's proof generation
        let merkle_proof = tree.generate_proof(key)?;

        // Convert proof elements
        let path = merkle_proof
            .path
            .into_iter()
            .map(|element| SparseProofElement::new(element.hash, element.is_left))
            .collect();

        Ok(Self::new(*key, path, merkle_proof.root_hash))
    }

    /// Verify the exclusion proof against a root hash
    pub fn verify(&self, root_hash: &HashDigest) -> Result<bool> {
        // Validate proof structure
        if self.path.len() != SPARSE_TREE_HEIGHT {
            return Err(SylvaError::ProofError {
                source: ProofError::ProofDepthMismatch {
                    expected: SPARSE_TREE_HEIGHT,
                    actual: self.path.len(),
                },
            });
        }

        // For exclusion proofs, we start with the empty hash at the leaf level
        let empty_hash = SparseMerkleTree::empty_hash_at_level(0);
        let reconstructed_root = self.reconstruct_root_hash_from_empty(&empty_hash)?;

        Ok(reconstructed_root == *root_hash)
    }

    /// Reconstruct the root hash starting from an empty leaf
    fn reconstruct_root_hash_from_empty(&self, empty_hash: &HashDigest) -> Result<HashDigest> {
        let hasher = Blake3Hasher::new();
        let mut current_hash = empty_hash.clone();

        for element in &self.path {
            current_hash = if element.is_left {
                hasher.hash_pair(&element.hash, &current_hash)?
            } else {
                hasher.hash_pair(&current_hash, &element.hash)?
            };
        }

        Ok(current_hash)
    }

    /// Get the size of this proof in bytes
    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<SparseKey>()
            + (self.path.len() * (32 + 1)) // 32 bytes for hash + 1 byte for direction
            + 32 // root hash
    }
}

/// Unified sparse proof that can handle both inclusion and exclusion
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SparseProof {
    /// Proof that a key exists with a specific value
    Inclusion(SparseInclusionProof),
    /// Proof that a key does not exist
    Exclusion(SparseExclusionProof),
}

impl SparseProof {
    /// Generate a sparse proof for any key (inclusion if exists, exclusion if not)
    pub fn generate(tree: &SparseMerkleTree, key: &SparseKey) -> Result<Self> {
        if tree.contains_key(key) {
            Ok(SparseProof::Inclusion(SparseInclusionProof::generate(
                tree, key,
            )?))
        } else {
            Ok(SparseProof::Exclusion(SparseExclusionProof::generate(
                tree, key,
            )?))
        }
    }

    /// Verify the proof against a root hash
    pub fn verify(&self, root_hash: &HashDigest) -> Result<bool> {
        match self {
            SparseProof::Inclusion(proof) => proof.verify(root_hash),
            SparseProof::Exclusion(proof) => proof.verify(root_hash),
        }
    }

    /// Get the key this proof is for
    pub fn key(&self) -> &SparseKey {
        match self {
            SparseProof::Inclusion(proof) => &proof.key,
            SparseProof::Exclusion(proof) => &proof.key,
        }
    }

    /// Check if this is an inclusion proof
    pub fn is_inclusion(&self) -> bool {
        matches!(self, SparseProof::Inclusion(_))
    }

    /// Check if this is an exclusion proof
    pub fn is_exclusion(&self) -> bool {
        matches!(self, SparseProof::Exclusion(_))
    }

    /// Get the value if this is an inclusion proof
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            SparseProof::Inclusion(proof) => Some(&proof.value),
            SparseProof::Exclusion(_) => None,
        }
    }

    /// Get the size of this proof in bytes
    pub fn size_bytes(&self) -> usize {
        match self {
            SparseProof::Inclusion(proof) => proof.size_bytes(),
            SparseProof::Exclusion(proof) => proof.size_bytes(),
        }
    }
}

/// Batch of sparse proofs for efficient verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseBatchProof {
    /// List of proofs in this batch
    pub proofs: Vec<SparseProof>,
    /// Common root hash for all proofs
    pub root_hash: HashDigest,
    /// Number of inclusion proofs
    pub inclusion_count: usize,
    /// Number of exclusion proofs
    pub exclusion_count: usize,
}

impl SparseBatchProof {
    /// Create a new batch proof
    pub fn new(proofs: Vec<SparseProof>, root_hash: HashDigest) -> Self {
        let inclusion_count = proofs.iter().filter(|p| p.is_inclusion()).count();
        let exclusion_count = proofs.len() - inclusion_count;

        Self {
            proofs,
            root_hash,
            inclusion_count,
            exclusion_count,
        }
    }

    /// Generate a batch of proofs for multiple keys
    pub fn generate(tree: &SparseMerkleTree, keys: &[SparseKey]) -> Result<Self> {
        let mut proofs = Vec::with_capacity(keys.len());

        for key in keys {
            proofs.push(SparseProof::generate(tree, key)?);
        }

        Ok(Self::new(proofs, tree.root_hash().clone()))
    }

    /// Verify all proofs in the batch
    pub fn verify_all(&self) -> Result<bool> {
        for proof in &self.proofs {
            if !proof.verify(&self.root_hash)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify a specific proof by index
    pub fn verify_proof(&self, index: usize) -> Result<bool> {
        self.proofs
            .get(index)
            .ok_or_else(|| SylvaError::InvalidInput {
                message: format!("Proof index {} out of bounds", index),
            })?
            .verify(&self.root_hash)
    }

    /// Get the total number of proofs
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Get inclusion proofs only
    pub fn inclusion_proofs(&self) -> impl Iterator<Item = &SparseInclusionProof> {
        self.proofs.iter().filter_map(|p| match p {
            SparseProof::Inclusion(inc) => Some(inc),
            _ => None,
        })
    }

    /// Get exclusion proofs only
    pub fn exclusion_proofs(&self) -> impl Iterator<Item = &SparseExclusionProof> {
        self.proofs.iter().filter_map(|p| match p {
            SparseProof::Exclusion(exc) => Some(exc),
            _ => None,
        })
    }

    /// Get the total size of all proofs in bytes
    pub fn total_size_bytes(&self) -> usize {
        self.proofs.iter().map(|p| p.size_bytes()).sum::<usize>()
            + 32 // root hash
            + 8  // inclusion_count
            + 8 // exclusion_count
    }

    /// Split the batch into inclusion and exclusion batches
    pub fn split_by_type(self) -> (Vec<SparseInclusionProof>, Vec<SparseExclusionProof>) {
        let mut inclusions = Vec::new();
        let mut exclusions = Vec::new();

        for proof in self.proofs {
            match proof {
                SparseProof::Inclusion(inc) => inclusions.push(inc),
                SparseProof::Exclusion(exc) => exclusions.push(exc),
            }
        }

        (inclusions, exclusions)
    }
}

/// Statistics about sparse proof operations
#[derive(Debug, Clone)]
pub struct SparseProofStatistics {
    pub total_proofs: usize,
    pub inclusion_proofs: usize,
    pub exclusion_proofs: usize,
    pub average_proof_size: f64,
    pub total_size_bytes: usize,
    pub verification_success_rate: f64,
}

impl SparseProofStatistics {
    pub fn from_batch(batch: &SparseBatchProof, verification_results: &[bool]) -> Self {
        let total_proofs = batch.len();
        let successful_verifications = verification_results.iter().filter(|&&v| v).count();
        let verification_success_rate = if total_proofs > 0 {
            successful_verifications as f64 / total_proofs as f64
        } else {
            0.0
        };

        let total_size_bytes = batch.total_size_bytes();
        let average_proof_size = if total_proofs > 0 {
            total_size_bytes as f64 / total_proofs as f64
        } else {
            0.0
        };

        Self {
            total_proofs,
            inclusion_proofs: batch.inclusion_count,
            exclusion_proofs: batch.exclusion_count,
            average_proof_size,
            total_size_bytes,
            verification_success_rate,
        }
    }
}

/// Extension trait for SparseMerkleTree to add proof generation methods
pub trait SparseTreeProofExt {
    /// Generate an inclusion proof for an existing key
    fn generate_inclusion_proof(&self, key: &SparseKey) -> Result<SparseInclusionProof>;

    /// Generate an exclusion proof for a non-existing key
    fn generate_exclusion_proof(&self, key: &SparseKey) -> Result<SparseExclusionProof>;

    /// Generate a proof for any key (inclusion or exclusion as appropriate)
    fn generate_sparse_proof(&self, key: &SparseKey) -> Result<SparseProof>;

    /// Generate a batch of proofs for multiple keys
    fn generate_batch_proofs(&self, keys: &[SparseKey]) -> Result<SparseBatchProof>;

    /// Verify an inclusion proof
    fn verify_inclusion_proof(&self, proof: &SparseInclusionProof) -> Result<bool>;

    /// Verify an exclusion proof
    fn verify_exclusion_proof(&self, proof: &SparseExclusionProof) -> Result<bool>;

    /// Verify a sparse proof
    fn verify_sparse_proof(&self, proof: &SparseProof) -> Result<bool>;

    /// Verify a batch of proofs
    fn verify_batch_proofs(&self, batch: &SparseBatchProof) -> Result<bool>;
}

impl SparseTreeProofExt for SparseMerkleTree {
    fn generate_inclusion_proof(&self, key: &SparseKey) -> Result<SparseInclusionProof> {
        SparseInclusionProof::generate(self, key)
    }

    fn generate_exclusion_proof(&self, key: &SparseKey) -> Result<SparseExclusionProof> {
        SparseExclusionProof::generate(self, key)
    }

    fn generate_sparse_proof(&self, key: &SparseKey) -> Result<SparseProof> {
        SparseProof::generate(self, key)
    }

    fn generate_batch_proofs(&self, keys: &[SparseKey]) -> Result<SparseBatchProof> {
        SparseBatchProof::generate(self, keys)
    }

    fn verify_inclusion_proof(&self, proof: &SparseInclusionProof) -> Result<bool> {
        proof.verify(self.root_hash())
    }

    fn verify_exclusion_proof(&self, proof: &SparseExclusionProof) -> Result<bool> {
        proof.verify(self.root_hash())
    }

    fn verify_sparse_proof(&self, proof: &SparseProof) -> Result<bool> {
        proof.verify(self.root_hash())
    }

    fn verify_batch_proofs(&self, batch: &SparseBatchProof) -> Result<bool> {
        // Verify root hash matches
        if batch.root_hash != *self.root_hash() {
            return Ok(false);
        }

        batch.verify_all()
    }
}

/// Add method to SparseMerkleTree to get empty hash at a specific level
impl SparseMerkleTree {
    /// Get the empty hash for a specific level in the sparse tree
    pub fn empty_hash_at_level(level: usize) -> HashDigest {
        let hasher = Blake3Hasher::new();

        if level == 0 {
            hasher.hash_bytes(b"").unwrap()
        } else {
            // Calculate empty hash for this level by recursively hashing empty hashes
            let mut current_hash = hasher.hash_bytes(b"").unwrap();
            for _ in 1..=level {
                current_hash = hasher.hash_pair(&current_hash, &current_hash).unwrap();
            }
            current_hash
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::sparse::SparseMerkleTree;

    fn create_test_tree_with_data() -> SparseMerkleTree {
        let mut tree = SparseMerkleTree::new();

        // Insert some test data
        let entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];

        for (key, value) in entries {
            tree.insert(key, value).unwrap();
        }

        tree
    }

    #[test]
    fn test_sparse_inclusion_proof_generation() {
        let tree = create_test_tree_with_data();
        let key = SparseKey::from_slice(b"key1");

        let proof = tree.generate_inclusion_proof(&key).unwrap();

        assert_eq!(proof.key, key);
        assert_eq!(proof.value, b"value1");
        assert_eq!(proof.path.len(), SPARSE_TREE_HEIGHT);
        assert!(tree.verify_inclusion_proof(&proof).unwrap());
    }

    #[test]
    fn test_sparse_exclusion_proof_generation() {
        let tree = create_test_tree_with_data();
        let key = SparseKey::from_slice(b"nonexistent");

        let proof = tree.generate_exclusion_proof(&key).unwrap();

        assert_eq!(proof.key, key);
        assert_eq!(proof.path.len(), SPARSE_TREE_HEIGHT);
        assert!(tree.verify_exclusion_proof(&proof).unwrap());
    }

    #[test]
    fn test_sparse_proof_unified_interface() {
        let tree = create_test_tree_with_data();

        // Test inclusion proof through unified interface
        let existing_key = SparseKey::from_slice(b"key1");
        let proof1 = tree.generate_sparse_proof(&existing_key).unwrap();

        assert!(proof1.is_inclusion());
        assert!(!proof1.is_exclusion());
        assert_eq!(proof1.value(), Some(b"value1".as_slice()));
        assert!(proof1.verify(tree.root_hash()).unwrap());

        // Test exclusion proof through unified interface
        let nonexistent_key = SparseKey::from_slice(b"nonexistent");
        let proof2 = tree.generate_sparse_proof(&nonexistent_key).unwrap();

        assert!(!proof2.is_inclusion());
        assert!(proof2.is_exclusion());
        assert_eq!(proof2.value(), None);
        assert!(proof2.verify(tree.root_hash()).unwrap());
    }

    #[test]
    fn test_batch_proof_generation() {
        let tree = create_test_tree_with_data();

        let keys = vec![
            SparseKey::from_slice(b"key1"),         // exists
            SparseKey::from_slice(b"key2"),         // exists
            SparseKey::from_slice(b"nonexistent1"), // doesn't exist
            SparseKey::from_slice(b"nonexistent2"), // doesn't exist
        ];

        let batch = tree.generate_batch_proofs(&keys).unwrap();

        assert_eq!(batch.len(), 4);
        assert_eq!(batch.inclusion_count, 2);
        assert_eq!(batch.exclusion_count, 2);
        assert!(tree.verify_batch_proofs(&batch).unwrap());
    }

    #[test]
    fn test_batch_proof_verification_individual() {
        let tree = create_test_tree_with_data();

        let keys = vec![
            SparseKey::from_slice(b"key1"),
            SparseKey::from_slice(b"nonexistent"),
        ];

        let batch = tree.generate_batch_proofs(&keys).unwrap();

        // Test individual proof verification
        assert!(batch.verify_proof(0).unwrap()); // inclusion proof
        assert!(batch.verify_proof(1).unwrap()); // exclusion proof

        // Test invalid index
        assert!(batch.verify_proof(2).is_err());
    }

    #[test]
    fn test_batch_proof_split_by_type() {
        let tree = create_test_tree_with_data();

        let keys = vec![
            SparseKey::from_slice(b"key1"),         // exists
            SparseKey::from_slice(b"key2"),         // exists
            SparseKey::from_slice(b"nonexistent1"), // doesn't exist
            SparseKey::from_slice(b"nonexistent2"), // doesn't exist
        ];

        let batch = tree.generate_batch_proofs(&keys).unwrap();
        let (inclusions, exclusions) = batch.split_by_type();

        assert_eq!(inclusions.len(), 2);
        assert_eq!(exclusions.len(), 2);

        // Verify individual proofs still work
        for inc_proof in &inclusions {
            assert!(tree.verify_inclusion_proof(inc_proof).unwrap());
        }

        for exc_proof in &exclusions {
            assert!(tree.verify_exclusion_proof(exc_proof).unwrap());
        }
    }

    #[test]
    fn test_proof_size_calculations() {
        let tree = create_test_tree_with_data();

        let inclusion_key = SparseKey::from_slice(b"key1");
        let exclusion_key = SparseKey::from_slice(b"nonexistent");

        let inc_proof = tree.generate_inclusion_proof(&inclusion_key).unwrap();
        let exc_proof = tree.generate_exclusion_proof(&exclusion_key).unwrap();

        let inc_size = inc_proof.size_bytes();
        let exc_size = exc_proof.size_bytes();

        // Inclusion proof should be larger due to the value
        assert!(inc_size > exc_size);
        assert!(inc_size > 0);
        assert!(exc_size > 0);
    }

    #[test]
    fn test_proof_statistics() {
        let tree = create_test_tree_with_data();

        let keys = vec![
            SparseKey::from_slice(b"key1"),
            SparseKey::from_slice(b"key2"),
            SparseKey::from_slice(b"nonexistent1"),
            SparseKey::from_slice(b"nonexistent2"),
        ];

        let batch = tree.generate_batch_proofs(&keys).unwrap();
        let verification_results: Vec<bool> = (0..batch.len())
            .map(|i| batch.verify_proof(i).unwrap_or(false))
            .collect();

        let stats = SparseProofStatistics::from_batch(&batch, &verification_results);

        assert_eq!(stats.total_proofs, 4);
        assert_eq!(stats.inclusion_proofs, 2);
        assert_eq!(stats.exclusion_proofs, 2);
        assert_eq!(stats.verification_success_rate, 1.0);
        assert!(stats.average_proof_size > 0.0);
        assert!(stats.total_size_bytes > 0);
    }

    #[test]
    fn test_inclusion_proof_invalid_key() {
        let tree = create_test_tree_with_data();
        let nonexistent_key = SparseKey::from_slice(b"nonexistent");

        let result = tree.generate_inclusion_proof(&nonexistent_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_exclusion_proof_existing_key() {
        let tree = create_test_tree_with_data();
        let existing_key = SparseKey::from_slice(b"key1");

        let result = tree.generate_exclusion_proof(&existing_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_tree_proofs() {
        let tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"any_key");

        // All keys should generate exclusion proofs in empty tree
        let proof = tree.generate_sparse_proof(&key).unwrap();
        assert!(proof.is_exclusion());
        assert!(proof.verify(tree.root_hash()).unwrap());
    }

    #[test]
    fn test_proof_verification_wrong_root() {
        let tree1 = create_test_tree_with_data();
        let mut tree2 = SparseMerkleTree::new();
        tree2
            .insert(SparseKey::from_slice(b"different"), b"data".to_vec())
            .unwrap();

        let key = SparseKey::from_slice(b"key1");
        let proof = tree1.generate_inclusion_proof(&key).unwrap();

        // Proof from tree1 should not verify against tree2's root
        assert!(!tree2.verify_inclusion_proof(&proof).unwrap());
    }

    #[test]
    fn test_proof_element_construction() {
        let hash = Blake3Hasher::new().hash_bytes(b"test").unwrap();

        let left_elem = SparseProofElement::left(hash.clone());
        assert!(left_elem.is_left);
        assert_eq!(left_elem.hash, hash);

        let right_elem = SparseProofElement::right(hash.clone());
        assert!(!right_elem.is_left);
        assert_eq!(right_elem.hash, hash);
    }

    #[test]
    fn test_batch_proof_empty() {
        let tree = create_test_tree_with_data();
        let batch = tree.generate_batch_proofs(&[]).unwrap();

        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert_eq!(batch.inclusion_count, 0);
        assert_eq!(batch.exclusion_count, 0);
        assert!(batch.verify_all().unwrap());
    }

    #[test]
    fn test_proof_depth_validation() {
        let tree = create_test_tree_with_data();
        let key = SparseKey::from_slice(b"key1");
        let proof = tree.generate_inclusion_proof(&key).unwrap();

        // All sparse proofs should have exactly SPARSE_TREE_HEIGHT elements
        assert_eq!(proof.path.len(), SPARSE_TREE_HEIGHT);
    }

    #[test]
    fn test_large_batch_proof() {
        let mut tree = SparseMerkleTree::new();

        // Insert many keys
        let mut keys = Vec::new();
        for i in 0..100 {
            let key = SparseKey::from_slice(format!("key{}", i).as_bytes());
            let value = format!("value{}", i).into_bytes();
            tree.insert(key, value).unwrap();
            keys.push(key);
        }

        // Add some non-existent keys
        for i in 100..120 {
            let key = SparseKey::from_slice(format!("nonexistent{}", i).as_bytes());
            keys.push(key);
        }

        let batch = tree.generate_batch_proofs(&keys).unwrap();

        assert_eq!(batch.len(), 120);
        assert_eq!(batch.inclusion_count, 100);
        assert_eq!(batch.exclusion_count, 20);
        assert!(tree.verify_batch_proofs(&batch).unwrap());
    }

    #[test]
    fn test_serialization_deserialization() {
        let tree = create_test_tree_with_data();

        // Test inclusion proof serialization
        let key = SparseKey::from_slice(b"key1");
        let inc_proof = tree.generate_inclusion_proof(&key).unwrap();
        let inc_json = serde_json::to_string(&inc_proof).unwrap();
        let inc_deserialized: SparseInclusionProof = serde_json::from_str(&inc_json).unwrap();
        assert_eq!(inc_proof, inc_deserialized);

        // Test exclusion proof serialization
        let nonexistent_key = SparseKey::from_slice(b"nonexistent");
        let exc_proof = tree.generate_exclusion_proof(&nonexistent_key).unwrap();
        let exc_json = serde_json::to_string(&exc_proof).unwrap();
        let exc_deserialized: SparseExclusionProof = serde_json::from_str(&exc_json).unwrap();
        assert_eq!(exc_proof, exc_deserialized);

        // Test unified proof serialization
        let unified_proof = tree.generate_sparse_proof(&key).unwrap();
        let unified_json = serde_json::to_string(&unified_proof).unwrap();
        let unified_deserialized: SparseProof = serde_json::from_str(&unified_json).unwrap();
        assert_eq!(unified_proof, unified_deserialized);

        // Test batch proof serialization
        let keys = vec![key, nonexistent_key];
        let batch = tree.generate_batch_proofs(&keys).unwrap();
        let batch_json = serde_json::to_string(&batch).unwrap();
        let batch_deserialized: SparseBatchProof = serde_json::from_str(&batch_json).unwrap();
        assert_eq!(batch.len(), batch_deserialized.len());
        assert_eq!(batch.inclusion_count, batch_deserialized.inclusion_count);
        assert_eq!(batch.exclusion_count, batch_deserialized.exclusion_count);
    }
}
