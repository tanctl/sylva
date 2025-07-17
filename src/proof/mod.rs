pub mod batch;
pub mod inclusion;
pub mod sparse;

use crate::error::Result;
use crate::hash::HashDigest;
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use inclusion::InclusionProof;
pub use sparse::{
    SparseBatchProof, SparseExclusionProof, SparseInclusionProof, SparseProof, SparseProofElement,
    SparseTreeProofExt,
};

/// Core trait for Merkle tree proofs
pub trait MerkleProof: Clone + Serialize + for<'de> Deserialize<'de> {
    /// Verify the proof against a given root hash and entry
    fn verify(&self, root_hash: &HashDigest, entry: &LedgerEntry) -> Result<bool>;

    /// Get the entry ID this proof is for
    fn entry_id(&self) -> &Uuid;

    /// Get the leaf hash for this proof
    fn leaf_hash(&self) -> &HashDigest;

    /// Get the depth of the proof (number of sibling hashes)
    fn depth(&self) -> usize;

    /// Check if the proof is valid structurally
    fn is_valid(&self) -> bool;

    /// Get the memory footprint of the proof in bytes
    fn memory_size(&self) -> usize;
}

/// Direction for navigation in a binary tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Convert boolean to direction (true = left, false = right)
    pub fn from_bool(is_left: bool) -> Self {
        if is_left {
            Direction::Left
        } else {
            Direction::Right
        }
    }

    /// Convert direction to boolean (left = true, right = false)
    pub fn to_bool(self) -> bool {
        match self {
            Direction::Left => true,
            Direction::Right => false,
        }
    }

    /// Get the opposite direction
    pub fn opposite(self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

/// A sibling hash with its direction in the tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingHash {
    pub hash: HashDigest,
    pub direction: Direction,
}

impl SiblingHash {
    pub fn new(hash: HashDigest, direction: Direction) -> Self {
        Self { hash, direction }
    }

    pub fn left(hash: HashDigest) -> Self {
        Self::new(hash, Direction::Left)
    }

    pub fn right(hash: HashDigest) -> Self {
        Self::new(hash, Direction::Right)
    }
}

/// Error types specific to proof operations
#[derive(Debug, thiserror::Error, Clone)]
pub enum ProofError {
    #[error("Invalid leaf index: {index} for tree with {total_leaves} leaves")]
    InvalidLeafIndex { index: usize, total_leaves: usize },

    #[error("Proof verification failed: computed hash {computed} does not match root {expected}")]
    VerificationFailed { computed: String, expected: String },

    #[error("Invalid proof structure: {reason}")]
    InvalidStructure { reason: String },

    #[error("Empty tree cannot generate proofs")]
    EmptyTree,

    #[error("Leaf not found in tree: {entry_id}")]
    LeafNotFound { entry_id: Uuid },

    #[error("Hash computation failed during verification: {reason}")]
    HashComputationFailed { reason: String },

    #[error("Proof depth mismatch: expected {expected}, found {actual}")]
    ProofDepthMismatch { expected: usize, actual: usize },

    #[error("Malicious proof detected: {attack_type}")]
    MaliciousProof { attack_type: String },

    #[error("Invalid hash format: {reason}")]
    InvalidHashFormat { reason: String },

    #[error("Proof path reconstruction failed: {reason}")]
    PathReconstructionFailed { reason: String },

    #[error("Cryptographic verification failed: {reason}")]
    CryptographicFailure { reason: String },
}

/// Utility functions for proof operations
pub mod utils {
    /// Calculate the height of a binary tree with the given number of leaves
    pub fn tree_height(leaf_count: usize) -> usize {
        if leaf_count <= 1 {
            0
        } else {
            (leaf_count as f64).log2().ceil() as usize
        }
    }

    /// Check if a number is a power of 2
    pub fn is_power_of_2(n: usize) -> bool {
        n > 0 && (n & (n - 1)) == 0
    }

    /// Find the next power of 2 greater than or equal to n
    pub fn next_power_of_2(n: usize) -> usize {
        if n <= 1 {
            return 1;
        }
        let mut power = 1;
        while power < n {
            power <<= 1;
        }
        power
    }

    /// Calculate the path from leaf to root in a binary tree
    pub fn leaf_to_root_path(leaf_index: usize, tree_height: usize) -> Vec<super::Direction> {
        let mut path = Vec::with_capacity(tree_height);
        let mut index = leaf_index;

        for _ in 0..tree_height {
            if index % 2 == 0 {
                path.push(super::Direction::Left);
            } else {
                path.push(super::Direction::Right);
            }
            index /= 2;
        }

        path
    }

    /// Calculate the sibling index for a given node index
    pub fn sibling_index(index: usize) -> usize {
        if index % 2 == 0 {
            index + 1
        } else {
            index - 1
        }
    }

    /// Calculate the parent index for a given node index
    pub fn parent_index(index: usize) -> usize {
        index / 2
    }
}

// Re-export the original Proof struct for backward compatibility
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub entry_id: String,
    pub merkle_path: Vec<String>,
}

impl Proof {
    pub fn new(entry_id: String) -> Self {
        Self {
            entry_id,
            merkle_path: Vec::new(),
        }
    }

    pub fn verify(&self) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_conversions() {
        assert_eq!(Direction::from_bool(true), Direction::Left);
        assert_eq!(Direction::from_bool(false), Direction::Right);

        assert!(Direction::Left.to_bool());
        assert!(!Direction::Right.to_bool());

        assert_eq!(Direction::Left.opposite(), Direction::Right);
        assert_eq!(Direction::Right.opposite(), Direction::Left);
    }

    #[test]
    fn test_sibling_hash_creation() {
        use crate::hash::HashDigest;

        let hash = HashDigest::new([1u8; 32]);
        let left_sibling = SiblingHash::left(hash.clone());
        let right_sibling = SiblingHash::right(hash.clone());

        assert_eq!(left_sibling.direction, Direction::Left);
        assert_eq!(right_sibling.direction, Direction::Right);
        assert_eq!(left_sibling.hash, hash);
        assert_eq!(right_sibling.hash, hash);
    }

    #[test]
    fn test_tree_height_calculation() {
        assert_eq!(utils::tree_height(0), 0);
        assert_eq!(utils::tree_height(1), 0); // Single node has height 0
        assert_eq!(utils::tree_height(2), 1); // Two nodes need height 1
        assert_eq!(utils::tree_height(3), 2); // Three nodes need height 2
        assert_eq!(utils::tree_height(4), 2); // Four nodes need height 2
        assert_eq!(utils::tree_height(8), 3); // Eight nodes need height 3
        assert_eq!(utils::tree_height(15), 4); // Fifteen nodes need height 4
        assert_eq!(utils::tree_height(16), 4); // Sixteen nodes need height 4
    }

    #[test]
    fn test_power_of_2_check() {
        assert!(!utils::is_power_of_2(0));
        assert!(utils::is_power_of_2(1));
        assert!(utils::is_power_of_2(2));
        assert!(!utils::is_power_of_2(3));
        assert!(utils::is_power_of_2(4));
        assert!(!utils::is_power_of_2(5));
        assert!(utils::is_power_of_2(8));
        assert!(utils::is_power_of_2(16));
    }

    #[test]
    fn test_next_power_of_2() {
        assert_eq!(utils::next_power_of_2(0), 1);
        assert_eq!(utils::next_power_of_2(1), 1);
        assert_eq!(utils::next_power_of_2(2), 2);
        assert_eq!(utils::next_power_of_2(3), 4);
        assert_eq!(utils::next_power_of_2(5), 8);
        assert_eq!(utils::next_power_of_2(15), 16);
        assert_eq!(utils::next_power_of_2(16), 16);
    }

    #[test]
    fn test_leaf_to_root_path() {
        // For a tree with height 3 (8 leaves)
        let path = utils::leaf_to_root_path(0, 3);
        assert_eq!(
            path,
            vec![Direction::Left, Direction::Left, Direction::Left]
        );

        let path = utils::leaf_to_root_path(1, 3);
        assert_eq!(
            path,
            vec![Direction::Right, Direction::Left, Direction::Left]
        );

        let path = utils::leaf_to_root_path(7, 3);
        assert_eq!(
            path,
            vec![Direction::Right, Direction::Right, Direction::Right]
        );
    }

    #[test]
    fn test_sibling_index() {
        assert_eq!(utils::sibling_index(0), 1);
        assert_eq!(utils::sibling_index(1), 0);
        assert_eq!(utils::sibling_index(2), 3);
        assert_eq!(utils::sibling_index(3), 2);
        assert_eq!(utils::sibling_index(4), 5);
        assert_eq!(utils::sibling_index(5), 4);
    }

    #[test]
    fn test_parent_index() {
        assert_eq!(utils::parent_index(0), 0);
        assert_eq!(utils::parent_index(1), 0);
        assert_eq!(utils::parent_index(2), 1);
        assert_eq!(utils::parent_index(3), 1);
        assert_eq!(utils::parent_index(4), 2);
        assert_eq!(utils::parent_index(5), 2);
    }
}
