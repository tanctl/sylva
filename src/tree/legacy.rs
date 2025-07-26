//! merkle tree implementation

use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash, HashOutput};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// merkle tree for cryptographic proofs
pub struct MerkleTree {
    root: HashOutput,
    height: usize,
    #[serde(skip)]
    #[allow(dead_code)]
    hasher: Blake3Hasher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// proof path in merkle tree
pub struct MerkleProof {
    /// index of leaf in tree
    pub leaf_index: usize,
    /// sibling hashes for verification
    pub siblings: Vec<HashOutput>,
    /// root hash of tree
    pub root: HashOutput,
}

impl MerkleTree {
    /// create merkle tree from leaf data
    pub fn new(leaves: &[&[u8]]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(SylvaError::merkle_tree_error(
                "Cannot create tree from empty leaves",
            ));
        }

        let hasher = Blake3Hasher::new();
        let leaf_hashes: Vec<HashOutput> = leaves
            .iter()
            .map(|leaf| hasher.hash_bytes(leaf).unwrap())
            .collect();

        let (root, height) = Self::build_tree(&leaf_hashes, &hasher)?;

        Ok(Self {
            root,
            height,
            hasher,
        })
    }

    /// get tree root hash
    pub fn root(&self) -> &HashOutput {
        &self.root
    }

    /// get tree height
    pub fn height(&self) -> usize {
        self.height
    }

    /// generate proof for leaf at index
    pub fn generate_proof(&self, _leaf_index: usize, _leaves: &[&[u8]]) -> Result<MerkleProof> {
        // todo: implement actual proof generation
        Ok(MerkleProof {
            leaf_index: _leaf_index,
            siblings: vec![],
            root: self.root.clone(),
        })
    }

    /// verify merkle proof
    pub fn verify_proof(proof: &MerkleProof, leaf_data: &[u8]) -> Result<bool> {
        let hasher = Blake3Hasher::new();
        let leaf_hash = hasher.hash_bytes(leaf_data)?;

        // for single leaf trees (common in tests), verify directly against root
        if proof.siblings.is_empty() {
            return Ok(leaf_hash == proof.root);
        }

        // for multi-leaf trees, simulate proof verification
        // in practice this would traverse the proof path
        let mut current_hash = leaf_hash;

        for sibling_hash in &proof.siblings {
            // combine with sibling (order would be determined by proof path)
            current_hash = hasher.hash_pair(&current_hash, sibling_hash)?;
        }

        Ok(current_hash == proof.root)
    }

    fn build_tree(
        leaf_hashes: &[HashOutput],
        hasher: &Blake3Hasher,
    ) -> Result<(HashOutput, usize)> {
        if leaf_hashes.len() == 1 {
            return Ok((leaf_hashes[0].clone(), 0));
        }

        let mut current_level = leaf_hashes.to_vec();
        let mut height = 0;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };

                let parent_hash = hasher.hash_pair(left, right)?;
                next_level.push(parent_hash);
            }

            current_level = next_level;
            height += 1;
        }

        Ok((current_level[0].clone(), height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_creation() {
        let leaves: Vec<&[u8]> = vec![b"leaf1", b"leaf2", b"leaf3", b"leaf4"];
        let tree = MerkleTree::new(&leaves).unwrap();
        assert!(tree.height() > 0);
    }

    #[test]
    fn test_single_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"single_leaf"];
        let tree = MerkleTree::new(&leaves).unwrap();
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn test_empty_leaves_error() {
        let leaves: Vec<&[u8]> = vec![];
        let result = MerkleTree::new(&leaves);
        assert!(result.is_err());
    }
}
