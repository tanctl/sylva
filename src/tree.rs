//! merkle tree implementation

use crate::error::{Result, SylvaError};
use crate::hash::{Hash, Hasher, Sha256Hasher};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    root: Hash,
    height: usize,
    #[serde(skip)]
    #[allow(dead_code)]
    hasher: Sha256Hasher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<Hash>,
    pub root: Hash,
}

impl MerkleTree {
    pub fn new(leaves: &[&[u8]]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(SylvaError::merkle_tree_error(
                "Cannot create tree from empty leaves",
            ));
        }

        let hasher = Sha256Hasher;
        let leaf_hashes: Vec<Hash> = leaves.iter().map(|leaf| hasher.hash(leaf)).collect();

        let (root, height) = Self::build_tree(&leaf_hashes, &hasher)?;

        Ok(Self {
            root,
            height,
            hasher,
        })
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn generate_proof(&self, _leaf_index: usize, _leaves: &[&[u8]]) -> Result<MerkleProof> {
        // todo: implement actual proof generation
        Ok(MerkleProof {
            leaf_index: _leaf_index,
            siblings: vec![],
            root: self.root.clone(),
        })
    }

    pub fn verify_proof(proof: &MerkleProof, leaf_data: &[u8]) -> Result<bool> {
        let hasher = Sha256Hasher;
        let leaf_hash = hasher.hash(leaf_data);

        // todo: implement actual proof verification
        Ok(!proof.siblings.is_empty() || leaf_hash == proof.root)
    }

    fn build_tree(leaf_hashes: &[Hash], hasher: &Sha256Hasher) -> Result<(Hash, usize)> {
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

                let combined = [left.as_bytes(), right.as_bytes()].concat();
                let parent_hash = hasher.hash(&combined);
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
