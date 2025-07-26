//! tree trait definitions for versioned data structures

pub mod binary;
pub mod legacy;
pub mod node;

// re-export legacy types for compatibility
pub use legacy::{MerkleProof, MerkleTree};

use crate::error::Result;
use crate::hash::HashOutput;
use crate::ledger::LedgerEntry;

/// trait for tree data structures that work with versioned ledger entries
pub trait Tree {
    /// create new tree from ledger entries
    fn from_entries(entries: &[LedgerEntry]) -> Result<Self>
    where
        Self: Sized;

    /// get tree height (levels from root to deepest leaf)
    fn height(&self) -> usize;

    /// get number of entries in the tree
    fn entry_count(&self) -> usize;

    /// check if tree is empty
    fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// get latest version number from all entries
    fn latest_version(&self) -> Option<u64>;

    /// get root hash of the tree
    fn root_hash(&self) -> Option<HashOutput>;

    /// validate tree structure integrity
    fn validate(&self) -> Result<bool>;

    /// get all entry ids in the tree
    fn entry_ids(&self) -> Vec<uuid::Uuid>;

    /// check if entry exists in tree
    fn contains_entry(&self, entry_id: uuid::Uuid) -> bool {
        self.entry_ids().contains(&entry_id)
    }
}

/// trait for trees that support proof generation
pub trait ProofTree: Tree {
    /// proof data structure
    type Proof;

    /// generate inclusion proof for entry
    fn generate_proof(&self, entry_id: uuid::Uuid) -> Result<Option<Self::Proof>>;

    /// verify proof against tree root
    fn verify_proof(&self, proof: &Self::Proof, entry_data: &[u8]) -> Result<bool>;
}

/// tree statistics and metadata
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TreeStats {
    /// number of entries
    pub entry_count: usize,
    /// tree height
    pub height: usize,
    /// number of internal nodes
    pub internal_nodes: usize,
    /// number of leaf nodes
    pub leaf_nodes: usize,
    /// latest version in tree
    pub latest_version: Option<u64>,
    /// earliest version in tree
    pub earliest_version: Option<u64>,
    /// total data size in bytes
    pub total_data_size: u64,
}

impl TreeStats {
    /// create empty tree stats
    pub fn empty() -> Self {
        Self {
            entry_count: 0,
            height: 0,
            internal_nodes: 0,
            leaf_nodes: 0,
            latest_version: None,
            earliest_version: None,
            total_data_size: 0,
        }
    }

    /// create stats from entries
    pub fn from_entries(entries: &[LedgerEntry]) -> Self {
        if entries.is_empty() {
            return Self::empty();
        }

        let latest_version = entries.iter().map(|e| e.version).max();
        let earliest_version = entries.iter().map(|e| e.version).min();
        let total_data_size = entries.iter().map(|e| e.data.len() as u64).sum();

        Self {
            entry_count: entries.len(),
            height: 0,         // to be filled by tree implementation
            internal_nodes: 0, // to be filled by tree implementation
            leaf_nodes: entries.len(),
            latest_version,
            earliest_version,
            total_data_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_stats_empty() {
        let stats = TreeStats::empty();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.height, 0);
        assert!(stats.latest_version.is_none());
        assert!(stats.earliest_version.is_none());
    }

    #[test]
    fn test_tree_stats_from_entries() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), None);
        let mut entry2 = LedgerEntry::new(b"data2".to_vec(), None);
        entry2.version = 5;

        let entries = vec![entry1, entry2];
        let stats = TreeStats::from_entries(&entries);

        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.leaf_nodes, 2);
        assert_eq!(stats.latest_version, Some(5));
        assert_eq!(stats.earliest_version, Some(1));
        assert_eq!(stats.total_data_size, 10); // "data1" + "data2" = 10 bytes
    }
}
