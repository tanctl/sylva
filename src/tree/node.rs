use crate::hash::{Blake3Hasher, Hash, HashDigest};
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// TreeNode represents a node in a binary Merkle tree
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeNode {
    /// Leaf node containing a ledger entry and its hash
    Leaf {
        hash: HashDigest,
        entry: LedgerEntry,
    },
    /// Internal node containing left and right child references and computed hash
    Internal {
        hash: HashDigest,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

impl Clone for TreeNode {
    fn clone(&self) -> Self {
        match self {
            TreeNode::Leaf { hash, entry } => TreeNode::Leaf {
                hash: hash.clone(),
                entry: entry.clone(),
            },
            TreeNode::Internal { hash, left, right } => TreeNode::Internal {
                hash: hash.clone(),
                left: left.clone(),
                right: right.clone(),
            },
        }
    }
}

impl TreeNode {
    /// Create a new leaf node from a ledger entry
    pub fn new_leaf(entry: LedgerEntry) -> crate::error::Result<Self> {
        use crate::hash::Blake3Hasher;

        let hasher = Blake3Hasher::new();
        let hash = Self::calculate_leaf_hash(&hasher, &entry)?;

        Ok(TreeNode::Leaf { hash, entry })
    }

    /// Calculate hash for a leaf node including version metadata
    pub fn calculate_leaf_hash(
        hasher: &Blake3Hasher,
        entry: &LedgerEntry,
    ) -> crate::error::Result<HashDigest> {
        // Create a deterministic representation including version metadata
        let mut hash_input = Vec::new();

        // Add entry data
        hash_input.extend_from_slice(&entry.data);

        // Add version as bytes (8 bytes, big-endian for deterministic ordering)
        hash_input.extend_from_slice(&entry.version.to_be_bytes());

        // Add timestamp as bytes (8 bytes, big-endian)
        hash_input.extend_from_slice(&entry.timestamp.to_be_bytes());

        // Add UUID as bytes (16 bytes, deterministic)
        hash_input.extend_from_slice(entry.id.as_bytes());

        // Add metadata in sorted order for deterministic hashing
        let mut metadata_keys: Vec<_> = entry.metadata.keys().collect();
        metadata_keys.sort();

        for key in metadata_keys {
            if let Some(value) = entry.metadata.get(key) {
                hash_input.extend_from_slice(key.as_bytes());
                hash_input.extend_from_slice(value.as_bytes());
            }
        }

        hasher.hash_bytes(&hash_input)
    }

    /// Create a new internal node from two child nodes
    pub fn new_internal(left: TreeNode, right: TreeNode) -> crate::error::Result<Self> {
        use crate::hash::Blake3Hasher;

        let hasher = Blake3Hasher::new();
        let hash = Self::calculate_internal_hash(&hasher, &left, &right)?;

        Ok(TreeNode::Internal {
            hash,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    /// Calculate hash for an internal node including version metadata from children
    fn calculate_internal_hash(
        hasher: &Blake3Hasher,
        left: &TreeNode,
        right: &TreeNode,
    ) -> crate::error::Result<HashDigest> {
        // Create a deterministic representation including version metadata
        let mut hash_input = Vec::new();

        // Add left child hash
        hash_input.extend_from_slice(left.hash().as_bytes());

        // Add right child hash
        hash_input.extend_from_slice(right.hash().as_bytes());

        // Add version range information for deterministic ordering
        let left_version_range = left.version_range();
        let right_version_range = right.version_range();

        // Add version ranges as bytes (min_version, max_version for each child)
        hash_input.extend_from_slice(&left_version_range.0.to_be_bytes());
        hash_input.extend_from_slice(&left_version_range.1.to_be_bytes());
        hash_input.extend_from_slice(&right_version_range.0.to_be_bytes());
        hash_input.extend_from_slice(&right_version_range.1.to_be_bytes());

        // Add leaf count for structural integrity
        hash_input.extend_from_slice(&left.leaf_count().to_be_bytes());
        hash_input.extend_from_slice(&right.leaf_count().to_be_bytes());

        hasher.hash_bytes(&hash_input)
    }

    /// Get the hash of this node
    pub fn hash(&self) -> &HashDigest {
        match self {
            TreeNode::Leaf { hash, .. } => hash,
            TreeNode::Internal { hash, .. } => hash,
        }
    }

    /// Check if this node is a leaf
    pub fn is_leaf(&self) -> bool {
        matches!(self, TreeNode::Leaf { .. })
    }

    /// Check if this node is internal
    pub fn is_internal(&self) -> bool {
        matches!(self, TreeNode::Internal { .. })
    }

    /// Get the ledger entry if this is a leaf node
    pub fn get_entry(&self) -> Option<&LedgerEntry> {
        match self {
            TreeNode::Leaf { entry, .. } => Some(entry),
            TreeNode::Internal { .. } => None,
        }
    }

    /// Get the left child if this is an internal node
    pub fn left_child(&self) -> Option<&TreeNode> {
        match self {
            TreeNode::Internal { left, .. } => Some(left),
            TreeNode::Leaf { .. } => None,
        }
    }

    /// Get the right child if this is an internal node
    pub fn right_child(&self) -> Option<&TreeNode> {
        match self {
            TreeNode::Internal { right, .. } => Some(right),
            TreeNode::Leaf { .. } => None,
        }
    }

    /// Get the height of the subtree rooted at this node
    pub fn height(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 0,
            TreeNode::Internal { left, right, .. } => {
                1 + std::cmp::max(left.height(), right.height())
            }
        }
    }

    /// Count the number of leaf nodes in this subtree
    pub fn leaf_count(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 1,
            TreeNode::Internal { left, right, .. } => left.leaf_count() + right.leaf_count(),
        }
    }

    /// Count the total number of nodes in this subtree
    pub fn node_count(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 1,
            TreeNode::Internal { left, right, .. } => 1 + left.node_count() + right.node_count(),
        }
    }

    /// Find a ledger entry by ID in this subtree
    pub fn find_entry(&self, id: &Uuid) -> Option<&LedgerEntry> {
        match self {
            TreeNode::Leaf { entry, .. } => {
                if entry.id == *id {
                    Some(entry)
                } else {
                    None
                }
            }
            TreeNode::Internal { left, right, .. } => {
                left.find_entry(id).or_else(|| right.find_entry(id))
            }
        }
    }

    /// Collect all ledger entries in this subtree
    pub fn collect_entries(&self) -> Vec<&LedgerEntry> {
        match self {
            TreeNode::Leaf { entry, .. } => vec![entry],
            TreeNode::Internal { left, right, .. } => {
                let mut entries = left.collect_entries();
                entries.extend(right.collect_entries());
                entries
            }
        }
    }

    /// Collect all ledger entries with a specific version
    pub fn collect_entries_by_version(&self, version: u64) -> Vec<&LedgerEntry> {
        match self {
            TreeNode::Leaf { entry, .. } => {
                if entry.version == version {
                    vec![entry]
                } else {
                    vec![]
                }
            }
            TreeNode::Internal { left, right, .. } => {
                let mut entries = left.collect_entries_by_version(version);
                entries.extend(right.collect_entries_by_version(version));
                entries
            }
        }
    }

    /// Get the maximum version in this subtree
    pub fn max_version(&self) -> u64 {
        match self {
            TreeNode::Leaf { entry, .. } => entry.version,
            TreeNode::Internal { left, right, .. } => {
                std::cmp::max(left.max_version(), right.max_version())
            }
        }
    }

    /// Get the minimum version in this subtree
    pub fn min_version(&self) -> u64 {
        match self {
            TreeNode::Leaf { entry, .. } => entry.version,
            TreeNode::Internal { left, right, .. } => {
                std::cmp::min(left.min_version(), right.min_version())
            }
        }
    }

    /// Get the version range (min, max) for this subtree
    pub fn version_range(&self) -> (u64, u64) {
        match self {
            TreeNode::Leaf { entry, .. } => (entry.version, entry.version),
            TreeNode::Internal { left, right, .. } => {
                let left_range = left.version_range();
                let right_range = right.version_range();

                (
                    std::cmp::min(left_range.0, right_range.0),
                    std::cmp::max(left_range.1, right_range.1),
                )
            }
        }
    }

    /// Generate a proof path for a given entry ID
    pub fn generate_proof_path(&self, id: &Uuid) -> Option<Vec<super::ProofElement>> {
        match self {
            TreeNode::Leaf { entry, .. } => {
                if entry.id == *id {
                    Some(vec![])
                } else {
                    None
                }
            }
            TreeNode::Internal { left, right, .. } => {
                if let Some(mut path) = left.generate_proof_path(id) {
                    path.push(super::ProofElement::new(right.hash().clone(), false));
                    Some(path)
                } else if let Some(mut path) = right.generate_proof_path(id) {
                    path.push(super::ProofElement::new(left.hash().clone(), true));
                    Some(path)
                } else {
                    None
                }
            }
        }
    }

    /// Verify the structural integrity of this subtree
    pub fn verify_structure(&self) -> crate::error::Result<bool> {
        use crate::hash::Blake3Hasher;

        match self {
            TreeNode::Leaf { hash, entry } => {
                let hasher = Blake3Hasher::new();
                let computed_hash = Self::calculate_leaf_hash(&hasher, entry)?;
                Ok(*hash == computed_hash)
            }
            TreeNode::Internal { hash, left, right } => {
                let hasher = Blake3Hasher::new();
                let computed_hash = Self::calculate_internal_hash(&hasher, left, right)?;

                if *hash != computed_hash {
                    return Ok(false);
                }

                Ok(left.verify_structure()? && right.verify_structure()?)
            }
        }
    }

    /// Get memory usage statistics for this subtree
    pub fn memory_stats(&self) -> NodeMemoryStats {
        match self {
            TreeNode::Leaf { entry, .. } => NodeMemoryStats {
                leaf_nodes: 1,
                internal_nodes: 0,
                total_data_size: entry.data.len(),
                total_metadata_size: entry.metadata.iter().map(|(k, v)| k.len() + v.len()).sum(),
            },
            TreeNode::Internal { left, right, .. } => {
                let left_stats = left.memory_stats();
                let right_stats = right.memory_stats();

                NodeMemoryStats {
                    leaf_nodes: left_stats.leaf_nodes + right_stats.leaf_nodes,
                    internal_nodes: 1 + left_stats.internal_nodes + right_stats.internal_nodes,
                    total_data_size: left_stats.total_data_size + right_stats.total_data_size,
                    total_metadata_size: left_stats.total_metadata_size
                        + right_stats.total_metadata_size,
                }
            }
        }
    }
}

/// Memory usage statistics for tree nodes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMemoryStats {
    pub leaf_nodes: usize,
    pub internal_nodes: usize,
    pub total_data_size: usize,
    pub total_metadata_size: usize,
}

impl NodeMemoryStats {
    pub fn total_nodes(&self) -> usize {
        self.leaf_nodes + self.internal_nodes
    }

    pub fn total_size(&self) -> usize {
        self.total_data_size + self.total_metadata_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_leaf_node_creation() {
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let node = TreeNode::new_leaf(entry.clone()).unwrap();

        assert!(node.is_leaf());
        assert!(!node.is_internal());
        assert_eq!(node.get_entry().unwrap(), &entry);
        assert_eq!(node.height(), 0);
        assert_eq!(node.leaf_count(), 1);
        assert_eq!(node.node_count(), 1);
    }

    #[test]
    fn test_internal_node_creation() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 2);
        let leaf1 = TreeNode::new_leaf(entry1).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2).unwrap();

        let internal = TreeNode::new_internal(leaf1, leaf2).unwrap();

        assert!(!internal.is_leaf());
        assert!(internal.is_internal());
        assert!(internal.get_entry().is_none());
        assert_eq!(internal.height(), 1);
        assert_eq!(internal.leaf_count(), 2);
        assert_eq!(internal.node_count(), 3);
    }

    #[test]
    fn test_tree_traversal() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 2);
        let entry3 = LedgerEntry::new(b"data3".to_vec(), 3);

        let leaf1 = TreeNode::new_leaf(entry1.clone()).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2.clone()).unwrap();
        let leaf3 = TreeNode::new_leaf(entry3.clone()).unwrap();

        let internal1 = TreeNode::new_internal(leaf1, leaf2).unwrap();
        let root = TreeNode::new_internal(internal1, leaf3).unwrap();

        let entries = root.collect_entries();
        assert_eq!(entries.len(), 3);

        assert!(root.find_entry(&entry1.id).is_some());
        assert!(root.find_entry(&entry2.id).is_some());
        assert!(root.find_entry(&entry3.id).is_some());

        let fake_id = uuid::Uuid::new_v4();
        assert!(root.find_entry(&fake_id).is_none());
    }

    #[test]
    fn test_version_operations() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 3);
        let entry3 = LedgerEntry::new(b"data3".to_vec(), 2);

        let leaf1 = TreeNode::new_leaf(entry1).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2).unwrap();
        let leaf3 = TreeNode::new_leaf(entry3).unwrap();

        let internal1 = TreeNode::new_internal(leaf1, leaf2).unwrap();
        let root = TreeNode::new_internal(internal1, leaf3).unwrap();

        assert_eq!(root.max_version(), 3);
        assert_eq!(root.min_version(), 1);

        let version_2_entries = root.collect_entries_by_version(2);
        assert_eq!(version_2_entries.len(), 1);
        assert_eq!(version_2_entries[0].version, 2);
    }

    #[test]
    fn test_proof_generation() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 2);

        let leaf1 = TreeNode::new_leaf(entry1.clone()).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2.clone()).unwrap();

        let root = TreeNode::new_internal(leaf1, leaf2).unwrap();

        let proof = root.generate_proof_path(&entry1.id);
        assert!(proof.is_some());
        assert_eq!(proof.unwrap().len(), 1);

        let fake_id = uuid::Uuid::new_v4();
        let no_proof = root.generate_proof_path(&fake_id);
        assert!(no_proof.is_none());
    }

    #[test]
    fn test_structure_verification() {
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let node = TreeNode::new_leaf(entry).unwrap();

        assert!(node.verify_structure().unwrap());

        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 2);
        let leaf1 = TreeNode::new_leaf(entry1).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2).unwrap();

        let internal = TreeNode::new_internal(leaf1, leaf2).unwrap();
        assert!(internal.verify_structure().unwrap());
    }

    #[test]
    fn test_memory_stats() {
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let entry = LedgerEntry::new(b"test data".to_vec(), 1).with_metadata(metadata);
        let node = TreeNode::new_leaf(entry).unwrap();

        let stats = node.memory_stats();
        assert_eq!(stats.leaf_nodes, 1);
        assert_eq!(stats.internal_nodes, 0);
        assert_eq!(stats.total_data_size, 9); // "test data".len()
        assert_eq!(stats.total_metadata_size, 8); // "key".len() + "value".len()
        assert_eq!(stats.total_nodes(), 1);
    }

    #[test]
    fn test_version_metadata_affects_hash() {
        // Test that version metadata affects leaf node hash
        let entry1 = LedgerEntry::new(b"same data".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"same data".to_vec(), 2);

        let node1 = TreeNode::new_leaf(entry1).unwrap();
        let node2 = TreeNode::new_leaf(entry2).unwrap();

        // Same data but different versions should produce different hashes
        assert_ne!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_metadata_affects_hash() {
        let mut metadata1 = HashMap::new();
        metadata1.insert("key".to_string(), "value1".to_string());

        let mut metadata2 = HashMap::new();
        metadata2.insert("key".to_string(), "value2".to_string());

        let entry1 = LedgerEntry::new(b"same data".to_vec(), 1).with_metadata(metadata1);
        let entry2 = LedgerEntry::new(b"same data".to_vec(), 1).with_metadata(metadata2);

        let node1 = TreeNode::new_leaf(entry1).unwrap();
        let node2 = TreeNode::new_leaf(entry2).unwrap();

        // Same data and version but different metadata should produce different hashes
        assert_ne!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_internal_node_version_range_hash() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 5);
        let entry3 = LedgerEntry::new(b"data3".to_vec(), 3);
        let entry4 = LedgerEntry::new(b"data4".to_vec(), 7);

        let leaf1 = TreeNode::new_leaf(entry1).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2).unwrap();
        let leaf3 = TreeNode::new_leaf(entry3).unwrap();
        let leaf4 = TreeNode::new_leaf(entry4).unwrap();

        let internal1 = TreeNode::new_internal(leaf1, leaf2).unwrap(); // versions 1-5
        let internal2 = TreeNode::new_internal(leaf3, leaf4).unwrap(); // versions 3-7

        // Different version ranges should produce different hashes
        assert_ne!(internal1.hash(), internal2.hash());

        // Check version ranges
        assert_eq!(internal1.version_range(), (1, 5));
        assert_eq!(internal2.version_range(), (3, 7));
    }

    #[test]
    fn test_deterministic_hash_calculation() {
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);

        let node1 = TreeNode::new_leaf(entry.clone()).unwrap();
        let node2 = TreeNode::new_leaf(entry).unwrap();

        // Same entry should produce same hash
        assert_eq!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_version_range_calculation() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 3);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 1);
        let entry3 = LedgerEntry::new(b"data3".to_vec(), 7);

        let leaf1 = TreeNode::new_leaf(entry1).unwrap();
        let leaf2 = TreeNode::new_leaf(entry2).unwrap();
        let leaf3 = TreeNode::new_leaf(entry3).unwrap();

        let internal1 = TreeNode::new_internal(leaf1, leaf2).unwrap();
        let root = TreeNode::new_internal(internal1, leaf3).unwrap();

        // Root should have version range from min to max across all entries
        assert_eq!(root.version_range(), (1, 7));
    }
}
