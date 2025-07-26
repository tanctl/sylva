//! tree node structures for binary merkle trees

use crate::hash::HashOutput;
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// node in a binary merkle tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TreeNode {
    /// leaf node containing entry data and hash
    Leaf {
        /// hash of entry data
        hash: HashOutput,
        /// reference to ledger entry
        entry_id: Uuid,
        /// entry version for quick access
        version: u64,
        /// data size for statistics
        data_size: u64,
    },
    /// internal node with hash of children
    Internal {
        /// hash of left and right children combined
        hash: HashOutput,
        /// left child node
        left: Box<TreeNode>,
        /// right child node
        right: Box<TreeNode>,
    },
}

impl TreeNode {
    /// create leaf node from ledger entry
    pub fn leaf(entry: &LedgerEntry, hash: HashOutput) -> Self {
        Self::Leaf {
            hash,
            entry_id: entry.id,
            version: entry.version,
            data_size: entry.data.len() as u64,
        }
    }

    /// create internal node from two children
    pub fn internal(left: TreeNode, right: TreeNode, hash: HashOutput) -> Self {
        Self::Internal {
            hash,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// get node hash
    pub fn hash(&self) -> &HashOutput {
        match self {
            TreeNode::Leaf { hash, .. } => hash,
            TreeNode::Internal { hash, .. } => hash,
        }
    }

    /// check if node is a leaf
    pub fn is_leaf(&self) -> bool {
        matches!(self, TreeNode::Leaf { .. })
    }

    /// check if node is internal
    pub fn is_internal(&self) -> bool {
        matches!(self, TreeNode::Internal { .. })
    }

    /// get entry id if this is a leaf node
    pub fn entry_id(&self) -> Option<Uuid> {
        match self {
            TreeNode::Leaf { entry_id, .. } => Some(*entry_id),
            TreeNode::Internal { .. } => None,
        }
    }

    /// get version if this is a leaf node
    pub fn version(&self) -> Option<u64> {
        match self {
            TreeNode::Leaf { version, .. } => Some(*version),
            TreeNode::Internal { .. } => None,
        }
    }

    /// get data size if this is a leaf node
    pub fn data_size(&self) -> Option<u64> {
        match self {
            TreeNode::Leaf { data_size, .. } => Some(*data_size),
            TreeNode::Internal { .. } => None,
        }
    }

    /// get left child if this is an internal node
    pub fn left(&self) -> Option<&TreeNode> {
        match self {
            TreeNode::Internal { left, .. } => Some(left),
            TreeNode::Leaf { .. } => None,
        }
    }

    /// get right child if this is an internal node
    pub fn right(&self) -> Option<&TreeNode> {
        match self {
            TreeNode::Internal { right, .. } => Some(right),
            TreeNode::Leaf { .. } => None,
        }
    }

    /// get height of subtree rooted at this node
    pub fn height(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 1,
            TreeNode::Internal { left, right, .. } => {
                1 + std::cmp::max(left.height(), right.height())
            }
        }
    }

    /// count total nodes in subtree
    pub fn node_count(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 1,
            TreeNode::Internal { left, right, .. } => 1 + left.node_count() + right.node_count(),
        }
    }

    /// count leaf nodes in subtree
    pub fn leaf_count(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 1,
            TreeNode::Internal { left, right, .. } => left.leaf_count() + right.leaf_count(),
        }
    }

    /// count internal nodes in subtree
    pub fn internal_count(&self) -> usize {
        match self {
            TreeNode::Leaf { .. } => 0,
            TreeNode::Internal { left, right, .. } => {
                1 + left.internal_count() + right.internal_count()
            }
        }
    }

    /// get all entry ids in subtree
    pub fn entry_ids(&self) -> Vec<Uuid> {
        match self {
            TreeNode::Leaf { entry_id, .. } => vec![*entry_id],
            TreeNode::Internal { left, right, .. } => {
                let mut ids = left.entry_ids();
                ids.extend(right.entry_ids());
                ids
            }
        }
    }

    /// get latest version in subtree
    pub fn latest_version(&self) -> Option<u64> {
        match self {
            TreeNode::Leaf { version, .. } => Some(*version),
            TreeNode::Internal { left, right, .. } => {
                match (left.latest_version(), right.latest_version()) {
                    (Some(l), Some(r)) => Some(std::cmp::max(l, r)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                }
            }
        }
    }

    /// get earliest version in subtree
    pub fn earliest_version(&self) -> Option<u64> {
        match self {
            TreeNode::Leaf { version, .. } => Some(*version),
            TreeNode::Internal { left, right, .. } => {
                match (left.earliest_version(), right.earliest_version()) {
                    (Some(l), Some(r)) => Some(std::cmp::min(l, r)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                }
            }
        }
    }

    /// get total data size in subtree
    pub fn total_data_size(&self) -> u64 {
        match self {
            TreeNode::Leaf { data_size, .. } => *data_size,
            TreeNode::Internal { left, right, .. } => {
                left.total_data_size() + right.total_data_size()
            }
        }
    }

    /// check if subtree contains entry
    pub fn contains_entry(&self, entry_id: Uuid) -> bool {
        match self {
            TreeNode::Leaf { entry_id: id, .. } => *id == entry_id,
            TreeNode::Internal { left, right, .. } => {
                left.contains_entry(entry_id) || right.contains_entry(entry_id)
            }
        }
    }

    /// find path to entry (returns indices: 0 = left, 1 = right)
    pub fn find_path(&self, entry_id: Uuid) -> Option<Vec<usize>> {
        match self {
            TreeNode::Leaf { entry_id: id, .. } => {
                if *id == entry_id {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TreeNode::Internal { left, right, .. } => {
                if let Some(mut path) = left.find_path(entry_id) {
                    path.insert(0, 0);
                    Some(path)
                } else if let Some(mut path) = right.find_path(entry_id) {
                    path.insert(0, 1);
                    Some(path)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(data: &[u8], version: u64) -> LedgerEntry {
        let mut entry = LedgerEntry::new(data.to_vec(), None);
        entry.version = version;
        entry
    }

    fn dummy_hash() -> HashOutput {
        HashOutput::new([0u8; 32])
    }

    #[test]
    fn test_leaf_node_creation() {
        let entry = create_test_entry(b"test data", 1);
        let hash = dummy_hash();
        let node = TreeNode::leaf(&entry, hash.clone());

        assert!(node.is_leaf());
        assert!(!node.is_internal());
        assert_eq!(node.hash(), &hash);
        assert_eq!(node.entry_id(), Some(entry.id));
        assert_eq!(node.version(), Some(1));
        assert_eq!(node.data_size(), Some(9));
    }

    #[test]
    fn test_internal_node_creation() {
        let entry1 = create_test_entry(b"data1", 1);
        let entry2 = create_test_entry(b"data2", 2);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash.clone());

        assert!(!internal.is_leaf());
        assert!(internal.is_internal());
        assert_eq!(internal.hash(), &hash);
        assert_eq!(internal.entry_id(), None);
        assert_eq!(internal.version(), None);
        assert_eq!(internal.data_size(), None);
    }

    #[test]
    fn test_node_height() {
        let entry = create_test_entry(b"test", 1);
        let hash = dummy_hash();
        let leaf = TreeNode::leaf(&entry, hash.clone());

        assert_eq!(leaf.height(), 1);

        let internal = TreeNode::internal(leaf.clone(), leaf, hash);
        assert_eq!(internal.height(), 2);
    }

    #[test]
    fn test_node_counts() {
        let entry1 = create_test_entry(b"data1", 1);
        let entry2 = create_test_entry(b"data2", 2);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        assert_eq!(internal.node_count(), 3);
        assert_eq!(internal.leaf_count(), 2);
        assert_eq!(internal.internal_count(), 1);
    }

    #[test]
    fn test_entry_ids_collection() {
        let entry1 = create_test_entry(b"data1", 1);
        let entry2 = create_test_entry(b"data2", 2);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        let ids = internal.entry_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&entry1.id));
        assert!(ids.contains(&entry2.id));
    }

    #[test]
    fn test_version_queries() {
        let entry1 = create_test_entry(b"data1", 3);
        let entry2 = create_test_entry(b"data2", 7);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        assert_eq!(internal.latest_version(), Some(7));
        assert_eq!(internal.earliest_version(), Some(3));
    }

    #[test]
    fn test_data_size_calculation() {
        let entry1 = create_test_entry(b"abc", 1); // 3 bytes
        let entry2 = create_test_entry(b"defgh", 2); // 5 bytes
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        assert_eq!(internal.total_data_size(), 8);
    }

    #[test]
    fn test_contains_entry() {
        let entry1 = create_test_entry(b"data1", 1);
        let entry2 = create_test_entry(b"data2", 2);
        let entry3 = create_test_entry(b"data3", 3);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        assert!(internal.contains_entry(entry1.id));
        assert!(internal.contains_entry(entry2.id));
        assert!(!internal.contains_entry(entry3.id));
    }

    #[test]
    fn test_find_path() {
        let entry1 = create_test_entry(b"data1", 1);
        let entry2 = create_test_entry(b"data2", 2);
        let hash = dummy_hash();

        let left = TreeNode::leaf(&entry1, hash.clone());
        let right = TreeNode::leaf(&entry2, hash.clone());
        let internal = TreeNode::internal(left, right, hash);

        let path1 = internal.find_path(entry1.id).unwrap();
        assert_eq!(path1, vec![0]);

        let path2 = internal.find_path(entry2.id).unwrap();
        assert_eq!(path2, vec![1]);

        let entry3 = create_test_entry(b"data3", 3);
        assert!(internal.find_path(entry3.id).is_none());
    }
}
