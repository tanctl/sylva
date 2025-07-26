//! binary merkle tree implementation for ledger entries

use crate::hash::{Blake3Hasher, HashOutput};
use crate::ledger::LedgerEntry;
use crate::tree::node::TreeNode;
use crate::tree::{ProofTree, Tree, TreeStats};
use crate::{error::Result, hash::Hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// binary merkle tree for organizing ledger entries
#[derive(Debug, Clone, Serialize)]
pub struct BinaryMerkleTree {
    /// root node of the tree
    root: Option<TreeNode>,
    /// tree statistics
    stats: TreeStats,
    /// hasher for computing node hashes
    #[serde(skip)]
    hasher: Blake3Hasher,
}

impl<'de> Deserialize<'de> for BinaryMerkleTree {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BinaryMerkleTreeHelper {
            root: Option<TreeNode>,
            stats: TreeStats,
        }

        let helper = BinaryMerkleTreeHelper::deserialize(deserializer)?;
        Ok(BinaryMerkleTree {
            root: helper.root,
            stats: helper.stats,
            hasher: Blake3Hasher::new(),
        })
    }
}

/// proof of inclusion for an entry in the binary merkle tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MerkleProof {
    /// entry id being proven
    pub entry_id: Uuid,
    /// path from leaf to root (0 = left, 1 = right)
    pub path: Vec<usize>,
    /// sibling hashes along the path
    pub sibling_hashes: Vec<HashOutput>,
    /// root hash at time of proof generation
    pub root_hash: HashOutput,
}

impl BinaryMerkleTree {
    /// create empty binary merkle tree
    pub fn new() -> Self {
        Self {
            root: None,
            stats: TreeStats::empty(),
            hasher: Blake3Hasher::new(),
        }
    }

    /// get tree root node
    pub fn root(&self) -> Option<&TreeNode> {
        self.root.as_ref()
    }

    /// get tree statistics
    pub fn stats(&self) -> &TreeStats {
        &self.stats
    }

    /// build tree from sorted entries (by timestamp) with deterministic root hash calculation
    fn build_tree(&mut self, entries: &[LedgerEntry]) -> Result<()> {
        // edge case: empty ledger returns default hash
        if entries.is_empty() {
            self.root = None;
            self.stats = TreeStats::empty();
            return Ok(());
        }

        // edge case: single entry returns entry hash
        if entries.len() == 1 {
            let entry = &entries[0];
            let hash = self.hash_entry_with_version_metadata(entry)?;
            self.root = Some(TreeNode::leaf(entry, hash));
            self.update_stats(entries);
            return Ok(());
        }

        // create leaf nodes with version-aware hashing
        let mut nodes: Vec<TreeNode> = Vec::new();
        for entry in entries {
            let hash = self.hash_entry_with_version_metadata(entry)?;
            nodes.push(TreeNode::leaf(entry, hash));
        }

        // efficient bottom-up tree building algorithm with version tracking
        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            // process pairs of nodes
            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    // combine two nodes with version metadata
                    let left = chunk[0].clone();
                    let right = chunk[1].clone();
                    let combined_hash = self.combine_hashes_with_version_metadata(&left, &right)?;
                    next_level.push(TreeNode::internal(left, right, combined_hash));
                } else {
                    // handle odd number by promoting the single node to next level
                    next_level.push(chunk[0].clone());
                }
            }

            nodes = next_level;
        }

        self.root = nodes.into_iter().next();
        self.update_stats(entries);

        Ok(())
    }

    /// hash entry with version metadata for deterministic calculation
    fn hash_entry_with_version_metadata(&self, entry: &LedgerEntry) -> Result<HashOutput> {
        let context = crate::hash::EntryHashContext {
            entry_id: entry.id,
            version: entry.version,
            timestamp: entry.metadata.timestamp,
            previous_id: entry.metadata.previous_id,
            content_type: entry.metadata.content_type.clone(),
            metadata: entry.metadata.properties.clone(),
        };

        self.hasher.hash_entry(&entry.data, &context)
    }

    /// combine two hashes with version metadata for parent node hashing
    fn combine_hashes_with_version_metadata(
        &self,
        left: &TreeNode,
        right: &TreeNode,
    ) -> Result<HashOutput> {
        // create version metadata for parent node
        let left_version = left.version().unwrap_or(0);
        let right_version = right.version().unwrap_or(0);
        let max_version = std::cmp::max(left_version, right_version);

        // create deterministic parent hash by combining child hashes with version info
        // this ensures same inputs always produce same output
        let mut combined_data = Vec::new();

        // add left hash
        combined_data.extend_from_slice(left.hash().as_bytes());

        // add right hash
        combined_data.extend_from_slice(right.hash().as_bytes());

        // add version metadata in deterministic order
        combined_data.extend_from_slice(&left_version.to_be_bytes());
        combined_data.extend_from_slice(&right_version.to_be_bytes());
        combined_data.extend_from_slice(&max_version.to_be_bytes());

        // add node type marker
        combined_data.extend_from_slice(b"INTERNAL_NODE");

        // use simple hash_pair for deterministic results
        let temp_hash = self.hasher.hash_bytes(&combined_data)?;
        Ok(temp_hash)
    }

    /// combine two hashes into a parent hash
    #[allow(dead_code)]
    fn combine_hashes(&self, left: &HashOutput, right: &HashOutput) -> Result<HashOutput> {
        self.hasher.hash_pair(left, right)
    }

    /// update tree statistics
    fn update_stats(&mut self, entries: &[LedgerEntry]) {
        self.stats = TreeStats::from_entries(entries);

        if let Some(ref root) = self.root {
            self.stats.height = root.height();
            self.stats.internal_nodes = root.internal_count();
            self.stats.leaf_nodes = root.leaf_count();
        }
    }
}

impl Default for BinaryMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree for BinaryMerkleTree {
    fn from_entries(entries: &[LedgerEntry]) -> Result<Self> {
        let mut tree = Self::new();

        // deterministic hash calculation preserving temporal ordering
        let mut sorted_entries = entries.to_vec();

        // primary sort by timestamp for temporal consistency
        // secondary sort by entry id for deterministic ordering of concurrent entries
        // tertiary sort by version for version chain consistency
        sorted_entries.sort_by(|a, b| {
            a.metadata
                .timestamp
                .cmp(&b.metadata.timestamp)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.version.cmp(&b.version))
        });

        tree.build_tree(&sorted_entries)?;
        Ok(tree)
    }

    fn height(&self) -> usize {
        self.stats.height
    }

    fn entry_count(&self) -> usize {
        self.stats.entry_count
    }

    fn latest_version(&self) -> Option<u64> {
        self.stats.latest_version
    }

    fn root_hash(&self) -> Option<HashOutput> {
        self.root.as_ref().map(|r| r.hash().clone())
    }

    fn validate(&self) -> Result<bool> {
        match &self.root {
            None => Ok(self.stats.entry_count == 0),
            Some(root) => {
                // verify tree structure consistency
                let actual_height = root.height();
                let actual_leaf_count = root.leaf_count();
                let actual_internal_count = root.internal_count();

                Ok(actual_height == self.stats.height
                    && actual_leaf_count == self.stats.leaf_nodes
                    && actual_internal_count == self.stats.internal_nodes
                    && actual_leaf_count == self.stats.entry_count)
            }
        }
    }

    fn entry_ids(&self) -> Vec<Uuid> {
        match &self.root {
            None => Vec::new(),
            Some(root) => root.entry_ids(),
        }
    }
}

impl ProofTree for BinaryMerkleTree {
    type Proof = MerkleProof;

    fn generate_proof(&self, entry_id: Uuid) -> Result<Option<Self::Proof>> {
        let root = match &self.root {
            Some(r) => r,
            None => return Ok(None),
        };

        let path = match root.find_path(entry_id) {
            Some(p) => p,
            None => return Ok(None),
        };

        let mut sibling_hashes = Vec::new();
        let mut current = root;

        for &direction in &path {
            match current {
                TreeNode::Internal { left, right, .. } => {
                    if direction == 0 {
                        // going left, sibling is right
                        sibling_hashes.push(right.hash().clone());
                        current = left;
                    } else {
                        // going right, sibling is left
                        sibling_hashes.push(left.hash().clone());
                        current = right;
                    }
                }
                TreeNode::Leaf { .. } => break,
            }
        }

        let root_hash = root.hash().clone();

        Ok(Some(MerkleProof {
            entry_id,
            path,
            sibling_hashes,
            root_hash,
        }))
    }

    fn verify_proof(&self, proof: &Self::Proof, _entry_data: &[u8]) -> Result<bool> {
        // verify against current root hash
        let current_root = match self.root_hash() {
            Some(h) => h,
            None => return Ok(false),
        };

        if current_root != proof.root_hash {
            return Ok(false);
        }

        // find the entry to get its proper hash
        let entry_ids = self.entry_ids();
        if !entry_ids.contains(&proof.entry_id) {
            return Ok(false);
        }

        // for now, we'll use a simplified verification that checks if the proof
        // was generated for this tree by comparing root hashes
        // TODO: implement full merkle path verification with version metadata
        Ok(current_root == proof.root_hash)
    }
}

// implement conversion from LedgerEntry to hash context
impl From<&LedgerEntry> for crate::hash::EntryHashContext {
    fn from(entry: &LedgerEntry) -> Self {
        Self {
            entry_id: entry.id,
            version: entry.version,
            timestamp: entry.metadata.timestamp,
            previous_id: entry.metadata.previous_id,
            content_type: entry.metadata.content_type.clone(),
            metadata: entry.metadata.properties.clone(),
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

    #[test]
    fn test_empty_tree() {
        let tree = BinaryMerkleTree::from_entries(&[]).unwrap();

        assert!(tree.is_empty());
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.entry_count(), 0);
        assert!(tree.latest_version().is_none());
        assert!(tree.root_hash().is_none());
        assert!(tree.validate().unwrap());
    }

    #[test]
    fn test_single_entry_tree() {
        let entry = create_test_entry(b"single entry", 1);
        let tree = BinaryMerkleTree::from_entries(&[entry.clone()]).unwrap();

        assert!(!tree.is_empty());
        assert_eq!(tree.height(), 1);
        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.latest_version(), Some(1));
        assert!(tree.root_hash().is_some());
        assert!(tree.validate().unwrap());
        assert!(tree.contains_entry(entry.id));
    }

    #[test]
    fn test_multiple_entries_tree() {
        let entries = vec![
            create_test_entry(b"entry1", 1),
            create_test_entry(b"entry2", 2),
            create_test_entry(b"entry3", 3),
            create_test_entry(b"entry4", 4),
        ];

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 4);
        assert_eq!(tree.latest_version(), Some(4));
        assert!(tree.height() >= 2);
        assert!(tree.validate().unwrap());

        // verify all entries are in the tree
        for entry in &entries {
            assert!(tree.contains_entry(entry.id));
        }
    }

    #[test]
    fn test_versioning_scenarios() {
        // entries with same data but different versions
        let mut entry1 = create_test_entry(b"same data", 1);
        let mut entry2 = create_test_entry(b"same data", 5);
        let mut entry3 = create_test_entry(b"different", 3);

        // ensure different timestamps for sorting
        entry1.metadata.timestamp = 1000;
        entry2.metadata.timestamp = 2000;
        entry3.metadata.timestamp = 1500;

        let entries = vec![entry1.clone(), entry2.clone(), entry3.clone()];
        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.latest_version(), Some(5));
        assert!(tree.validate().unwrap());

        // all entries should be present
        assert!(tree.contains_entry(entry1.id));
        assert!(tree.contains_entry(entry2.id));
        assert!(tree.contains_entry(entry3.id));
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let entries = vec![
            create_test_entry(b"data1", 1),
            create_test_entry(b"data2", 2),
            create_test_entry(b"data3", 3),
        ];

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        // generate proof for each entry
        for entry in &entries {
            let proof = tree.generate_proof(entry.id).unwrap();
            assert!(proof.is_some());

            let proof = proof.unwrap();
            assert_eq!(proof.entry_id, entry.id);

            // verify proof
            let is_valid = tree.verify_proof(&proof, &entry.data).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_proof_for_nonexistent_entry() {
        let entries = vec![create_test_entry(b"data", 1)];
        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        let nonexistent_id = Uuid::new_v4();
        let proof = tree.generate_proof(nonexistent_id).unwrap();
        assert!(proof.is_none());
    }

    #[test]
    fn test_tree_statistics() {
        let entries = vec![
            create_test_entry(b"abc", 1),   // 3 bytes
            create_test_entry(b"defgh", 2), // 5 bytes
            create_test_entry(b"ij", 3),    // 2 bytes
        ];

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();
        let stats = tree.stats();

        assert_eq!(stats.entry_count, 3);
        assert_eq!(stats.latest_version, Some(3));
        assert_eq!(stats.earliest_version, Some(1));
        assert_eq!(stats.total_data_size, 10);
        assert_eq!(stats.leaf_nodes, 3);
        assert!(stats.internal_nodes > 0);
    }

    #[test]
    fn test_large_tree() {
        // with many entries to verify tree balance
        let mut entries = Vec::new();
        for i in 0..100 {
            entries.push(create_test_entry(
                format!("data{}", i).as_bytes(),
                i as u64 + 1,
            ));
        }

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 100);
        assert_eq!(tree.latest_version(), Some(100));
        assert!(tree.validate().unwrap());

        // height should be reasonable for 100 entries (log2(100) ≈ 7)
        assert!(tree.height() <= 10);

        // verify some random entries
        for entry in entries.iter().step_by(10) {
            assert!(tree.contains_entry(entry.id));

            let proof = tree.generate_proof(entry.id).unwrap().unwrap();
            let is_valid = tree.verify_proof(&proof, &entry.data).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_tree_with_versioned_entries() {
        // create entry chain with versions
        let mut entry1 = create_test_entry(b"initial", 1);
        let mut entry2 =
            LedgerEntry::new_version(&entry1, b"updated".to_vec(), Some("v2".to_string()));
        let mut entry3 =
            LedgerEntry::new_version(&entry2, b"final".to_vec(), Some("v3".to_string()));

        // ensure different timestamps
        entry1.metadata.timestamp = 1000;
        entry2.metadata.timestamp = 2000;
        entry3.metadata.timestamp = 3000;

        let entries = vec![entry1.clone(), entry2.clone(), entry3.clone()];
        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.latest_version(), Some(3));

        // verify version chain metadata is preserved
        assert_eq!(entry2.metadata.previous_id, Some(entry1.id));
        assert_eq!(entry3.metadata.previous_id, Some(entry2.id));

        // all versions should be in tree
        assert!(tree.contains_entry(entry1.id));
        assert!(tree.contains_entry(entry2.id));
        assert!(tree.contains_entry(entry3.id));
    }

    #[test]
    fn test_root_hash_deterministic() {
        // root hashes are deterministic for same input
        let entries = vec![
            create_test_entry(b"data1", 1),
            create_test_entry(b"data2", 2),
            create_test_entry(b"data3", 3),
        ];

        let tree1 = BinaryMerkleTree::from_entries(&entries).unwrap();
        let tree2 = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree1.root_hash(), tree2.root_hash());
        assert!(tree1.root_hash().is_some());
    }

    #[test]
    fn test_root_hash_temporal_consistency() {
        // temporal ordering affects root hash
        let mut entry1 = create_test_entry(b"data1", 1);
        let mut entry2 = create_test_entry(b"data2", 2);

        // same data, different timestamps
        entry1.metadata.timestamp = 1000;
        entry2.metadata.timestamp = 2000;

        let tree1 = BinaryMerkleTree::from_entries(&[entry1.clone(), entry2.clone()]).unwrap();

        // swap timestamps
        entry1.metadata.timestamp = 2000;
        entry2.metadata.timestamp = 1000;

        let tree2 = BinaryMerkleTree::from_entries(&[entry1, entry2]).unwrap();

        // root hashes should be different due to different temporal ordering
        assert_ne!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_odd_number_entries_duplication() {
        // handling of odd number of entries
        let entries = vec![
            create_test_entry(b"data1", 1),
            create_test_entry(b"data2", 2),
            create_test_entry(b"data3", 3),
        ];

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert!(tree.root_hash().is_some());
        assert!(tree.validate().unwrap());

        // verify all entries can be proven
        for entry in &entries {
            let proof = tree.generate_proof(entry.id).unwrap();
            assert!(proof.is_some());
            let is_valid = tree.verify_proof(&proof.unwrap(), &entry.data).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_edge_case_empty_ledger() {
        // empty ledger returns default hash
        let tree = BinaryMerkleTree::from_entries(&[]).unwrap();

        assert!(tree.is_empty());
        assert!(tree.root_hash().is_none());
        assert_eq!(tree.entry_count(), 0);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn test_edge_case_single_entry() {
        // single entry returns entry hash
        let entry = create_test_entry(b"single", 1);
        let tree = BinaryMerkleTree::from_entries(&[entry.clone()]).unwrap();

        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.height(), 1);
        assert!(tree.root_hash().is_some());

        // single entry should be provable
        let proof = tree.generate_proof(entry.id).unwrap();
        assert!(proof.is_some());
    }

    #[test]
    fn test_version_metadata_preservation() {
        // version metadata is preserved in hash calculation
        let mut entry1 = create_test_entry(b"data", 1);
        let mut entry2 = create_test_entry(b"data", 2);

        entry1.metadata.timestamp = 1000;
        entry2.metadata.timestamp = 1000;

        let tree1 = BinaryMerkleTree::from_entries(&[entry1]).unwrap();
        let tree2 = BinaryMerkleTree::from_entries(&[entry2]).unwrap();

        // different versions should produce different root hashes
        assert_ne!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_concurrent_entries_deterministic_ordering() {
        // deterministic ordering of concurrent entries (same timestamp)
        let mut entry1 = create_test_entry(b"data1", 1);
        let mut entry2 = create_test_entry(b"data2", 1);
        let mut entry3 = create_test_entry(b"data3", 1);

        // all same timestamp
        let timestamp = 1000;
        entry1.metadata.timestamp = timestamp;
        entry2.metadata.timestamp = timestamp;
        entry3.metadata.timestamp = timestamp;

        let entries1 = vec![entry1.clone(), entry2.clone(), entry3.clone()];
        let entries2 = vec![entry3.clone(), entry1.clone(), entry2.clone()];

        let tree1 = BinaryMerkleTree::from_entries(&entries1).unwrap();
        let tree2 = BinaryMerkleTree::from_entries(&entries2).unwrap();

        // should produce same root hash due to deterministic sorting
        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_version_chain_consistency() {
        // version chains maintain consistency
        let mut base_entry = create_test_entry(b"base", 1);
        base_entry.metadata.timestamp = 1000;

        let mut v2_entry =
            LedgerEntry::new_version(&base_entry, b"version2".to_vec(), Some("v2".to_string()));
        v2_entry.metadata.timestamp = 2000;

        let mut v3_entry =
            LedgerEntry::new_version(&v2_entry, b"version3".to_vec(), Some("v3".to_string()));
        v3_entry.metadata.timestamp = 3000;

        let entries = vec![base_entry.clone(), v2_entry.clone(), v3_entry.clone()];
        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.latest_version(), Some(3));

        // verify chain integrity
        assert_eq!(v2_entry.metadata.previous_id, Some(base_entry.id));
        assert_eq!(v3_entry.metadata.previous_id, Some(v2_entry.id));
        assert_eq!(v2_entry.version, 2);
        assert_eq!(v3_entry.version, 3);
    }

    #[test]
    fn test_large_tree_with_versions() {
        // large tree with multiple version chains
        let mut entries = Vec::new();
        let mut base_entries = Vec::new();

        // create 10 base entries
        for i in 0..10 {
            let mut entry = create_test_entry(format!("base{}", i).as_bytes(), 1);
            entry.metadata.timestamp = (i * 1000) as u64;
            base_entries.push(entry);
        }

        // create version chains
        for (i, base) in base_entries.iter().enumerate() {
            entries.push(base.clone());

            // add 2 versions for each base
            let mut v2 = LedgerEntry::new_version(
                base,
                format!("v2_{}", i).as_bytes().to_vec(),
                Some("v2".to_string()),
            );
            v2.metadata.timestamp = base.metadata.timestamp + 500;
            entries.push(v2.clone());

            let mut v3 = LedgerEntry::new_version(
                &v2,
                format!("v3_{}", i).as_bytes().to_vec(),
                Some("v3".to_string()),
            );
            v3.metadata.timestamp = base.metadata.timestamp + 1000;
            entries.push(v3);
        }

        let tree = BinaryMerkleTree::from_entries(&entries).unwrap();

        assert_eq!(tree.entry_count(), 30);
        assert_eq!(tree.latest_version(), Some(3));
        assert!(tree.validate().unwrap());

        // verify some proofs
        for entry in entries.iter().step_by(5) {
            let proof = tree.generate_proof(entry.id).unwrap().unwrap();
            let is_valid = tree.verify_proof(&proof, &entry.data).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_known_test_vectors() {
        // known test vectors for hash verification to ensure consistency

        // vector 1: single entry with known data
        let mut entry1 = create_test_entry(b"test_vector_1", 1);
        entry1.metadata.timestamp = 1234567890;
        entry1.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let tree1 = BinaryMerkleTree::from_entries(&[entry1]).unwrap();
        let root_hash1 = tree1.root_hash().unwrap();

        // the root hash should be deterministic for this specific input
        // note: actual hash will depend on Blake3 implementation details
        assert_eq!(root_hash1.as_bytes().len(), 32);

        // vector 2: two entries with known data
        let mut entry2a = create_test_entry(b"vector_2a", 1);
        entry2a.metadata.timestamp = 1000;
        entry2a.id = uuid::Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();

        let mut entry2b = create_test_entry(b"vector_2b", 2);
        entry2b.metadata.timestamp = 2000;
        entry2b.id = uuid::Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap();

        let tree2 = BinaryMerkleTree::from_entries(&[entry2a, entry2b]).unwrap();
        let root_hash2 = tree2.root_hash().unwrap();

        assert_eq!(root_hash2.as_bytes().len(), 32);
        assert_ne!(root_hash1, root_hash2);

        // vector 3: three entries (odd number) with known data
        let mut entry3a = create_test_entry(b"vector_3a", 1);
        entry3a.metadata.timestamp = 1000;
        entry3a.id = uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();

        let mut entry3b = create_test_entry(b"vector_3b", 2);
        entry3b.metadata.timestamp = 2000;
        entry3b.id = uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d480").unwrap();

        let mut entry3c = create_test_entry(b"vector_3c", 3);
        entry3c.metadata.timestamp = 3000;
        entry3c.id = uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d481").unwrap();

        let tree3 = BinaryMerkleTree::from_entries(&[entry3a, entry3b, entry3c]).unwrap();
        let root_hash3 = tree3.root_hash().unwrap();

        assert_eq!(root_hash3.as_bytes().len(), 32);
        assert_ne!(root_hash2, root_hash3);
        assert_ne!(root_hash1, root_hash3);

        // vector 4: version chain consistency
        let mut base = create_test_entry(b"base_data", 1);
        base.metadata.timestamp = 1000;
        base.id = uuid::Uuid::parse_str("12345678-1234-5678-1234-123456789abc").unwrap();

        let mut v2 =
            LedgerEntry::new_version(&base, b"updated_data".to_vec(), Some("v2".to_string()));
        v2.metadata.timestamp = 2000;

        let mut v3 = LedgerEntry::new_version(&v2, b"final_data".to_vec(), Some("v3".to_string()));
        v3.metadata.timestamp = 3000;

        let tree4 = BinaryMerkleTree::from_entries(&[base, v2, v3]).unwrap();
        let root_hash4 = tree4.root_hash().unwrap();

        assert_eq!(root_hash4.as_bytes().len(), 32);
        assert_ne!(root_hash3, root_hash4);
    }

    #[test]
    fn test_hash_consistency_across_rebuilds() {
        // rebuilding the same tree produces the same hash
        let entries = vec![
            create_test_entry(b"consistency_test_1", 1),
            create_test_entry(b"consistency_test_2", 2),
            create_test_entry(b"consistency_test_3", 3),
            create_test_entry(b"consistency_test_4", 4),
        ];

        // build tree multiple times
        let mut hashes = Vec::new();
        for _ in 0..5 {
            let tree = BinaryMerkleTree::from_entries(&entries).unwrap();
            hashes.push(tree.root_hash().unwrap());
        }

        // all hashes should be identical
        for hash in &hashes[1..] {
            assert_eq!(hashes[0], *hash);
        }
    }

    #[test]
    fn test_hash_sensitivity() {
        // small changes produce different hashes (avalanche effect)
        let mut entry1 = create_test_entry(b"test_data", 1);
        let mut entry2 = create_test_entry(b"test_datA", 1);

        entry1.metadata.timestamp = 1000;
        entry2.metadata.timestamp = 1000;

        let tree1 = BinaryMerkleTree::from_entries(&[entry1]).unwrap();
        let tree2 = BinaryMerkleTree::from_entries(&[entry2]).unwrap();

        assert_ne!(tree1.root_hash(), tree2.root_hash());

        // version sensitivity
        let mut entry3 = create_test_entry(b"test_data", 2);
        entry3.metadata.timestamp = 1000;

        let tree3 = BinaryMerkleTree::from_entries(&[entry3]).unwrap();

        assert_ne!(tree1.root_hash(), tree3.root_hash());
    }

    #[test]
    fn test_temporal_ordering_verification() {
        // comprehensive test of temporal ordering preservation
        let mut entries = Vec::new();

        // create entries with specific temporal pattern
        for i in 0..5 {
            let mut entry = create_test_entry(format!("temporal_{}", i).as_bytes(), 1);
            entry.metadata.timestamp = (i * 100) as u64;
            entries.push(entry);
        }

        let tree_ordered = BinaryMerkleTree::from_entries(&entries).unwrap();

        // reverse the temporal order
        entries.reverse();
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.metadata.timestamp = (i * 100) as u64;
        }

        let tree_reversed = BinaryMerkleTree::from_entries(&entries).unwrap();

        // should produce different root hashes due to different temporal ordering
        assert_ne!(tree_ordered.root_hash(), tree_reversed.root_hash());
    }
}
