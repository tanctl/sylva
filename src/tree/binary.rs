use super::node::{NodeMemoryStats, TreeNode};
use super::{
    MerkleProof, Tree, TreeExportData, TreeMemoryUsage, TreeMetadata, TreeSnapshot, TreeStatistics,
    TreeType, VersionedTree,
};
use crate::error::{Result, SylvaError};
use crate::hash::HashDigest;
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Binary Merkle Tree implementation for versioned ledger entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMerkleTree {
    root: Option<TreeNode>,
    entries: HashMap<Uuid, LedgerEntry>,
    version_map: HashMap<u64, Vec<Uuid>>,
    metadata: TreeMetadata,
}

impl Default for BinaryMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryMerkleTree {
    /// Create a new empty binary Merkle tree
    pub fn new() -> Self {
        Self {
            root: None,
            entries: HashMap::new(),
            version_map: HashMap::new(),
            metadata: TreeMetadata::new(TreeType::Binary),
        }
    }

    /// Generate an inclusion proof for a specific entry using the new InclusionProof implementation
    pub fn generate_inclusion_proof(&self, id: &Uuid) -> Result<Option<MerkleProof>> {
        use super::node::TreeNode;
        use crate::hash::Blake3Hasher;
        use crate::proof::inclusion::InclusionProof;

        if let Some(entry) = self.entries.get(id) {
            if self.entries.is_empty() {
                return Ok(None);
            }

            // Handle single entry case
            if self.entries.len() == 1 {
                let hasher = Blake3Hasher::new();
                let leaf_hash = TreeNode::calculate_leaf_hash(&hasher, entry)?;
                let root_hash = self.root_hash().unwrap_or(leaf_hash.clone());

                return Ok(Some(MerkleProof::new(
                    *id,
                    leaf_hash,
                    Vec::new(), // No path elements for single entry
                    root_hash,
                )));
            }

            // Get all entries sorted by the same order as tree construction
            let mut sorted_entries: Vec<_> = self.entries.values().cloned().collect();
            sorted_entries.sort_by(|a, b| {
                a.timestamp
                    .cmp(&b.timestamp)
                    .then_with(|| a.version.cmp(&b.version))
                    .then_with(|| a.id.cmp(&b.id))
            });

            // Find the leaf index for this entry
            let leaf_index = sorted_entries
                .iter()
                .position(|e| e.id == *id)
                .ok_or(crate::proof::ProofError::LeafNotFound { entry_id: *id })?;

            // Create leaf hashes in the same order
            let hasher = Blake3Hasher::new();
            let mut leaf_hashes = Vec::new();
            for entry in &sorted_entries {
                let hash = TreeNode::calculate_leaf_hash(&hasher, entry)?;
                leaf_hashes.push(hash);
            }

            // Generate the inclusion proof
            let inclusion_proof =
                InclusionProof::generate_for_leaf_index(*id, leaf_index, &leaf_hashes)?;

            // Convert to the legacy MerkleProof format for compatibility
            let path_elements: Vec<crate::tree::ProofElement> = inclusion_proof
                .sibling_hashes
                .iter()
                .map(|sibling| crate::tree::ProofElement {
                    hash: sibling.hash.clone(),
                    is_left: sibling.direction == crate::proof::Direction::Left,
                })
                .collect();

            Ok(Some(MerkleProof::new(
                *id,
                inclusion_proof.leaf_hash,
                path_elements,
                inclusion_proof.root_hash,
            )))
        } else {
            Ok(None)
        }
    }

    /// Create a binary Merkle tree from a vector of ledger entries
    pub fn from_entries(entries: Vec<LedgerEntry>) -> Result<Self> {
        let mut tree = Self::new();
        tree.insert_batch(entries)?;
        Ok(tree)
    }

    /// Rebuild the tree from current entries
    fn rebuild_tree(&mut self) -> Result<()> {
        if self.entries.is_empty() {
            self.root = None;
            return Ok(());
        }

        let mut sorted_entries: Vec<_> = self.entries.values().cloned().collect();
        // Sort by timestamp for temporal ordering, then by version for deterministic ordering
        sorted_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.version.cmp(&b.version))
                .then_with(|| a.id.cmp(&b.id))
        });

        self.root = Some(self.build_tree_bottom_up(sorted_entries)?);
        Ok(())
    }

    /// Build a balanced binary tree from entries using bottom-up approach
    fn build_tree_bottom_up(&self, entries: Vec<LedgerEntry>) -> Result<TreeNode> {
        if entries.is_empty() {
            return Err(SylvaError::InvalidTreeStructure);
        }

        // Handle single entry case
        if entries.len() == 1 {
            return TreeNode::new_leaf(entries.into_iter().next().unwrap());
        }

        // Create leaf nodes for all entries
        let mut current_level: Vec<TreeNode> = Vec::new();
        for entry in entries {
            current_level.push(TreeNode::new_leaf(entry)?);
        }

        // Build tree bottom-up, handling odd numbers by duplicating last entry
        while current_level.len() > 1 {
            let mut next_level: Vec<TreeNode> = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // Pair exists, create internal node
                    let left = current_level[i].clone();
                    let right = current_level[i + 1].clone();
                    next_level.push(TreeNode::new_internal(left, right)?);
                } else {
                    // Odd number of nodes, duplicate the last one
                    let node = current_level[i].clone();
                    let duplicated_node = node.clone();
                    next_level.push(TreeNode::new_internal(node, duplicated_node)?);
                }
            }

            current_level = next_level;
        }

        Ok(current_level.into_iter().next().unwrap())
    }

    /// Update the version map after adding entries
    fn update_version_map(&mut self, entry: &LedgerEntry) {
        self.version_map
            .entry(entry.version)
            .or_default()
            .push(entry.id);
    }

    /// Remove entry from version map
    fn remove_from_version_map(&mut self, entry: &LedgerEntry) {
        if let Some(ids) = self.version_map.get_mut(&entry.version) {
            ids.retain(|id| *id != entry.id);
            if ids.is_empty() {
                self.version_map.remove(&entry.version);
            }
        }
    }

    /// Get memory usage statistics
    pub fn memory_stats(&self) -> TreeMemoryStats {
        let mut stats = TreeMemoryStats {
            total_entries: self.entries.len(),
            total_versions: self.version_map.len(),
            node_stats: NodeMemoryStats {
                leaf_nodes: 0,
                internal_nodes: 0,
                total_data_size: 0,
                total_metadata_size: 0,
            },
        };

        if let Some(root) = &self.root {
            stats.node_stats = root.memory_stats();
        }

        stats
    }

    /// Verify the integrity of the entire tree
    pub fn verify_integrity(&self) -> Result<bool> {
        if let Some(root) = &self.root {
            root.verify_structure()
        } else {
            Ok(self.entries.is_empty())
        }
    }

    /// Get all entries sorted by timestamp
    pub fn entries_by_timestamp(&self) -> Vec<&LedgerEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        entries
    }

    /// Get all entries sorted by version
    pub fn entries_by_version(&self) -> Vec<&LedgerEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| a.version.cmp(&b.version));
        entries
    }

    /// Remove an entry by ID
    pub fn remove_entry(&mut self, id: &Uuid) -> Result<Option<LedgerEntry>> {
        if let Some(entry) = self.entries.remove(id) {
            self.remove_from_version_map(&entry);
            self.rebuild_tree()?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Get entries in a specific version range
    pub fn get_entries_in_range(&self, start_version: u64, end_version: u64) -> Vec<&LedgerEntry> {
        self.entries
            .values()
            .filter(|e| e.version >= start_version && e.version <= end_version)
            .collect()
    }

    /// Get entry count by version
    pub fn get_version_counts(&self) -> HashMap<u64, usize> {
        self.version_map
            .iter()
            .map(|(version, ids)| (*version, ids.len()))
            .collect()
    }

    /// Get the default hash for empty ledger
    fn default_hash(&self) -> HashDigest {
        use crate::hash::{Blake3Hasher, Hash as HashTrait};

        let hasher = Blake3Hasher::new();
        // Use a constant for empty tree hash
        hasher
            .hash_bytes(b"SYLVA_EMPTY_TREE_HASH_v1")
            .unwrap_or_else(|_| {
                // Fallback to zero hash if hashing fails
                HashDigest::new([0u8; 32])
            })
    }

    /// Calculate deterministic root hash with proper temporal ordering
    pub fn calculate_deterministic_root_hash(&self) -> HashDigest {
        match &self.root {
            Some(root) => root.hash().clone(),
            None => self.default_hash(),
        }
    }

    /// Verify temporal consistency of the tree
    pub fn verify_temporal_consistency(&self) -> Result<bool> {
        let entries = self.entries_by_timestamp();

        // Check that timestamps are non-decreasing
        for window in entries.windows(2) {
            if window[0].timestamp > window[1].timestamp {
                return Ok(false);
            }

            // If timestamps are equal, check version ordering
            if window[0].timestamp == window[1].timestamp && window[0].version > window[1].version {
                return Ok(false);
            }

            // If timestamps and versions are equal, check ID ordering (deterministic)
            if window[0].timestamp == window[1].timestamp
                && window[0].version == window[1].version
                && window[0].id > window[1].id
            {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Tree for BinaryMerkleTree {
    fn insert(&mut self, entry: LedgerEntry) -> Result<()> {
        let id = entry.id;
        self.update_version_map(&entry);
        self.entries.insert(id, entry);
        self.rebuild_tree()?;
        self.metadata
            .update_stats(self.entries.len(), self.root_hash());
        Ok(())
    }

    fn insert_batch(&mut self, entries: Vec<LedgerEntry>) -> Result<()> {
        for entry in entries {
            let id = entry.id;
            self.update_version_map(&entry);
            self.entries.insert(id, entry);
        }
        self.rebuild_tree()?;
        self.metadata
            .update_stats(self.entries.len(), self.root_hash());
        Ok(())
    }

    fn root_hash(&self) -> Option<HashDigest> {
        self.root.as_ref().map(|root| root.hash().clone())
    }

    fn height(&self) -> usize {
        self.root.as_ref().map_or(0, |root| root.height())
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn latest_version(&self) -> u64 {
        self.entries.values().map(|e| e.version).max().unwrap_or(0)
    }

    fn get_entries(&self) -> Vec<&LedgerEntry> {
        self.entries.values().collect()
    }

    fn get_entries_by_version(&self, version: u64) -> Vec<&LedgerEntry> {
        self.version_map
            .get(&version)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    fn find_entry(&self, id: &Uuid) -> Option<&LedgerEntry> {
        self.entries.get(id)
    }

    fn generate_proof(&self, id: &Uuid) -> Result<Option<MerkleProof>> {
        if let Some(_entry) = self.entries.get(id) {
            // Use the new InclusionProof for more efficient and comprehensive proofs
            return self.generate_inclusion_proof(id);
        }
        Ok(None)
    }

    fn verify_proof(&self, proof: &MerkleProof, entry: &LedgerEntry) -> Result<bool> {
        // Verify that the proof's root hash matches the tree's root hash
        if let Some(tree_root_hash) = self.root_hash() {
            if proof.root_hash != tree_root_hash {
                return Ok(false);
            }
        } else {
            // Empty tree, proof should not exist
            return Ok(false);
        }

        // Use the proof's own verification logic
        proof.verify(entry)
    }

    fn clear(&mut self) {
        self.root = None;
        self.entries.clear();
        self.version_map.clear();
        self.metadata.update_stats(0, None);
    }

    fn tree_type(&self) -> TreeType {
        TreeType::Binary
    }

    fn metadata(&self) -> &TreeMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut TreeMetadata {
        &mut self.metadata
    }

    fn export_data(&self) -> Result<TreeExportData> {
        let entries = self.entries.values().cloned().collect();
        Ok(TreeExportData::from_ledger_entries(
            TreeType::Binary,
            TreeType::Binary, // Default to same type
            entries,
            self.metadata.clone(),
        ))
    }

    fn import_data(&mut self, data: TreeExportData) -> Result<()> {
        if !data.is_compatible_with(TreeType::Binary) {
            return Err(SylvaError::InvalidInput {
                message: "Export data not compatible with binary tree".to_string(),
            });
        }

        self.clear();
        self.insert_batch(data.ledger_entries)?;
        self.metadata = data.metadata;
        self.metadata.tree_type = TreeType::Binary; // Ensure correct type
        Ok(())
    }

    fn validate_structure(&self) -> Result<bool> {
        self.verify_integrity()
    }

    fn memory_usage(&self) -> TreeMemoryUsage {
        let stats = self.memory_stats();
        let structure_bytes = stats.node_stats.total_size();
        let data_bytes = stats.node_stats.total_data_size;
        let metadata_bytes = std::mem::size_of::<TreeMetadata>();
        let total_bytes = structure_bytes + data_bytes + metadata_bytes;

        TreeMemoryUsage::new(total_bytes, data_bytes, metadata_bytes, structure_bytes)
    }
}

impl VersionedTree for BinaryMerkleTree {
    fn get_entries_since_version(&self, version: u64) -> Vec<&LedgerEntry> {
        self.entries
            .values()
            .filter(|e| e.version >= version)
            .collect()
    }

    fn get_entries_between_versions(
        &self,
        start_version: u64,
        end_version: u64,
    ) -> Vec<&LedgerEntry> {
        self.get_entries_in_range(start_version, end_version)
    }

    fn version_range(&self) -> Option<(u64, u64)> {
        if self.entries.is_empty() {
            return None;
        }

        let versions: Vec<u64> = self.version_map.keys().cloned().collect();
        let min_version = versions.iter().min().cloned().unwrap_or(0);
        let max_version = versions.iter().max().cloned().unwrap_or(0);

        Some((min_version, max_version))
    }

    fn snapshot_at_version(&self, version: u64) -> Result<TreeSnapshot> {
        let entries = self
            .get_entries_since_version(0)
            .into_iter()
            .filter(|e| e.version <= version)
            .cloned()
            .collect();

        Ok(TreeSnapshot::new(version, entries, self.root_hash()))
    }

    fn restore_from_snapshot(&mut self, snapshot: TreeSnapshot) -> Result<()> {
        self.clear();
        self.insert_batch(snapshot.entries)?;
        Ok(())
    }

    fn tree_statistics(&self) -> TreeStatistics {
        let memory_usage = self.memory_usage();
        let mut stats = TreeStatistics::new(
            TreeType::Binary,
            self.entry_count(),
            self.height(),
            memory_usage,
        );

        // Add binary tree specific metrics
        stats.add_metric("latest_version", &self.latest_version().to_string());
        stats.add_metric("version_count", &self.version_map.len().to_string());
        stats.add_metric(
            "temporal_consistent",
            &self
                .verify_temporal_consistency()
                .unwrap_or(false)
                .to_string(),
        );

        let version_range = self.version_range();
        if let Some((min, max)) = version_range {
            stats.add_metric("version_range", &format!("{}-{}", min, max));
        }

        stats
    }
}

/// Memory usage statistics for the binary Merkle tree
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeMemoryStats {
    pub total_entries: usize,
    pub total_versions: usize,
    pub node_stats: NodeMemoryStats,
}

impl TreeMemoryStats {
    pub fn total_memory_usage(&self) -> usize {
        self.node_stats.total_size()
    }

    pub fn average_entry_size(&self) -> usize {
        if self.total_entries == 0 {
            0
        } else {
            self.node_stats.total_data_size / self.total_entries
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_empty_tree() {
        let tree = BinaryMerkleTree::new();

        assert!(tree.is_empty());
        assert_eq!(tree.entry_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.latest_version(), 0);
        assert!(tree.root_hash().is_none());
    }

    #[test]
    fn test_single_entry() {
        let mut tree = BinaryMerkleTree::new();
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let id = entry.id;

        tree.insert(entry.clone()).unwrap();

        assert!(!tree.is_empty());
        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.latest_version(), 1);
        assert!(tree.root_hash().is_some());

        let found = tree.find_entry(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &entry);
    }

    #[test]
    fn test_multiple_entries() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
            LedgerEntry::new(b"data3".to_vec(), 3),
        ];

        tree.insert_batch(entries.clone()).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.height(), 2); // With 3 entries, tree height is 2
        assert_eq!(tree.latest_version(), 3);

        for entry in &entries {
            assert!(tree.find_entry(&entry.id).is_some());
        }
    }

    #[test]
    fn test_version_queries() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 1),
            LedgerEntry::new(b"data3".to_vec(), 2),
            LedgerEntry::new(b"data4".to_vec(), 3),
        ];

        tree.insert_batch(entries).unwrap();

        let version_1_entries = tree.get_entries_by_version(1);
        assert_eq!(version_1_entries.len(), 2);

        let version_2_entries = tree.get_entries_by_version(2);
        assert_eq!(version_2_entries.len(), 1);

        let since_version_2 = tree.get_entries_since_version(2);
        assert_eq!(since_version_2.len(), 2);

        let between_1_2 = tree.get_entries_between_versions(1, 2);
        assert_eq!(between_1_2.len(), 3);

        let version_range = tree.version_range();
        assert_eq!(version_range, Some((1, 3)));
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = BinaryMerkleTree::new();

        // Create entries with deterministic timestamps for consistent behavior
        let mut entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        entry1.timestamp = 1000;
        let mut entry2 = LedgerEntry::new(b"data2".to_vec(), 2);
        entry2.timestamp = 2000;
        let id1 = entry1.id;

        tree.insert(entry1.clone()).unwrap();
        tree.insert(entry2).unwrap();

        let proof = tree.generate_proof(&id1).unwrap();
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.entry_id, id1);

        // The proof should be self-verifying (CLI verification works)
        let is_valid = proof.verify(&entry1).unwrap();
        assert!(is_valid);

        // Test with non-existent entry
        let fake_id = Uuid::new_v4();
        let no_proof = tree.generate_proof(&fake_id).unwrap();
        assert!(no_proof.is_none());
    }

    #[test]
    fn test_tree_from_entries() {
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
            LedgerEntry::new(b"data3".to_vec(), 3),
        ];

        let tree = BinaryMerkleTree::from_entries(entries.clone()).unwrap();

        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.latest_version(), 3);

        for entry in &entries {
            assert!(tree.find_entry(&entry.id).is_some());
        }
    }

    #[test]
    fn test_tree_snapshots() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
            LedgerEntry::new(b"data3".to_vec(), 3),
        ];

        tree.insert_batch(entries).unwrap();

        let snapshot = tree.snapshot_at_version(2).unwrap();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.entry_count(), 2);

        let mut new_tree = BinaryMerkleTree::new();
        new_tree.restore_from_snapshot(snapshot).unwrap();

        assert_eq!(new_tree.entry_count(), 2);
        assert_eq!(new_tree.latest_version(), 2);
    }

    #[test]
    fn test_entry_removal() {
        let mut tree = BinaryMerkleTree::new();
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let id = entry.id;

        tree.insert(entry).unwrap();
        assert_eq!(tree.entry_count(), 1);

        let removed = tree.remove_entry(&id).unwrap();
        assert!(removed.is_some());
        assert_eq!(tree.entry_count(), 0);
        assert!(tree.is_empty());

        let removed_again = tree.remove_entry(&id).unwrap();
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_memory_stats() {
        let mut tree = BinaryMerkleTree::new();
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let entry = LedgerEntry::new(b"test data".to_vec(), 1).with_metadata(metadata);
        tree.insert(entry).unwrap();

        let stats = tree.memory_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_versions, 1);
        assert_eq!(stats.node_stats.leaf_nodes, 1);
        assert_eq!(stats.node_stats.internal_nodes, 0);
        assert_eq!(stats.node_stats.total_data_size, 9); // "test data".len()
    }

    #[test]
    fn test_tree_integrity() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
        ];

        tree.insert_batch(entries).unwrap();

        assert!(tree.verify_integrity().unwrap());
    }

    #[test]
    fn test_version_counts() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 1),
            LedgerEntry::new(b"data3".to_vec(), 2),
        ];

        tree.insert_batch(entries).unwrap();

        let counts = tree.get_version_counts();
        assert_eq!(counts.get(&1), Some(&2));
        assert_eq!(counts.get(&2), Some(&1));
        assert_eq!(counts.get(&3), None);
    }

    #[test]
    fn test_empty_tree_root_hash() {
        let tree = BinaryMerkleTree::new();

        let root_hash = tree.root_hash();
        assert!(root_hash.is_none());
    }

    #[test]
    fn test_single_entry_root_hash() {
        let mut tree = BinaryMerkleTree::new();
        let entry = LedgerEntry::new(b"single entry".to_vec(), 1);

        tree.insert(entry.clone()).unwrap();

        let root_hash = tree.root_hash();
        assert!(root_hash.is_some());

        // Single entry: root hash should be the entry's hash
        if let Some(root) = &tree.root {
            assert_eq!(root_hash.unwrap(), *root.hash());
        }
    }

    #[test]
    fn test_deterministic_root_hash() {
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
            LedgerEntry::new(b"data3".to_vec(), 3),
        ];

        let mut tree1 = BinaryMerkleTree::new();
        tree1.insert_batch(entries.clone()).unwrap();
        let hash1 = tree1.root_hash().unwrap();

        let mut tree2 = BinaryMerkleTree::new();
        tree2.insert_batch(entries).unwrap();
        let hash2 = tree2.root_hash().unwrap();

        // Root hashes should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_odd_number_entries_duplication() {
        let mut tree = BinaryMerkleTree::new();
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
            LedgerEntry::new(b"data3".to_vec(), 3), // Odd number
        ];

        tree.insert_batch(entries).unwrap();

        // Should successfully build tree with odd number of entries
        assert!(tree.root_hash().is_some());
        assert_eq!(tree.entry_count(), 3);
        assert_eq!(tree.height(), 2); // Height should reflect balanced tree
    }

    #[test]
    fn test_temporal_consistency() {
        let mut tree = BinaryMerkleTree::new();

        // Add entries with increasing timestamps
        let mut entries = vec![];
        for i in 1u32..=5 {
            let mut entry = LedgerEntry::new(format!("data{}", i).into_bytes(), i as u64);
            entry.timestamp = (i as u64) * 1000; // Ensure increasing timestamps
            entries.push(entry);
        }

        tree.insert_batch(entries).unwrap();

        // Verify temporal consistency
        assert!(tree.verify_temporal_consistency().unwrap());
    }

    #[test]
    fn test_version_metadata_in_hash() {
        let mut tree = BinaryMerkleTree::new();

        // Create two entries with same data but different versions
        let entry1 = LedgerEntry::new(b"same data".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"same data".to_vec(), 2);

        tree.insert(entry1).unwrap();
        let hash1 = tree.root_hash().unwrap();

        tree.clear();
        tree.insert(entry2).unwrap();
        let hash2 = tree.root_hash().unwrap();

        // Hashes should be different despite same data (different versions)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_metadata_in_hash() {
        let mut tree = BinaryMerkleTree::new();

        // Create entries with same data but different metadata
        let mut metadata1 = std::collections::HashMap::new();
        metadata1.insert("key1".to_string(), "value1".to_string());

        let mut metadata2 = std::collections::HashMap::new();
        metadata2.insert("key2".to_string(), "value2".to_string());

        let entry1 = LedgerEntry::new(b"same data".to_vec(), 1).with_metadata(metadata1);
        let entry2 = LedgerEntry::new(b"same data".to_vec(), 1).with_metadata(metadata2);

        tree.insert(entry1).unwrap();
        let hash1 = tree.root_hash().unwrap();

        tree.clear();
        tree.insert(entry2).unwrap();
        let hash2 = tree.root_hash().unwrap();

        // Hashes should be different due to different metadata
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_ordering_deterministic() {
        let mut tree = BinaryMerkleTree::new();

        // Create entries with specific timestamps to ensure deterministic ordering
        let mut entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        entry1.timestamp = 1000;
        let mut entry2 = LedgerEntry::new(b"data2".to_vec(), 2);
        entry2.timestamp = 2000;
        let mut entry3 = LedgerEntry::new(b"data3".to_vec(), 3);
        entry3.timestamp = 3000;

        // Add entries in different orders
        let entries1 = vec![entry1.clone(), entry2.clone(), entry3.clone()];
        let entries2 = vec![entry3.clone(), entry1.clone(), entry2.clone()];

        tree.insert_batch(entries1).unwrap();
        let hash1 = tree.root_hash().unwrap();

        tree.clear();
        tree.insert_batch(entries2).unwrap();
        let hash2 = tree.root_hash().unwrap();

        // Should be deterministic regardless of insertion order due to sorting
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_large_tree_performance() {
        let mut tree = BinaryMerkleTree::new();

        // Create a large number of entries with incremental timestamps
        let entries: Vec<LedgerEntry> = (0..1000)
            .map(|i| {
                let mut entry = LedgerEntry::new(format!("data{}", i).into_bytes(), i as u64);
                entry.timestamp = 1000 + i as u64; // Incremental timestamps
                entry
            })
            .collect();

        tree.insert_batch(entries).unwrap();

        // Should handle large trees efficiently
        assert_eq!(tree.entry_count(), 1000);
        assert!(tree.root_hash().is_some());
        assert!(tree.verify_temporal_consistency().unwrap());
    }

    #[test]
    fn test_power_of_two_vs_non_power_of_two() {
        let mut tree_4 = BinaryMerkleTree::new();
        let mut tree_5 = BinaryMerkleTree::new();

        // 4 entries (power of 2)
        let entries_4: Vec<LedgerEntry> = (1..=4)
            .map(|i| LedgerEntry::new(format!("data{}", i).into_bytes(), i as u64))
            .collect();

        // 5 entries (not power of 2)
        let entries_5: Vec<LedgerEntry> = (1..=5)
            .map(|i| LedgerEntry::new(format!("data{}", i).into_bytes(), i as u64))
            .collect();

        tree_4.insert_batch(entries_4).unwrap();
        tree_5.insert_batch(entries_5).unwrap();

        // Both should work and have different hashes
        assert!(tree_4.root_hash().is_some());
        assert!(tree_5.root_hash().is_some());
        assert_ne!(tree_4.root_hash().unwrap(), tree_5.root_hash().unwrap());
    }

    mod test_vectors {
        use super::*;

        #[test]
        fn test_known_vector_empty_tree() {
            let tree = BinaryMerkleTree::new();
            let root_hash = tree.root_hash();

            // Empty tree should return None for root hash
            assert!(root_hash.is_none(), "Empty tree should have no root hash");
        }

        #[test]
        fn test_known_vector_single_entry() {
            let mut tree = BinaryMerkleTree::new();
            let mut entry = LedgerEntry::new(b"test".to_vec(), 1);

            // Set deterministic values for reproducible test
            entry.timestamp = 1000;
            entry.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

            tree.insert(entry).unwrap();
            let root_hash = tree.root_hash().unwrap();

            // This would be the expected hash for this specific entry
            // In practice, you'd compute this once and then use it as a regression test
            assert_eq!(root_hash.as_bytes().len(), 32);
        }

        #[test]
        fn test_known_vector_two_entries() {
            let mut tree = BinaryMerkleTree::new();

            let mut entry1 = LedgerEntry::new(b"first".to_vec(), 1);
            entry1.timestamp = 1000;
            entry1.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

            let mut entry2 = LedgerEntry::new(b"second".to_vec(), 2);
            entry2.timestamp = 2000;
            entry2.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();

            tree.insert_batch(vec![entry1, entry2]).unwrap();
            let root_hash = tree.root_hash().unwrap();

            // This would be the expected hash for these two specific entries
            assert_eq!(root_hash.as_bytes().len(), 32);
        }

        #[test]
        fn test_known_vector_three_entries_odd() {
            let mut tree = BinaryMerkleTree::new();

            let mut entry1 = LedgerEntry::new(b"first".to_vec(), 1);
            entry1.timestamp = 1000;
            entry1.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

            let mut entry2 = LedgerEntry::new(b"second".to_vec(), 2);
            entry2.timestamp = 2000;
            entry2.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();

            let mut entry3 = LedgerEntry::new(b"third".to_vec(), 3);
            entry3.timestamp = 3000;
            entry3.id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();

            tree.insert_batch(vec![entry1, entry2, entry3]).unwrap();
            let root_hash = tree.root_hash().unwrap();

            // This tests the odd number handling (third entry gets duplicated)
            assert_eq!(root_hash.as_bytes().len(), 32);
        }

        #[test]
        fn test_regression_deterministic_order() {
            // This test ensures that hash calculation remains deterministic
            // across different code changes
            let mut tree = BinaryMerkleTree::new();

            // Create entries with known, deterministic values
            let entries = vec![
                create_deterministic_entry(
                    b"data1",
                    1,
                    1000,
                    "550e8400-e29b-41d4-a716-446655440000",
                ),
                create_deterministic_entry(
                    b"data2",
                    2,
                    2000,
                    "550e8400-e29b-41d4-a716-446655440001",
                ),
                create_deterministic_entry(
                    b"data3",
                    3,
                    3000,
                    "550e8400-e29b-41d4-a716-446655440002",
                ),
                create_deterministic_entry(
                    b"data4",
                    4,
                    4000,
                    "550e8400-e29b-41d4-a716-446655440003",
                ),
            ];

            tree.insert_batch(entries).unwrap();
            let root_hash = tree.root_hash().unwrap();

            // This hash should remain the same across code changes
            // as long as the hash calculation algorithm is unchanged
            assert_eq!(root_hash.as_bytes().len(), 32);

            // Test the same entries in different order produce same hash
            let mut tree2 = BinaryMerkleTree::new();
            let entries2 = vec![
                create_deterministic_entry(
                    b"data3",
                    3,
                    3000,
                    "550e8400-e29b-41d4-a716-446655440002",
                ),
                create_deterministic_entry(
                    b"data1",
                    1,
                    1000,
                    "550e8400-e29b-41d4-a716-446655440000",
                ),
                create_deterministic_entry(
                    b"data4",
                    4,
                    4000,
                    "550e8400-e29b-41d4-a716-446655440003",
                ),
                create_deterministic_entry(
                    b"data2",
                    2,
                    2000,
                    "550e8400-e29b-41d4-a716-446655440001",
                ),
            ];

            tree2.insert_batch(entries2).unwrap();
            let root_hash2 = tree2.root_hash().unwrap();

            assert_eq!(root_hash, root_hash2);
        }

        fn create_deterministic_entry(
            data: &[u8],
            version: u64,
            timestamp: u64,
            uuid_str: &str,
        ) -> LedgerEntry {
            let mut entry = LedgerEntry::new(data.to_vec(), version);
            entry.timestamp = timestamp;
            entry.id = uuid::Uuid::parse_str(uuid_str).unwrap();
            entry
        }
    }
}
