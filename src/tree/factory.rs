//! Tree factory for creating and managing different tree types

use super::{
    binary::BinaryMerkleTree,
    patricia::PatriciaTrie,
    sparse::{SparseKey, SparseMerkleTree},
    Tree, TreeExportData, TreeMetadata, TreeStatistics, TreeType, VersionedTree,
};
use crate::error::{Result, SylvaError};
use crate::ledger::LedgerEntry;
use std::collections::HashMap;
use uuid::Uuid;

/// Unified tree interface that wraps different tree implementations
#[derive(Debug, Clone)]
pub enum UnifiedTree {
    /// Binary Merkle Tree
    Binary(BinaryMerkleTree),
    /// Sparse Merkle Tree
    Sparse(SparseMerkleTree),
    /// Patricia Trie
    Patricia(PatriciaTrie),
}

impl UnifiedTree {
    /// Create a new tree of the specified type
    pub fn new(tree_type: TreeType) -> Self {
        match tree_type {
            TreeType::Binary => UnifiedTree::Binary(BinaryMerkleTree::new()),
            TreeType::Sparse => UnifiedTree::Sparse(SparseMerkleTree::new()),
            TreeType::Patricia => UnifiedTree::Patricia(PatriciaTrie::new()),
        }
    }

    /// Create a tree from configuration
    pub fn from_config(tree_type: TreeType, config: &HashMap<String, String>) -> Result<Self> {
        let mut tree = Self::new(tree_type);

        // Apply configuration
        for (key, value) in config {
            tree.metadata_mut().set_config(key, value);
        }

        Ok(tree)
    }

    /// Get the tree type
    pub fn tree_type(&self) -> TreeType {
        match self {
            UnifiedTree::Binary(tree) => tree.tree_type(),
            UnifiedTree::Sparse(tree) => tree.tree_type(),
            UnifiedTree::Patricia(tree) => tree.tree_type(),
        }
    }

    /// Get tree metadata
    pub fn metadata(&self) -> &TreeMetadata {
        match self {
            UnifiedTree::Binary(tree) => tree.metadata(),
            UnifiedTree::Sparse(tree) => tree.metadata(),
            UnifiedTree::Patricia(tree) => tree.metadata(),
        }
    }

    /// Get mutable tree metadata
    pub fn metadata_mut(&mut self) -> &mut TreeMetadata {
        match self {
            UnifiedTree::Binary(tree) => tree.metadata_mut(),
            UnifiedTree::Sparse(tree) => tree.metadata_mut(),
            UnifiedTree::Patricia(tree) => tree.metadata_mut(),
        }
    }

    /// Get tree statistics
    pub fn statistics(&self) -> TreeStatistics {
        match self {
            UnifiedTree::Binary(tree) => tree.tree_statistics(),
            UnifiedTree::Sparse(tree) => tree.tree_statistics(),
            UnifiedTree::Patricia(tree) => tree.tree_statistics(),
        }
    }

    /// Insert a ledger entry (works for all tree types)
    pub fn insert_ledger_entry(&mut self, entry: LedgerEntry) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => tree.insert(entry),
            UnifiedTree::Sparse(tree) => {
                // Convert ledger entry to key-value pair
                let key = SparseKey::from_slice(&entry.id.as_bytes()[..]);
                tree.insert(key, entry.data)?;
                Ok(())
            }
            UnifiedTree::Patricia(tree) => {
                // Convert ledger entry to key-value pair
                let key = entry.id.as_bytes().to_vec();
                tree.insert(&key, entry.data)?;
                Ok(())
            }
        }
    }

    /// Insert multiple ledger entries
    pub fn insert_ledger_entries(&mut self, entries: Vec<LedgerEntry>) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => tree.insert_batch(entries),
            UnifiedTree::Sparse(tree) => {
                for entry in entries {
                    let key = SparseKey::from_slice(&entry.id.as_bytes()[..]);
                    tree.insert(key, entry.data)?;
                }
                Ok(())
            }
            UnifiedTree::Patricia(tree) => {
                let pairs = entries
                    .into_iter()
                    .map(|entry| (entry.id.as_bytes().to_vec(), entry.data))
                    .collect();
                tree.batch_insert(pairs)?;
                Ok(())
            }
        }
    }

    /// Insert a key-value pair (works for sparse and patricia trees)
    pub fn insert_key_value(&mut self, key: &[u8], value: Vec<u8>) -> Result<()> {
        match self {
            UnifiedTree::Binary(_) => Err(SylvaError::InvalidInput {
                message: "Binary trees use ledger entries, not key-value pairs".to_string(),
            }),
            UnifiedTree::Sparse(tree) => {
                let sparse_key = SparseKey::from_slice(key);
                tree.insert(sparse_key, value)?;
                Ok(())
            }
            UnifiedTree::Patricia(tree) => {
                tree.insert(key, value)?;
                Ok(())
            }
        }
    }

    /// Get a value by key (works for sparse and patricia trees)
    pub fn get_by_key(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            UnifiedTree::Binary(_) => Err(SylvaError::InvalidInput {
                message: "Binary trees use ledger entries, not key-value pairs".to_string(),
            }),
            UnifiedTree::Sparse(tree) => {
                let sparse_key = SparseKey::from_slice(key);
                Ok(tree.get(&sparse_key).map(|v| v.to_vec()))
            }
            UnifiedTree::Patricia(tree) => Ok(tree.get(key)),
        }
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        match self {
            UnifiedTree::Binary(tree) => tree.is_empty(),
            UnifiedTree::Sparse(tree) => tree.is_empty(),
            UnifiedTree::Patricia(tree) => tree.is_empty(),
        }
    }

    /// Get entry count
    pub fn entry_count(&self) -> usize {
        match self {
            UnifiedTree::Binary(tree) => tree.entry_count(),
            UnifiedTree::Sparse(tree) => tree.entry_count(),
            UnifiedTree::Patricia(tree) => tree.entry_count(),
        }
    }

    /// Get tree height
    pub fn height(&self) -> usize {
        match self {
            UnifiedTree::Binary(tree) => tree.height(),
            UnifiedTree::Sparse(tree) => tree.height(),
            UnifiedTree::Patricia(_tree) => 0, // Patricia tries don't have a fixed height
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        match self {
            UnifiedTree::Binary(tree) => tree.clear(),
            UnifiedTree::Sparse(tree) => tree.clear(),
            UnifiedTree::Patricia(tree) => {
                *tree = PatriciaTrie::new();
            }
        }
    }

    /// Validate tree structure
    pub fn validate(&self) -> Result<bool> {
        match self {
            UnifiedTree::Binary(tree) => tree.validate_structure(),
            UnifiedTree::Sparse(tree) => {
                let report = tree.validate_consistency()?;
                Ok(report.is_consistent)
            }
            UnifiedTree::Patricia(tree) => tree.verify_structure(),
        }
    }

    /// Export tree data for migration
    pub fn export_for_migration(&self, target_type: TreeType) -> Result<TreeExportData> {
        match self {
            UnifiedTree::Binary(tree) => {
                let mut data = tree.export_data()?;
                data.target_tree_type = target_type;
                Ok(data)
            }
            UnifiedTree::Sparse(tree) => {
                let pairs = tree
                    .entries()
                    .into_iter()
                    .map(|(key, value)| (key.as_bytes().to_vec(), value))
                    .collect();
                let mut metadata = tree.metadata().clone();
                metadata.tree_type = target_type;
                Ok(TreeExportData::from_key_value_pairs(
                    TreeType::Sparse,
                    target_type,
                    pairs,
                    metadata,
                ))
            }
            UnifiedTree::Patricia(tree) => {
                let pairs = tree.iter().collect();
                let mut metadata = TreeMetadata::new(target_type);
                metadata.entry_count = tree.entry_count();
                Ok(TreeExportData::from_key_value_pairs(
                    TreeType::Patricia,
                    target_type,
                    pairs,
                    metadata,
                ))
            }
        }
    }

    /// Import tree data from migration
    pub fn import_from_migration(&mut self, data: TreeExportData) -> Result<()> {
        let target_type = self.tree_type();
        if !data.is_compatible_with(target_type) {
            return Err(SylvaError::InvalidInput {
                message: format!(
                    "Cannot import {} data into {} tree",
                    data.source_tree_type.as_str(),
                    target_type.as_str()
                ),
            });
        }

        match self {
            UnifiedTree::Binary(tree) => {
                if !data.ledger_entries.is_empty() {
                    tree.import_data(data)?;
                } else {
                    // Convert key-value pairs to ledger entries
                    let entries = data
                        .key_value_pairs
                        .into_iter()
                        .enumerate()
                        .map(|(i, (key, value))| {
                            let mut entry = LedgerEntry::new(value, i as u64 + 1);
                            // Use first 16 bytes of key as UUID if possible
                            if key.len() >= 16 {
                                let uuid_bytes = &key[..16];
                                if let Ok(uuid) = uuid::Uuid::from_slice(uuid_bytes) {
                                    entry.id = uuid;
                                }
                            }
                            entry
                        })
                        .collect();
                    tree.insert_batch(entries)?;
                }
            }
            UnifiedTree::Sparse(tree) => {
                tree.clear();

                // Handle ledger entries (from binary tree migration)
                if !data.ledger_entries.is_empty() {
                    for entry in data.ledger_entries {
                        // Use entry ID as key and data as value
                        let key_bytes = entry.id.as_bytes().to_vec();
                        let sparse_key = SparseKey::from_slice(&key_bytes);
                        tree.insert(sparse_key, entry.data)?;
                    }
                }

                // Handle key-value pairs (from patricia tree migration)
                for (key, value) in data.key_value_pairs {
                    let sparse_key = SparseKey::from_slice(&key);
                    tree.insert(sparse_key, value)?;
                }
            }
            UnifiedTree::Patricia(tree) => {
                *tree = PatriciaTrie::new();

                // Handle ledger entries (from binary tree migration)
                if !data.ledger_entries.is_empty() {
                    for entry in data.ledger_entries {
                        // Use entry ID as key and data as value
                        let key_bytes = entry.id.as_bytes().to_vec();
                        tree.insert(&key_bytes, entry.data)?;
                    }
                }

                // Handle key-value pairs (from sparse tree migration)
                for (key, value) in data.key_value_pairs {
                    tree.insert(&key, value)?;
                }
            }
        }

        Ok(())
    }

    /// Migrate to a different tree type
    pub fn migrate_to(&self, target_type: TreeType) -> Result<UnifiedTree> {
        if self.tree_type() == target_type {
            return Ok(self.clone());
        }

        if !self.tree_type().is_compatible_with(&target_type) {
            return Err(SylvaError::InvalidInput {
                message: format!(
                    "Cannot migrate directly from {} to {}. Consider using an intermediate format.",
                    self.tree_type().as_str(),
                    target_type.as_str()
                ),
            });
        }

        let export_data = self.export_for_migration(target_type)?;
        let mut new_tree = UnifiedTree::new(target_type);
        new_tree.import_from_migration(export_data)?;
        Ok(new_tree)
    }

    /// Get memory usage for the tree
    pub fn memory_usage(&self) -> super::TreeMemoryUsage {
        match self {
            UnifiedTree::Binary(tree) => tree.memory_usage(),
            UnifiedTree::Sparse(tree) => tree.memory_usage(),
            UnifiedTree::Patricia(tree) => tree.memory_usage(),
        }
    }

    /// Compact the tree by removing unused/redundant nodes
    pub fn compact(&mut self) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => {
                // For binary trees, rebuilding can help optimize structure
                let entries: Vec<LedgerEntry> =
                    tree.get_entries().iter().map(|e| (*e).clone()).collect();
                tree.clear();
                tree.insert_batch(entries)?;
                Ok(())
            }
            UnifiedTree::Sparse(_tree) => {
                // Sparse trees are self-consistent by design
                // No repair needed for sparse Merkle trees
                Ok(())
            }
            UnifiedTree::Patricia(tree) => {
                // For patricia tries, rebuild from current entries to optimize structure
                let pairs: Vec<(Vec<u8>, Vec<u8>)> = tree.iter().collect();
                *tree = PatriciaTrie::new();
                tree.batch_insert(pairs)?;
                Ok(())
            }
        }
    }

    /// Remove redundant data from the tree
    pub fn remove_redundant_data(&mut self) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => {
                // Binary trees don't typically have redundant data in their structure
                // but we can ensure optimal tree layout
                if tree.entry_count() > 1 {
                    let entries: Vec<LedgerEntry> =
                        tree.get_entries().iter().map(|e| (*e).clone()).collect();
                    tree.clear();
                    tree.insert_batch(entries)?;
                }
                Ok(())
            }
            UnifiedTree::Sparse(_tree) => {
                // Sparse trees are already optimized by design
                Ok(())
            }
            UnifiedTree::Patricia(_tree) => {
                // Patricia tries are already optimized with path compression
                Ok(())
            }
        }
    }

    /// Rebalance the tree for better access patterns
    pub fn rebalance(&mut self) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => {
                // Rebalance by rebuilding the tree with optimal structure
                let mut entries: Vec<LedgerEntry> =
                    tree.get_entries().iter().map(|e| (*e).clone()).collect();
                // Sort entries by a combination of access frequency and data locality
                entries.sort_by(|a, b| {
                    // Sort by timestamp for temporal locality, then by ID for consistency
                    a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
                });
                tree.clear();
                tree.insert_batch(entries)?;
                Ok(())
            }
            UnifiedTree::Sparse(_tree) => {
                // Sparse trees are naturally balanced by design
                Ok(())
            }
            UnifiedTree::Patricia(_tree) => {
                // Patricia tries are self-balancing with automatic path compression
                Ok(())
            }
        }
    }
}

/// Tree factory for creating trees
pub struct TreeFactory {
    /// Default tree type
    default_type: TreeType,
    /// Default configuration
    default_config: HashMap<String, String>,
}

impl TreeFactory {
    /// Create a new tree factory
    pub fn new() -> Self {
        Self {
            default_type: TreeType::Binary,
            default_config: HashMap::new(),
        }
    }

    /// Set the default tree type
    pub fn with_default_type(mut self, tree_type: TreeType) -> Self {
        self.default_type = tree_type;
        self
    }

    /// Set default configuration
    pub fn with_config(mut self, key: &str, value: &str) -> Self {
        self.default_config
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Create a tree with default settings
    pub fn create_default(&self) -> Result<UnifiedTree> {
        UnifiedTree::from_config(self.default_type, &self.default_config)
    }

    /// Create a tree of specific type
    pub fn create(&self, tree_type: TreeType) -> Result<UnifiedTree> {
        UnifiedTree::from_config(tree_type, &self.default_config)
    }

    /// Create a tree with custom configuration
    pub fn create_with_config(
        &self,
        tree_type: TreeType,
        config: &HashMap<String, String>,
    ) -> Result<UnifiedTree> {
        let mut merged_config = self.default_config.clone();
        merged_config.extend(config.clone());
        UnifiedTree::from_config(tree_type, &merged_config)
    }

    /// Detect tree type from metadata
    pub fn detect_tree_type(&self, metadata: &TreeMetadata) -> TreeType {
        metadata.tree_type
    }

    /// Get all supported tree types
    pub fn supported_types(&self) -> &'static [TreeType] {
        TreeType::all()
    }

    /// Check if migration is possible between two tree types
    pub fn can_migrate(&self, from: TreeType, to: TreeType) -> bool {
        from.is_compatible_with(&to)
    }

    /// Get migration path between two tree types
    pub fn migration_path(&self, from: TreeType, to: TreeType) -> Vec<TreeType> {
        if from == to {
            return vec![from];
        }

        if from.is_compatible_with(&to) {
            return vec![from, to];
        }

        // For incompatible types, find intermediate path
        match (from, to) {
            (TreeType::Patricia, TreeType::Binary) => {
                vec![TreeType::Patricia, TreeType::Sparse, TreeType::Binary]
            }
            _ => vec![], // No path found
        }
    }
}

impl Tree for UnifiedTree {
    fn insert(&mut self, entry: LedgerEntry) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => Tree::insert(tree, entry),
            UnifiedTree::Sparse(tree) => Tree::insert(tree, entry),
            UnifiedTree::Patricia(tree) => Tree::insert(tree, entry),
        }
    }

    fn insert_batch(&mut self, entries: Vec<LedgerEntry>) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => Tree::insert_batch(tree, entries),
            UnifiedTree::Sparse(tree) => Tree::insert_batch(tree, entries),
            UnifiedTree::Patricia(tree) => Tree::insert_batch(tree, entries),
        }
    }

    fn root_hash(&self) -> Option<super::HashDigest> {
        match self {
            UnifiedTree::Binary(tree) => Tree::root_hash(tree),
            UnifiedTree::Sparse(tree) => Tree::root_hash(tree),
            UnifiedTree::Patricia(tree) => Tree::root_hash(tree),
        }
    }

    fn height(&self) -> usize {
        match self {
            UnifiedTree::Binary(tree) => Tree::height(tree),
            UnifiedTree::Sparse(tree) => Tree::height(tree),
            UnifiedTree::Patricia(tree) => Tree::height(tree),
        }
    }

    fn entry_count(&self) -> usize {
        match self {
            UnifiedTree::Binary(tree) => Tree::entry_count(tree),
            UnifiedTree::Sparse(tree) => Tree::entry_count(tree),
            UnifiedTree::Patricia(tree) => Tree::entry_count(tree),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            UnifiedTree::Binary(tree) => Tree::is_empty(tree),
            UnifiedTree::Sparse(tree) => Tree::is_empty(tree),
            UnifiedTree::Patricia(tree) => Tree::is_empty(tree),
        }
    }

    fn latest_version(&self) -> u64 {
        match self {
            UnifiedTree::Binary(tree) => Tree::latest_version(tree),
            UnifiedTree::Sparse(tree) => Tree::latest_version(tree),
            UnifiedTree::Patricia(tree) => Tree::latest_version(tree),
        }
    }

    fn get_entries(&self) -> Vec<&LedgerEntry> {
        match self {
            UnifiedTree::Binary(tree) => Tree::get_entries(tree),
            UnifiedTree::Sparse(tree) => Tree::get_entries(tree),
            UnifiedTree::Patricia(tree) => Tree::get_entries(tree),
        }
    }

    fn get_entries_by_version(&self, version: u64) -> Vec<&LedgerEntry> {
        match self {
            UnifiedTree::Binary(tree) => Tree::get_entries_by_version(tree, version),
            UnifiedTree::Sparse(tree) => Tree::get_entries_by_version(tree, version),
            UnifiedTree::Patricia(tree) => Tree::get_entries_by_version(tree, version),
        }
    }

    fn find_entry(&self, id: &Uuid) -> Option<&LedgerEntry> {
        match self {
            UnifiedTree::Binary(tree) => Tree::find_entry(tree, id),
            UnifiedTree::Sparse(tree) => Tree::find_entry(tree, id),
            UnifiedTree::Patricia(tree) => Tree::find_entry(tree, id),
        }
    }

    fn generate_proof(&self, id: &Uuid) -> Result<Option<super::MerkleProof>> {
        match self {
            UnifiedTree::Binary(tree) => Tree::generate_proof(tree, id),
            UnifiedTree::Sparse(tree) => Tree::generate_proof(tree, id),
            UnifiedTree::Patricia(tree) => Tree::generate_proof(tree, id),
        }
    }

    fn verify_proof(&self, proof: &super::MerkleProof, entry: &LedgerEntry) -> Result<bool> {
        match self {
            UnifiedTree::Binary(tree) => Tree::verify_proof(tree, proof, entry),
            UnifiedTree::Sparse(tree) => Tree::verify_proof(tree, proof, entry),
            UnifiedTree::Patricia(tree) => Tree::verify_proof(tree, proof, entry),
        }
    }

    fn clear(&mut self) {
        match self {
            UnifiedTree::Binary(tree) => Tree::clear(tree),
            UnifiedTree::Sparse(tree) => Tree::clear(tree),
            UnifiedTree::Patricia(tree) => Tree::clear(tree),
        }
    }

    fn tree_type(&self) -> TreeType {
        match self {
            UnifiedTree::Binary(_) => TreeType::Binary,
            UnifiedTree::Sparse(_) => TreeType::Sparse,
            UnifiedTree::Patricia(_) => TreeType::Patricia,
        }
    }

    fn metadata(&self) -> &super::TreeMetadata {
        match self {
            UnifiedTree::Binary(tree) => Tree::metadata(tree),
            UnifiedTree::Sparse(tree) => Tree::metadata(tree),
            UnifiedTree::Patricia(tree) => Tree::metadata(tree),
        }
    }

    fn metadata_mut(&mut self) -> &mut super::TreeMetadata {
        match self {
            UnifiedTree::Binary(tree) => Tree::metadata_mut(tree),
            UnifiedTree::Sparse(tree) => Tree::metadata_mut(tree),
            UnifiedTree::Patricia(tree) => Tree::metadata_mut(tree),
        }
    }

    fn export_data(&self) -> Result<super::TreeExportData> {
        match self {
            UnifiedTree::Binary(tree) => Tree::export_data(tree),
            UnifiedTree::Sparse(tree) => Tree::export_data(tree),
            UnifiedTree::Patricia(tree) => Tree::export_data(tree),
        }
    }

    fn import_data(&mut self, data: super::TreeExportData) -> Result<()> {
        match self {
            UnifiedTree::Binary(tree) => Tree::import_data(tree, data),
            UnifiedTree::Sparse(tree) => Tree::import_data(tree, data),
            UnifiedTree::Patricia(tree) => Tree::import_data(tree, data),
        }
    }

    fn validate_structure(&self) -> Result<bool> {
        match self {
            UnifiedTree::Binary(tree) => Tree::validate_structure(tree),
            UnifiedTree::Sparse(tree) => Tree::validate_structure(tree),
            UnifiedTree::Patricia(tree) => Tree::validate_structure(tree),
        }
    }

    fn memory_usage(&self) -> super::TreeMemoryUsage {
        match self {
            UnifiedTree::Binary(tree) => Tree::memory_usage(tree),
            UnifiedTree::Sparse(tree) => Tree::memory_usage(tree),
            UnifiedTree::Patricia(tree) => Tree::memory_usage(tree),
        }
    }
}

impl Default for TreeFactory {
    fn default() -> Self {
        Self::new()
    }
}
