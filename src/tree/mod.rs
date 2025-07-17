pub mod binary;
pub mod factory;
pub mod node;
pub mod patricia;
pub mod sparse;

pub use sparse::{
    BulkOperationError, BulkOperationResult, SparseKey, SparseMerkleTree, SparseNode,
    SparseTreeStatistics, TreeConsistencyReport, TreeRepairResult,
};

pub use patricia::{NibblePath, NodeRef, PatriciaNode, PatriciaTrie, TrieIterator};

pub use factory::{TreeFactory, UnifiedTree};

use crate::error::{Result, SylvaError};
use crate::hash::HashDigest;
use crate::ledger::LedgerEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

/// Enumeration of supported tree types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TreeType {
    /// Binary Merkle Tree - balanced tree for ledger entries
    Binary,
    /// Sparse Merkle Tree - efficient for large key spaces
    Sparse,
    /// Patricia Trie - Ethereum-compatible compressed trie
    Patricia,
}

impl TreeType {
    /// Get all supported tree types
    pub fn all() -> &'static [TreeType] {
        &[TreeType::Binary, TreeType::Sparse, TreeType::Patricia]
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            TreeType::Binary => "binary",
            TreeType::Sparse => "sparse",
            TreeType::Patricia => "patricia",
        }
    }

    /// Check if this tree type is compatible with another for migration
    pub fn is_compatible_with(&self, other: &TreeType) -> bool {
        match (self, other) {
            // All can convert to binary (via ledger entries)
            (_, TreeType::Binary) => true,
            // Binary can convert to sparse (via key-value pairs)
            (TreeType::Binary, TreeType::Sparse) => true,
            // Sparse can convert to patricia (both are key-value stores)
            (TreeType::Sparse, TreeType::Patricia) => true,
            // Patricia can convert to sparse (both are key-value stores)
            (TreeType::Patricia, TreeType::Sparse) => true,
            // Same type is always compatible
            (a, b) if a == b => true,
            // Other combinations require intermediate conversions
            _ => false,
        }
    }

    /// Get the data model used by this tree type
    pub fn data_model(&self) -> TreeDataModel {
        match self {
            TreeType::Binary => TreeDataModel::LedgerEntries,
            TreeType::Sparse => TreeDataModel::KeyValue,
            TreeType::Patricia => TreeDataModel::KeyValue,
        }
    }
}

impl FromStr for TreeType {
    type Err = SylvaError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "binary" => Ok(TreeType::Binary),
            "sparse" => Ok(TreeType::Sparse),
            "patricia" => Ok(TreeType::Patricia),
            _ => Err(SylvaError::InvalidInput {
                message: format!(
                    "Unknown tree type: {}. Supported types: binary, sparse, patricia",
                    s
                ),
            }),
        }
    }
}

/// Data model used by different tree types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeDataModel {
    /// Stores ledger entries with versioning
    LedgerEntries,
    /// Stores raw key-value pairs
    KeyValue,
}

/// Tree metadata for type detection and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeMetadata {
    /// Type of tree
    pub tree_type: TreeType,
    /// Version of the tree format
    pub format_version: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modification timestamp
    pub modified_at: u64,
    /// Tree-specific configuration
    pub config: HashMap<String, String>,
    /// Entry count
    pub entry_count: usize,
    /// Root hash if available
    pub root_hash: Option<HashDigest>,
}

impl TreeMetadata {
    /// Create new metadata for a tree type
    pub fn new(tree_type: TreeType) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            tree_type,
            format_version: 1,
            created_at: now,
            modified_at: now,
            config: HashMap::new(),
            entry_count: 0,
            root_hash: None,
        }
    }

    /// Update modification time
    pub fn touch(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};

        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Set configuration value
    pub fn set_config(&mut self, key: &str, value: &str) {
        self.config.insert(key.to_string(), value.to_string());
        self.touch();
    }

    /// Get configuration value
    pub fn get_config(&self, key: &str) -> Option<&String> {
        self.config.get(key)
    }

    /// Update entry count and root hash
    pub fn update_stats(&mut self, entry_count: usize, root_hash: Option<HashDigest>) {
        self.entry_count = entry_count;
        self.root_hash = root_hash;
        self.touch();
    }

    /// Get a unique identifier for this tree metadata
    pub fn tree_id(&self) -> String {
        format!(
            "{}_{}_v{}",
            self.tree_type.as_str(),
            self.created_at,
            self.format_version
        )
    }

    /// Check if this metadata is compatible with a tree type
    pub fn is_compatible_with_type(&self, tree_type: TreeType) -> bool {
        self.tree_type == tree_type || self.tree_type.is_compatible_with(&tree_type)
    }

    /// Create a detection fingerprint for this tree
    pub fn detection_fingerprint(&self) -> TreeDetectionFingerprint {
        TreeDetectionFingerprint {
            tree_type: self.tree_type,
            format_version: self.format_version,
            entry_count: self.entry_count,
            has_root_hash: self.root_hash.is_some(),
            config_keys: self.config.keys().cloned().collect(),
            age_days: self.age_days(),
        }
    }

    /// Get the age of this tree in days
    pub fn age_days(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        (now.saturating_sub(self.created_at)) / (24 * 60 * 60)
    }
}

/// Tree detection fingerprint for identifying tree types from stored data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeDetectionFingerprint {
    /// Detected tree type
    pub tree_type: TreeType,
    /// Format version
    pub format_version: u32,
    /// Number of entries
    pub entry_count: usize,
    /// Whether tree has a root hash
    pub has_root_hash: bool,
    /// Configuration keys present
    pub config_keys: Vec<String>,
    /// Age in days since creation
    pub age_days: u64,
}

impl TreeDetectionFingerprint {
    /// Calculate confidence score for tree type detection (0.0 to 1.0)
    pub fn confidence_score(&self) -> f64 {
        let mut score: f64 = 0.5; // Base confidence

        // Higher confidence for trees with more entries
        if self.entry_count > 100 {
            score += 0.2;
        } else if self.entry_count > 10 {
            score += 0.1;
        }

        // Higher confidence if tree has root hash
        if self.has_root_hash {
            score += 0.1;
        }

        // Higher confidence for trees with specific config keys
        if self.config_keys.contains(&"tree_type_verified".to_string()) {
            score += 0.3;
        }

        if self.config_keys.contains(&"workspace".to_string()) {
            score += 0.1;
        }

        // Slightly lower confidence for very old trees (format may have changed)
        if self.age_days > 365 {
            score -= 0.1;
        }

        score.clamp(0.0, 1.0)
    }

    /// Check if this fingerprint suggests the tree is likely the given type
    pub fn suggests_type(&self, tree_type: TreeType) -> bool {
        self.tree_type == tree_type && self.confidence_score() > 0.6
    }
}

/// Tree type detector for analyzing stored tree data
#[derive(Debug)]
pub struct TreeTypeDetector {
    /// Minimum confidence threshold for detection
    confidence_threshold: f64,
}

impl TreeTypeDetector {
    /// Create a new tree type detector
    pub fn new() -> Self {
        Self {
            confidence_threshold: 0.7,
        }
    }

    /// Create a detector with custom confidence threshold
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            confidence_threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Detect tree type from metadata
    pub fn detect_from_metadata(&self, metadata: &TreeMetadata) -> TreeDetectionResult {
        let fingerprint = metadata.detection_fingerprint();
        let confidence = fingerprint.confidence_score();

        TreeDetectionResult {
            detected_type: Some(fingerprint.tree_type),
            confidence,
            fingerprint,
            is_reliable: confidence >= self.confidence_threshold,
        }
    }

    /// Detect tree type from stored tree file
    pub fn detect_from_file(&self, file_path: &std::path::Path) -> Result<TreeDetectionResult> {
        use std::fs;

        if !file_path.exists() {
            return Ok(TreeDetectionResult::no_detection());
        }

        // Try to read and parse tree metadata
        let data = fs::read(file_path)?;

        // Try to deserialize as TreeExportData first
        if let Ok(export_data) = bincode::deserialize::<TreeExportData>(&data) {
            let fingerprint = export_data.metadata.detection_fingerprint();
            let confidence = fingerprint.confidence_score() + 0.1; // Bonus for valid export format

            return Ok(TreeDetectionResult {
                detected_type: Some(export_data.source_tree_type),
                confidence,
                fingerprint,
                is_reliable: confidence >= self.confidence_threshold,
            });
        }

        // Try to parse filename for tree type hints
        if let Some(filename) = file_path.file_name() {
            if let Some(filename_str) = filename.to_str() {
                for tree_type in TreeType::all() {
                    if filename_str.contains(tree_type.as_str()) {
                        // Low confidence detection from filename only
                        let fingerprint = TreeDetectionFingerprint {
                            tree_type: *tree_type,
                            format_version: 1,
                            entry_count: 0,
                            has_root_hash: false,
                            config_keys: vec![],
                            age_days: 0,
                        };

                        return Ok(TreeDetectionResult {
                            detected_type: Some(*tree_type),
                            confidence: 0.3, // Low confidence from filename only
                            fingerprint,
                            is_reliable: false,
                        });
                    }
                }
            }
        }

        Ok(TreeDetectionResult::no_detection())
    }

    /// Detect tree type from workspace configuration
    pub fn detect_from_workspace(
        &self,
        workspace_path: &std::path::Path,
    ) -> Result<TreeDetectionResult> {
        let config_path = workspace_path.join(".sylva").join("config.json");

        if !config_path.exists() {
            return Ok(TreeDetectionResult::no_detection());
        }

        let config_data = std::fs::read_to_string(&config_path)?;
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_data) {
            if let Some(default_tree_type) = config.get("default_tree_type") {
                if let Some(type_str) = default_tree_type.as_str() {
                    if let Ok(tree_type) = type_str.parse::<TreeType>() {
                        let fingerprint = TreeDetectionFingerprint {
                            tree_type,
                            format_version: 1,
                            entry_count: 0,
                            has_root_hash: false,
                            config_keys: vec!["default_tree_type".to_string()],
                            age_days: 0,
                        };

                        return Ok(TreeDetectionResult {
                            detected_type: Some(tree_type),
                            confidence: 0.8, // High confidence from explicit config
                            fingerprint,
                            is_reliable: true,
                        });
                    }
                }
            }
        }

        Ok(TreeDetectionResult::no_detection())
    }
}

impl Default for TreeTypeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of tree type detection
#[derive(Debug, Clone)]
pub struct TreeDetectionResult {
    /// Detected tree type (if any)
    pub detected_type: Option<TreeType>,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Detection fingerprint
    pub fingerprint: TreeDetectionFingerprint,
    /// Whether the detection is considered reliable
    pub is_reliable: bool,
}

impl TreeDetectionResult {
    /// Create a result indicating no detection was possible
    pub fn no_detection() -> Self {
        Self {
            detected_type: None,
            confidence: 0.0,
            fingerprint: TreeDetectionFingerprint {
                tree_type: TreeType::Binary, // Default fallback
                format_version: 1,
                entry_count: 0,
                has_root_hash: false,
                config_keys: vec![],
                age_days: 0,
            },
            is_reliable: false,
        }
    }

    /// Check if detection found a specific tree type
    pub fn detected(&self, tree_type: TreeType) -> bool {
        self.detected_type == Some(tree_type) && self.is_reliable
    }

    /// Get the detected type or a fallback
    pub fn tree_type_or_default(&self, default: TreeType) -> TreeType {
        if self.is_reliable {
            self.detected_type.unwrap_or(default)
        } else {
            default
        }
    }
}

/// Core trait for versioned tree data structures
pub trait Tree {
    /// Insert a ledger entry into the tree
    fn insert(&mut self, entry: LedgerEntry) -> Result<()>;

    /// Insert multiple ledger entries into the tree
    fn insert_batch(&mut self, entries: Vec<LedgerEntry>) -> Result<()>;

    /// Get the root hash of the tree
    fn root_hash(&self) -> Option<HashDigest>;

    /// Get the height of the tree
    fn height(&self) -> usize;

    /// Get the number of entries in the tree
    fn entry_count(&self) -> usize;

    /// Check if the tree is empty
    fn is_empty(&self) -> bool;

    /// Get the latest version in the tree
    fn latest_version(&self) -> u64;

    /// Get all entries in the tree
    fn get_entries(&self) -> Vec<&LedgerEntry>;

    /// Get entries by version
    fn get_entries_by_version(&self, version: u64) -> Vec<&LedgerEntry>;

    /// Find entry by ID
    fn find_entry(&self, id: &Uuid) -> Option<&LedgerEntry>;

    /// Generate a proof for an entry
    fn generate_proof(&self, id: &Uuid) -> Result<Option<MerkleProof>>;

    /// Verify a proof for an entry
    fn verify_proof(&self, proof: &MerkleProof, entry: &LedgerEntry) -> Result<bool>;

    /// Clear all entries from the tree
    fn clear(&mut self);

    /// Get the tree type
    fn tree_type(&self) -> TreeType;

    /// Get tree metadata
    fn metadata(&self) -> &TreeMetadata;

    /// Get mutable tree metadata
    fn metadata_mut(&mut self) -> &mut TreeMetadata;

    /// Export tree data for migration
    fn export_data(&self) -> Result<TreeExportData>;

    /// Import tree data from migration
    fn import_data(&mut self, data: TreeExportData) -> Result<()>;

    /// Validate tree structure integrity
    fn validate_structure(&self) -> Result<bool>;

    /// Get memory usage statistics
    fn memory_usage(&self) -> TreeMemoryUsage;
}

/// Trait for versioned tree operations
pub trait VersionedTree: Tree {
    /// Get entries since a specific version
    fn get_entries_since_version(&self, version: u64) -> Vec<&LedgerEntry>;

    /// Get entries between two versions (inclusive)
    fn get_entries_between_versions(
        &self,
        start_version: u64,
        end_version: u64,
    ) -> Vec<&LedgerEntry>;

    /// Get the version range of the tree
    fn version_range(&self) -> Option<(u64, u64)>;

    /// Create a snapshot of the tree at a specific version
    fn snapshot_at_version(&self, version: u64) -> Result<TreeSnapshot>;

    /// Restore tree from a snapshot
    fn restore_from_snapshot(&mut self, snapshot: TreeSnapshot) -> Result<()>;

    /// Get tree-specific statistics
    fn tree_statistics(&self) -> TreeStatistics;
}

/// Proof structure for Merkle tree verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub entry_id: Uuid,
    pub entry_hash: HashDigest,
    pub path: Vec<ProofElement>,
    pub root_hash: HashDigest,
}

/// Element in a Merkle proof path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofElement {
    pub hash: HashDigest,
    pub is_left: bool,
}

/// Snapshot of a tree at a specific version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub version: u64,
    pub entries: Vec<LedgerEntry>,
    pub root_hash: Option<HashDigest>,
    pub timestamp: u64,
}

impl MerkleProof {
    pub fn new(
        entry_id: Uuid,
        entry_hash: HashDigest,
        path: Vec<ProofElement>,
        root_hash: HashDigest,
    ) -> Self {
        Self {
            entry_id,
            entry_hash,
            path,
            root_hash,
        }
    }

    pub fn verify(&self, entry: &LedgerEntry) -> Result<bool> {
        use crate::hash::{Blake3Hasher, Hash};
        use crate::tree::node::TreeNode;

        if entry.id != self.entry_id {
            return Ok(false);
        }

        let hasher = Blake3Hasher::new();

        // Calculate the expected leaf hash using the same method as tree nodes
        let expected_leaf_hash = TreeNode::calculate_leaf_hash(&hasher, entry)?;
        if expected_leaf_hash != self.entry_hash {
            return Ok(false);
        }

        let mut current_hash = self.entry_hash.clone();

        for element in &self.path {
            let combined = if element.is_left {
                hasher.hash_pair(&element.hash, &current_hash)?
            } else {
                hasher.hash_pair(&current_hash, &element.hash)?
            };
            current_hash = combined;
        }

        Ok(current_hash == self.root_hash)
    }
}

impl ProofElement {
    pub fn new(hash: HashDigest, is_left: bool) -> Self {
        Self { hash, is_left }
    }
}

impl TreeSnapshot {
    pub fn new(version: u64, entries: Vec<LedgerEntry>, root_hash: Option<HashDigest>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            version,
            entries,
            root_hash,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Export data for tree migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeExportData {
    /// Source tree type
    pub source_tree_type: TreeType,
    /// Target tree type
    pub target_tree_type: TreeType,
    /// Ledger entries (for binary trees)
    pub ledger_entries: Vec<LedgerEntry>,
    /// Key-value pairs (for sparse/patricia trees)
    pub key_value_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    /// Export timestamp
    pub exported_at: u64,
    /// Metadata
    pub metadata: TreeMetadata,
}

impl TreeExportData {
    /// Create export data from ledger entries
    pub fn from_ledger_entries(
        source_type: TreeType,
        target_type: TreeType,
        entries: Vec<LedgerEntry>,
        metadata: TreeMetadata,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            source_tree_type: source_type,
            target_tree_type: target_type,
            ledger_entries: entries,
            key_value_pairs: Vec::new(),
            exported_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata,
        }
    }

    /// Create export data from key-value pairs
    pub fn from_key_value_pairs(
        source_type: TreeType,
        target_type: TreeType,
        pairs: Vec<(Vec<u8>, Vec<u8>)>,
        metadata: TreeMetadata,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            source_tree_type: source_type,
            target_tree_type: target_type,
            ledger_entries: Vec::new(),
            key_value_pairs: pairs,
            exported_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata,
        }
    }

    /// Check if export data is compatible with target tree type
    pub fn is_compatible_with(&self, target_type: TreeType) -> bool {
        self.target_tree_type == target_type
            && self.source_tree_type.is_compatible_with(&target_type)
    }
}

/// Memory usage statistics for trees
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMemoryUsage {
    /// Total memory used by tree structure
    pub total_bytes: usize,
    /// Memory used by data storage
    pub data_bytes: usize,
    /// Memory used by metadata
    pub metadata_bytes: usize,
    /// Memory used by tree structure (nodes, indices)
    pub structure_bytes: usize,
}

impl TreeMemoryUsage {
    pub fn new(total: usize, data: usize, metadata: usize, structure: usize) -> Self {
        Self {
            total_bytes: total,
            data_bytes: data,
            metadata_bytes: metadata,
            structure_bytes: structure,
        }
    }

    /// Get memory efficiency ratio (data / total)
    pub fn efficiency(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            self.data_bytes as f64 / self.total_bytes as f64
        }
    }
}

/// Tree-specific statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeStatistics {
    /// Tree type
    pub tree_type: TreeType,
    /// Number of entries
    pub entry_count: usize,
    /// Tree height/depth
    pub height: usize,
    /// Memory usage
    pub memory_usage: TreeMemoryUsage,
    /// Tree-specific metrics
    pub metrics: HashMap<String, String>,
}

impl TreeStatistics {
    pub fn new(
        tree_type: TreeType,
        entry_count: usize,
        height: usize,
        memory_usage: TreeMemoryUsage,
    ) -> Self {
        Self {
            tree_type,
            entry_count,
            height,
            memory_usage,
            metrics: HashMap::new(),
        }
    }

    /// Add a metric
    pub fn add_metric(&mut self, key: &str, value: &str) {
        self.metrics.insert(key.to_string(), value.to_string());
    }

    /// Get a metric
    pub fn get_metric(&self, key: &str) -> Option<&String> {
        self.metrics.get(key)
    }
}

/// Utility functions for tree operations
pub mod utils {

    /// Calculate the next power of 2 for a given number
    pub fn next_power_of_2(n: usize) -> usize {
        if n == 0 {
            return 1;
        }
        let mut power = 1;
        while power < n {
            power *= 2;
        }
        power
    }

    /// Calculate the height of a binary tree with n leaves
    pub fn tree_height(leaf_count: usize) -> usize {
        if leaf_count == 0 {
            return 0;
        }
        (leaf_count as f64).log2().ceil() as usize
    }

    /// Check if a number is a power of 2
    pub fn is_power_of_2(n: usize) -> bool {
        n > 0 && (n & (n - 1)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake3Hasher;

    #[test]
    fn test_merkle_proof_verification() {
        use crate::hash::Hash as HashTrait;
        use crate::tree::node::TreeNode;

        let hasher = Blake3Hasher::new();
        let entry = LedgerEntry::new(b"test data".to_vec(), 1);
        let entry_hash = TreeNode::calculate_leaf_hash(&hasher, &entry).unwrap();

        let path = vec![ProofElement::new(
            hasher.hash_bytes(b"sibling").unwrap(),
            true,
        )];

        let root_hash = hasher
            .hash_pair(&hasher.hash_bytes(b"sibling").unwrap(), &entry_hash)
            .unwrap();

        let proof = MerkleProof::new(entry.id, entry_hash, path, root_hash);
        assert!(proof.verify(&entry).unwrap());
    }

    #[test]
    fn test_tree_snapshot() {
        let entries = vec![
            LedgerEntry::new(b"data1".to_vec(), 1),
            LedgerEntry::new(b"data2".to_vec(), 2),
        ];

        let snapshot = TreeSnapshot::new(2, entries.clone(), None);
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.entry_count(), 2);
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.entries.len(), 2);
    }

    #[test]
    fn test_utils_next_power_of_2() {
        assert_eq!(utils::next_power_of_2(0), 1);
        assert_eq!(utils::next_power_of_2(1), 1);
        assert_eq!(utils::next_power_of_2(2), 2);
        assert_eq!(utils::next_power_of_2(3), 4);
        assert_eq!(utils::next_power_of_2(5), 8);
        assert_eq!(utils::next_power_of_2(8), 8);
    }

    #[test]
    fn test_utils_tree_height() {
        assert_eq!(utils::tree_height(0), 0);
        assert_eq!(utils::tree_height(1), 0);
        assert_eq!(utils::tree_height(2), 1);
        assert_eq!(utils::tree_height(3), 2);
        assert_eq!(utils::tree_height(4), 2);
        assert_eq!(utils::tree_height(5), 3);
        assert_eq!(utils::tree_height(8), 3);
    }

    #[test]
    fn test_utils_is_power_of_2() {
        assert!(!utils::is_power_of_2(0));
        assert!(utils::is_power_of_2(1));
        assert!(utils::is_power_of_2(2));
        assert!(!utils::is_power_of_2(3));
        assert!(utils::is_power_of_2(4));
        assert!(!utils::is_power_of_2(5));
        assert!(utils::is_power_of_2(8));
    }
}
