//! Sparse Merkle Tree implementation for efficient key-value storage
//!
//! A sparse Merkle tree is a variant of a Merkle tree that can efficiently handle
//! large key spaces by only storing non-empty nodes. Empty subtrees are represented
//! by predetermined default hash values at each level.
//!
//! Key features:
//! - Memory usage proportional to data, not key space size
//! - Efficient proofs for both inclusion and non-inclusion
//! - Support for 256-bit keys (full SHA-256 hash space)
//! - Lazy node creation for optimal memory usage

use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash, HashDigest};
use crate::ledger::LedgerEntry;
use crate::tree::{
    MerkleProof, ProofElement, TreeExportData, TreeMemoryUsage, TreeMetadata, TreeStatistics,
    TreeType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Height of the sparse Merkle tree (256 levels for 256-bit keys)
pub const SPARSE_TREE_HEIGHT: usize = 256;

/// A 256-bit key for the sparse Merkle tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SparseKey([u8; 32]);

impl SparseKey {
    /// Create a new sparse key from a 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a sparse key from a slice (pads with zeros if shorter)
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let len = slice.len().min(32);
        bytes[..len].copy_from_slice(&slice[..len]);
        Self(bytes)
    }

    /// Get the byte at a specific index
    pub fn byte(&self, index: usize) -> u8 {
        if index < 32 {
            self.0[index]
        } else {
            0
        }
    }

    /// Get the bit at a specific position (0-255)
    pub fn bit(&self, position: usize) -> bool {
        if position >= 256 {
            return false;
        }
        let byte_index = position / 8;
        let bit_index = position % 8;
        (self.0[byte_index] >> (7 - bit_index)) & 1 == 1
    }

    /// Get a slice of bits from the key (used for tree traversal)
    pub fn prefix(&self, depth: usize) -> u64 {
        if depth == 0 {
            return 0;
        }

        let mut prefix = 0u64;
        for i in 0..depth.min(64) {
            if self.bit(i) {
                prefix |= 1u64 << (63 - i);
            }
        }
        prefix >> (64 - depth.min(64))
    }

    /// Convert to bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a key from a string hash
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(SylvaError::InvalidInput {
                message: "Hex string must be exactly 64 characters for 256-bit key".to_string(),
            });
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let hex_byte = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(hex_byte, 16).map_err(|_| SylvaError::InvalidInput {
                message: format!("Invalid hex character in key: {}", hex_byte),
            })?;
        }

        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Node in the sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SparseNode {
    /// Leaf node containing a value
    Leaf {
        key: SparseKey,
        value: Vec<u8>,
        hash: HashDigest,
    },
    /// Internal node with children
    Internal {
        left_hash: HashDigest,
        right_hash: HashDigest,
        hash: HashDigest,
    },
    /// Empty node (represented by default hash)
    Empty,
}

impl SparseNode {
    /// Get the hash of this node
    pub fn hash(&self) -> &HashDigest {
        match self {
            SparseNode::Leaf { hash, .. } => hash,
            SparseNode::Internal { hash, .. } => hash,
            SparseNode::Empty => &EMPTY_HASHES[0], // Default empty hash
        }
    }

    /// Check if this node is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, SparseNode::Empty)
    }

    /// Check if this node is a leaf
    pub fn is_leaf(&self) -> bool {
        matches!(self, SparseNode::Leaf { .. })
    }
}

lazy_static::lazy_static! {
    /// Pre-computed default hashes for empty subtrees at each level
    /// Level 0 is leaf level, level 255 is root level
    static ref EMPTY_HASHES: Vec<HashDigest> = {
        let mut hashes = Vec::with_capacity(SPARSE_TREE_HEIGHT + 1);
        let hasher = Blake3Hasher::new();

        // Level 0: Empty leaf hash
        hashes.push(hasher.hash_bytes(b"").unwrap());

        // Each subsequent level: hash of two empty subtrees from previous level
        for i in 1..=SPARSE_TREE_HEIGHT {
            let prev_hash = &hashes[i - 1];
            hashes.push(hasher.hash_pair(prev_hash, prev_hash).unwrap());
        }

        hashes
    };
}

/// Sparse Merkle Tree for efficient key-value storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    /// Only stores non-empty nodes
    nodes: HashMap<(usize, SparseKey), SparseNode>,
    /// Root hash of the tree
    root_hash: HashDigest,
    /// Number of key-value pairs stored
    entry_count: usize,
    /// Height of the tree (always 256 for sparse trees)
    height: usize,
    /// Tree metadata
    metadata: TreeMetadata,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create a new empty sparse Merkle tree
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_hash: EMPTY_HASHES[SPARSE_TREE_HEIGHT].clone(),
            entry_count: 0,
            height: SPARSE_TREE_HEIGHT,
            metadata: TreeMetadata::new(TreeType::Sparse),
        }
    }

    /// Insert a new key-value pair (fails if key already exists)
    pub fn insert(&mut self, key: SparseKey, value: Vec<u8>) -> Result<()> {
        if self.contains_key(&key) {
            return Err(SylvaError::InvalidInput {
                message: format!(
                    "Key {} already exists. Use update() to modify existing keys.",
                    key.to_hex()
                ),
            });
        }

        self.insert_or_update_internal(key, value, true)
    }

    /// Update an existing key-value pair (fails if key doesn't exist)
    pub fn update(&mut self, key: SparseKey, value: Vec<u8>) -> Result<Vec<u8>> {
        if !self.contains_key(&key) {
            return Err(SylvaError::InvalidInput {
                message: format!(
                    "Key {} does not exist. Use insert() to add new keys.",
                    key.to_hex()
                ),
            });
        }

        // Get the old value before updating
        let old_value = self.get(&key).unwrap().to_vec();

        self.insert_or_update_internal(key, value, false)?;
        Ok(old_value)
    }

    /// Insert or update a key-value pair (upsert operation)
    pub fn upsert(&mut self, key: SparseKey, value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let old_value = self.get(&key).map(|v| v.to_vec());
        let is_new_key = old_value.is_none();

        self.insert_or_update_internal(key, value, is_new_key)?;
        Ok(old_value)
    }

    /// Internal method for insert/update operations
    fn insert_or_update_internal(
        &mut self,
        key: SparseKey,
        value: Vec<u8>,
        is_new_key: bool,
    ) -> Result<()> {
        // Validate input
        if value.is_empty() {
            return Err(SylvaError::InvalidInput {
                message: "Value cannot be empty. Use delete() to remove keys.".to_string(),
            });
        }

        let hasher = Blake3Hasher::new();

        // Create leaf node
        let key_bytes = key.as_bytes();
        let leaf_data = [key_bytes.as_slice(), &value].concat();
        let leaf_hash = hasher.hash_bytes(&leaf_data)?;

        let leaf_node = SparseNode::Leaf {
            key,
            value,
            hash: leaf_hash.clone(),
        };

        // Update entry count for new keys
        if is_new_key {
            self.entry_count += 1;
        }

        // Insert the leaf node
        self.nodes.insert((0, key), leaf_node);

        // Update the tree from leaf to root
        self.update_path_to_root(key, &hasher)?;

        Ok(())
    }

    /// Get the value for a key
    pub fn get(&self, key: &SparseKey) -> Option<&[u8]> {
        match self.nodes.get(&(0, *key)) {
            Some(SparseNode::Leaf { value, .. }) => Some(value),
            _ => None,
        }
    }

    /// Check if a key exists in the tree
    pub fn contains_key(&self, key: &SparseKey) -> bool {
        self.nodes.contains_key(&(0, *key))
    }

    /// Delete a key-value pair (alias for remove for CRUD consistency)
    pub fn delete(&mut self, key: &SparseKey) -> Result<Vec<u8>> {
        match self.remove(key)? {
            Some(value) => Ok(value),
            None => Err(SylvaError::InvalidInput {
                message: format!("Key {} does not exist", key.to_hex()),
            }),
        }
    }

    /// Remove a key-value pair (returns None if key doesn't exist)
    pub fn remove(&mut self, key: &SparseKey) -> Result<Option<Vec<u8>>> {
        let hasher = Blake3Hasher::new();

        // Get the current value if it exists
        let old_value = match self.nodes.remove(&(0, *key)) {
            Some(SparseNode::Leaf { value, .. }) => {
                self.entry_count -= 1;
                Some(value)
            }
            _ => return Ok(None),
        };

        // Remove nodes along the path that are no longer needed
        self.cleanup_path_to_root(*key);

        // Update the tree from leaf to root
        self.update_path_to_root(*key, &hasher)?;

        Ok(old_value)
    }

    /// Get value with inclusion/exclusion proof
    pub fn get_with_proof(&self, key: &SparseKey) -> Result<(Option<Vec<u8>>, MerkleProof)> {
        let value = self.get(key).map(|v| v.to_vec());
        let proof = self.generate_proof(key)?;
        Ok((value, proof))
    }

    /// Update the tree along the path from a leaf to the root
    fn update_path_to_root(&mut self, key: SparseKey, hasher: &Blake3Hasher) -> Result<()> {
        // Only update the path that's actually affected by this key
        let mut current_key = key;

        for level in 1..=SPARSE_TREE_HEIGHT {
            let parent_key = self.get_parent_key(current_key, level);
            let (left_key, right_key) = self.get_children_keys(parent_key, level - 1);

            let left_hash = self.get_node_hash(level - 1, left_key);
            let right_hash = self.get_node_hash(level - 1, right_key);

            // Only create internal node if both children aren't empty default hashes
            if left_hash != &EMPTY_HASHES[level - 1] || right_hash != &EMPTY_HASHES[level - 1] {
                // But only if this actually creates a meaningful internal node
                let parent_hash = hasher.hash_pair(left_hash, right_hash)?;

                // Don't store nodes that would just contain the default empty hash
                if parent_hash != EMPTY_HASHES[level] {
                    let internal_node = SparseNode::Internal {
                        left_hash: left_hash.clone(),
                        right_hash: right_hash.clone(),
                        hash: parent_hash,
                    };
                    self.nodes.insert((level, parent_key), internal_node);
                } else {
                    // Remove node that becomes empty
                    self.nodes.remove(&(level, parent_key));
                }
            } else {
                // Remove empty internal node if it exists
                self.nodes.remove(&(level, parent_key));
            }

            current_key = parent_key;
        }

        // Update root hash
        let root_key = SparseKey::new([0u8; 32]); // Root key is always zero
        self.root_hash = self.get_node_hash(SPARSE_TREE_HEIGHT, root_key).clone();

        Ok(())
    }

    /// Clean up empty nodes along the path to root
    fn cleanup_path_to_root(&mut self, key: SparseKey) {
        for level in 1..=SPARSE_TREE_HEIGHT {
            let parent_key = self.get_parent_key(key, level);
            let (left_key, right_key) = self.get_children_keys(parent_key, level - 1);

            let left_hash = self.get_node_hash(level - 1, left_key);
            let right_hash = self.get_node_hash(level - 1, right_key);

            // If both children are empty, remove this internal node
            if left_hash == &EMPTY_HASHES[level - 1] && right_hash == &EMPTY_HASHES[level - 1] {
                self.nodes.remove(&(level, parent_key));
            }
        }
    }

    /// Get the hash for a node at a specific level and key
    fn get_node_hash(&self, level: usize, key: SparseKey) -> &HashDigest {
        match self.nodes.get(&(level, key)) {
            Some(node) => node.hash(),
            None => &EMPTY_HASHES[level],
        }
    }

    /// Get the parent key for a given key at a specific level
    /// Level 0 = leaf level, level 256 = root level
    fn get_parent_key(&self, key: SparseKey, level: usize) -> SparseKey {
        if level >= SPARSE_TREE_HEIGHT {
            return SparseKey::new([0u8; 32]);
        }

        let mut parent_bytes = *key.as_bytes();

        // For level L, we need to clear all bits from position (256-L) to 255
        let clear_from_bit = SPARSE_TREE_HEIGHT - level;

        for bit_pos in clear_from_bit..256 {
            let byte_index = bit_pos / 8;
            let bit_offset = bit_pos % 8;

            if byte_index < 32 {
                parent_bytes[byte_index] &= !(1u8 << (7 - bit_offset));
            }
        }

        SparseKey::new(parent_bytes)
    }

    /// Get the left and right child keys for a parent at a specific level
    fn get_children_keys(
        &self,
        parent_key: SparseKey,
        child_level: usize,
    ) -> (SparseKey, SparseKey) {
        if child_level >= SPARSE_TREE_HEIGHT {
            return (parent_key, parent_key);
        }

        // The bit that differentiates left from right at this level
        let bit_index = SPARSE_TREE_HEIGHT - child_level - 1;
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;

        let mut left_bytes = *parent_key.as_bytes();
        let mut right_bytes = *parent_key.as_bytes();

        if byte_index < 32 {
            // Left child: clear the bit (0)
            left_bytes[byte_index] &= !(1u8 << (7 - bit_offset));
            // Right child: set the bit (1)
            right_bytes[byte_index] |= 1u8 << (7 - bit_offset);
        }

        (SparseKey::new(left_bytes), SparseKey::new(right_bytes))
    }

    /// Generate an inclusion or exclusion proof for a key
    pub fn generate_proof(&self, key: &SparseKey) -> Result<MerkleProof> {
        let mut path = Vec::new();
        let _hasher = Blake3Hasher::new();

        // Build proof path from leaf to root
        for level in 0..SPARSE_TREE_HEIGHT {
            let current_key = if level == 0 {
                *key
            } else {
                self.get_parent_key(*key, level)
            };

            let parent_key = self.get_parent_key(*key, level + 1);
            let (left_key, right_key) = self.get_children_keys(parent_key, level);

            // Determine if current node is left or right child
            let is_left_child = current_key == left_key;
            let sibling_key = if is_left_child { right_key } else { left_key };
            let sibling_hash = self.get_node_hash(level, sibling_key);

            path.push(ProofElement::new(sibling_hash.clone(), !is_left_child));
        }

        // Get the leaf hash
        let leaf_hash = match self.nodes.get(&(0, *key)) {
            Some(SparseNode::Leaf { hash, .. }) => hash.clone(),
            _ => {
                // For non-inclusion proof, use empty leaf hash
                EMPTY_HASHES[0].clone()
            }
        };

        Ok(MerkleProof::new(
            uuid::Uuid::new_v4(), // Sparse trees don't use UUIDs, but required by interface
            leaf_hash,
            path,
            self.root_hash.clone(),
        ))
    }

    /// Verify a proof for a key-value pair
    pub fn verify_proof(
        &self,
        proof: &MerkleProof,
        key: &SparseKey,
        value: Option<&[u8]>,
    ) -> Result<bool> {
        let hasher = Blake3Hasher::new();

        // Calculate expected leaf hash
        let expected_leaf_hash = match value {
            Some(v) => {
                let key_bytes = key.as_bytes();
                let leaf_data = [key_bytes.as_slice(), v].concat();
                hasher.hash_bytes(&leaf_data)?
            }
            None => EMPTY_HASHES[0].clone(),
        };

        if proof.entry_hash != expected_leaf_hash {
            return Ok(false);
        }

        // Verify the path
        let mut current_hash = proof.entry_hash.clone();
        for element in &proof.path {
            current_hash = if element.is_left {
                hasher.hash_pair(&element.hash, &current_hash)?
            } else {
                hasher.hash_pair(&current_hash, &element.hash)?
            };
        }

        Ok(current_hash == proof.root_hash && proof.root_hash == self.root_hash)
    }

    /// Verify a sparse proof using the key-value pair directly
    pub fn verify_sparse_proof(&self, key: &SparseKey, value: Option<&[u8]>) -> Result<bool> {
        let proof = self.generate_proof(key)?;
        self.verify_proof(&proof, key, value)
    }

    /// Get the root hash of the tree
    pub fn root_hash(&self) -> &HashDigest {
        &self.root_hash
    }

    /// Get the number of key-value pairs in the tree
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Get the height of the tree (always 256 for sparse trees)
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get the number of nodes actually stored (non-empty nodes only)
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get all keys in the tree
    pub fn keys(&self) -> Vec<SparseKey> {
        self.nodes
            .iter()
            .filter_map(|((level, key), node)| {
                if *level == 0 && node.is_leaf() {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all key-value pairs in the tree
    pub fn entries(&self) -> Vec<(SparseKey, Vec<u8>)> {
        self.nodes
            .iter()
            .filter_map(|((level, key), node)| {
                if *level == 0 {
                    if let SparseNode::Leaf { value, .. } = node {
                        Some((*key, value.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Clear all entries from the tree
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.root_hash = EMPTY_HASHES[SPARSE_TREE_HEIGHT].clone();
        self.entry_count = 0;
        self.metadata.update_stats(0, Some(self.root_hash.clone()));
    }

    /// Build a sparse tree efficiently from a collection of key-value pairs
    pub fn from_entries<I>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (SparseKey, Vec<u8>)>,
    {
        let mut tree = Self::new();
        tree.bulk_insert(entries)?;
        Ok(tree)
    }

    /// Bulk insert multiple key-value pairs
    pub fn bulk_insert<I>(&mut self, entries: I) -> Result<BulkOperationResult>
    where
        I: IntoIterator<Item = (SparseKey, Vec<u8>)>,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut result = BulkOperationResult::new();

        // Validate all entries first
        for (key, value) in &entries {
            if value.is_empty() {
                result.errors.push(BulkOperationError {
                    key: *key,
                    operation: "insert".to_string(),
                    error: "Value cannot be empty".to_string(),
                });
                continue;
            }

            if self.contains_key(key) {
                result.errors.push(BulkOperationError {
                    key: *key,
                    operation: "insert".to_string(),
                    error: "Key already exists".to_string(),
                });
                continue;
            }

            result.processed_keys.push(*key);
        }

        // If there are validation errors, return them without modifying the tree
        if !result.errors.is_empty() {
            return Ok(result);
        }

        // Process all valid entries
        for (key, value) in entries {
            if let Err(e) = self.insert_or_update_internal(key, value, true) {
                result.errors.push(BulkOperationError {
                    key,
                    operation: "insert".to_string(),
                    error: e.to_string(),
                });
                result.processed_keys.retain(|&k| k != key);
            } else {
                result.successful_operations += 1;
            }
        }

        Ok(result)
    }

    /// Bulk update multiple key-value pairs
    pub fn bulk_update<I>(&mut self, entries: I) -> Result<BulkOperationResult>
    where
        I: IntoIterator<Item = (SparseKey, Vec<u8>)>,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut result = BulkOperationResult::new();

        // Validate all entries first
        for (key, value) in &entries {
            if value.is_empty() {
                result.errors.push(BulkOperationError {
                    key: *key,
                    operation: "update".to_string(),
                    error: "Value cannot be empty".to_string(),
                });
                continue;
            }

            if !self.contains_key(key) {
                result.errors.push(BulkOperationError {
                    key: *key,
                    operation: "update".to_string(),
                    error: "Key does not exist".to_string(),
                });
                continue;
            }

            result.processed_keys.push(*key);
        }

        // Process valid entries
        for (key, value) in entries {
            if result.processed_keys.contains(&key) {
                if let Err(e) = self.insert_or_update_internal(key, value, false) {
                    result.errors.push(BulkOperationError {
                        key,
                        operation: "update".to_string(),
                        error: e.to_string(),
                    });
                } else {
                    result.successful_operations += 1;
                }
            }
        }

        Ok(result)
    }

    /// Bulk upsert multiple key-value pairs
    pub fn bulk_upsert<I>(&mut self, entries: I) -> Result<BulkOperationResult>
    where
        I: IntoIterator<Item = (SparseKey, Vec<u8>)>,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut result = BulkOperationResult::new();

        for (key, value) in entries {
            if value.is_empty() {
                result.errors.push(BulkOperationError {
                    key,
                    operation: "upsert".to_string(),
                    error: "Value cannot be empty".to_string(),
                });
                continue;
            }

            let is_new_key = !self.contains_key(&key);
            if let Err(e) = self.insert_or_update_internal(key, value, is_new_key) {
                result.errors.push(BulkOperationError {
                    key,
                    operation: "upsert".to_string(),
                    error: e.to_string(),
                });
            } else {
                result.successful_operations += 1;
                result.processed_keys.push(key);
            }
        }

        Ok(result)
    }

    /// Bulk delete multiple keys
    pub fn bulk_delete<I>(&mut self, keys: I) -> Result<BulkOperationResult>
    where
        I: IntoIterator<Item = SparseKey>,
    {
        let keys: Vec<_> = keys.into_iter().collect();
        let mut result = BulkOperationResult::new();

        for key in keys {
            if !self.contains_key(&key) {
                result.errors.push(BulkOperationError {
                    key,
                    operation: "delete".to_string(),
                    error: "Key does not exist".to_string(),
                });
                continue;
            }

            if let Err(e) = self.remove(&key) {
                result.errors.push(BulkOperationError {
                    key,
                    operation: "delete".to_string(),
                    error: e.to_string(),
                });
            } else {
                result.successful_operations += 1;
                result.processed_keys.push(key);
            }
        }

        Ok(result)
    }

    /// Get memory efficiency ratio (entries / nodes stored)
    pub fn memory_efficiency(&self) -> f64 {
        if self.nodes.is_empty() {
            1.0
        } else {
            self.entry_count as f64 / self.nodes.len() as f64
        }
    }

    /// Get detailed statistics about the tree
    pub fn statistics(&self) -> SparseTreeStatistics {
        let leaf_nodes = self
            .nodes
            .iter()
            .filter(|((level, _), node)| *level == 0 && node.is_leaf())
            .count();

        let internal_nodes = self
            .nodes
            .iter()
            .filter(|((level, _), node)| *level > 0 && !node.is_leaf())
            .count();

        let memory_usage = std::mem::size_of::<Self>()
            + self.nodes.capacity() * std::mem::size_of::<((usize, SparseKey), SparseNode)>()
            + self
                .nodes
                .values()
                .map(|node| match node {
                    SparseNode::Leaf { value, .. } => value.len(),
                    _ => 0,
                })
                .sum::<usize>();

        SparseTreeStatistics {
            entry_count: self.entry_count,
            leaf_nodes,
            internal_nodes,
            total_nodes: self.nodes.len(),
            height: self.height,
            memory_usage,
            memory_efficiency: self.memory_efficiency(),
        }
    }

    /// Validate tree consistency
    pub fn validate_consistency(&self) -> Result<TreeConsistencyReport> {
        let mut report = TreeConsistencyReport::new();
        let hasher = Blake3Hasher::new();

        // Check entry count consistency
        let actual_leaf_count = self
            .nodes
            .iter()
            .filter(|((level, _), node)| *level == 0 && node.is_leaf())
            .count();

        if actual_leaf_count != self.entry_count {
            report.errors.push(format!(
                "Entry count mismatch: expected {}, found {}",
                self.entry_count, actual_leaf_count
            ));
        }

        // Validate each internal node's hash
        for ((level, key), node) in &self.nodes {
            if *level > 0 {
                if let SparseNode::Internal {
                    left_hash,
                    right_hash,
                    hash,
                } = node
                {
                    let expected_hash = hasher.hash_pair(left_hash, right_hash)?;
                    if *hash != expected_hash {
                        report.errors.push(format!(
                            "Hash mismatch at level {} key {}: expected {:?}, found {:?}",
                            level,
                            key.to_hex(),
                            expected_hash,
                            hash
                        ));
                    }
                }
            }
        }

        // Validate leaf nodes
        for ((level, key), node) in &self.nodes {
            if *level == 0 {
                if let SparseNode::Leaf {
                    key: leaf_key,
                    value,
                    hash,
                } = node
                {
                    if *key != *leaf_key {
                        report.errors.push(format!(
                            "Key mismatch in leaf: map key {}, leaf key {}",
                            key.to_hex(),
                            leaf_key.to_hex()
                        ));
                    }

                    let key_bytes = leaf_key.as_bytes();
                    let leaf_data = [key_bytes.as_slice(), value].concat();
                    let expected_hash = hasher.hash_bytes(&leaf_data)?;
                    if *hash != expected_hash {
                        report.errors.push(format!(
                            "Leaf hash mismatch for key {}: expected {:?}, found {:?}",
                            leaf_key.to_hex(),
                            expected_hash,
                            hash
                        ));
                    }
                }
            }
        }

        // Validate root hash
        let root_key = SparseKey::new([0u8; 32]);
        let expected_root_hash = self.get_node_hash(SPARSE_TREE_HEIGHT, root_key);
        if self.root_hash != *expected_root_hash {
            report.errors.push(format!(
                "Root hash mismatch: expected {:?}, found {:?}",
                expected_root_hash, self.root_hash
            ));
        }

        report.is_consistent = report.errors.is_empty();
        Ok(report)
    }

    /// Perform tree integrity check and attempt repair if needed
    pub fn repair_if_needed(&mut self) -> Result<TreeRepairResult> {
        let mut result = TreeRepairResult::new();
        let report = self.validate_consistency()?;

        if report.is_consistent {
            result.was_consistent = true;
            result.repair_successful = true;
            return Ok(result);
        }

        result.initial_errors = report.errors.clone();

        // Attempt to recalculate all hashes
        let hasher = Blake3Hasher::new();
        let mut repaired_nodes = 0;

        // Recalculate leaf hashes
        for ((level, _key), node) in self.nodes.iter_mut() {
            if *level == 0 {
                if let SparseNode::Leaf {
                    key: leaf_key,
                    value,
                    hash,
                } = node
                {
                    let key_bytes = leaf_key.as_bytes();
                    let leaf_data = [key_bytes.as_slice(), value].concat();
                    let correct_hash = hasher.hash_bytes(&leaf_data)?;
                    if *hash != correct_hash {
                        *hash = correct_hash;
                        repaired_nodes += 1;
                    }
                }
            }
        }

        // Rebuild internal nodes from bottom up
        for level in 1..=SPARSE_TREE_HEIGHT {
            let keys_at_level: Vec<SparseKey> = self
                .nodes
                .iter()
                .filter_map(|((l, k), _)| if *l == level { Some(*k) } else { None })
                .collect();

            for key in keys_at_level {
                let (left_key, right_key) = self.get_children_keys(key, level - 1);
                let left_hash = self.get_node_hash(level - 1, left_key);
                let right_hash = self.get_node_hash(level - 1, right_key);
                let correct_hash = hasher.hash_pair(left_hash, right_hash)?;

                if let Some(SparseNode::Internal { hash, .. }) = self.nodes.get_mut(&(level, key)) {
                    if *hash != correct_hash {
                        *hash = correct_hash;
                        repaired_nodes += 1;
                    }
                }
            }
        }

        // Update root hash
        let root_key = SparseKey::new([0u8; 32]);
        let correct_root_hash = self.get_node_hash(SPARSE_TREE_HEIGHT, root_key).clone();
        if self.root_hash != correct_root_hash {
            self.root_hash = correct_root_hash;
            repaired_nodes += 1;
        }

        result.nodes_repaired = repaired_nodes;
        result.repair_successful = self.validate_consistency()?.is_consistent;

        Ok(result)
    }

    /// Get tree metadata
    pub fn metadata(&self) -> &TreeMetadata {
        &self.metadata
    }

    /// Get mutable tree metadata
    pub fn metadata_mut(&mut self) -> &mut TreeMetadata {
        &mut self.metadata
    }

    /// Get tree statistics
    pub fn tree_statistics(&self) -> TreeStatistics {
        let stats = self.statistics();
        let memory_usage = TreeMemoryUsage::new(
            stats.memory_usage,
            stats.memory_usage / 2, // Rough estimate for data
            std::mem::size_of::<TreeMetadata>(),
            stats.memory_usage / 2, // Rough estimate for structure
        );

        let mut tree_stats = TreeStatistics::new(
            TreeType::Sparse,
            stats.entry_count,
            stats.height,
            memory_usage,
        );

        tree_stats.add_metric("total_nodes", &stats.total_nodes.to_string());
        tree_stats.add_metric("leaf_nodes", &stats.leaf_nodes.to_string());
        tree_stats.add_metric("internal_nodes", &stats.internal_nodes.to_string());
        tree_stats.add_metric(
            "memory_efficiency",
            &format!("{:.2}", stats.memory_efficiency),
        );

        tree_stats
    }
}

/// Tree trait implementation for SparseMerkleTree
impl super::Tree for SparseMerkleTree {
    fn insert(&mut self, entry: LedgerEntry) -> Result<()> {
        // Convert ledger entry to sparse key-value pair
        let key = SparseKey::from_slice(&entry.id.as_bytes()[..]);
        SparseMerkleTree::insert(self, key, entry.data)?;
        self.metadata
            .update_stats(self.entry_count, Some(self.root_hash.clone()));
        Ok(())
    }

    fn insert_batch(&mut self, entries: Vec<LedgerEntry>) -> Result<()> {
        for entry in entries {
            let key = SparseKey::from_slice(&entry.id.as_bytes()[..]);
            SparseMerkleTree::insert(self, key, entry.data)?;
        }
        self.metadata
            .update_stats(self.entry_count, Some(self.root_hash.clone()));
        Ok(())
    }

    fn root_hash(&self) -> Option<HashDigest> {
        Some(self.root_hash.clone())
    }

    fn height(&self) -> usize {
        self.height
    }

    fn entry_count(&self) -> usize {
        self.entry_count
    }

    fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    fn latest_version(&self) -> u64 {
        1 // Sparse trees don't have versions
    }

    fn get_entries(&self) -> Vec<&LedgerEntry> {
        Vec::new() // Sparse trees don't store ledger entries directly
    }

    fn get_entries_by_version(&self, _version: u64) -> Vec<&LedgerEntry> {
        Vec::new() // Sparse trees don't have versions
    }

    fn find_entry(&self, _id: &uuid::Uuid) -> Option<&LedgerEntry> {
        None // Sparse trees don't store ledger entries directly
    }

    fn generate_proof(&self, id: &uuid::Uuid) -> Result<Option<super::MerkleProof>> {
        let key = SparseKey::from_slice(&id.as_bytes()[..]);
        Ok(Some(self.generate_proof(&key)?))
    }

    fn verify_proof(&self, proof: &super::MerkleProof, entry: &LedgerEntry) -> Result<bool> {
        let key = SparseKey::from_slice(&entry.id.as_bytes()[..]);
        self.verify_proof(proof, &key, Some(&entry.data))
    }

    fn clear(&mut self) {
        self.clear();
    }

    fn tree_type(&self) -> TreeType {
        TreeType::Sparse
    }

    fn metadata(&self) -> &TreeMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut TreeMetadata {
        &mut self.metadata
    }

    fn export_data(&self) -> Result<TreeExportData> {
        let pairs = self
            .entries()
            .into_iter()
            .map(|(key, value)| (key.as_bytes().to_vec(), value))
            .collect();
        Ok(TreeExportData::from_key_value_pairs(
            TreeType::Sparse,
            TreeType::Sparse,
            pairs,
            self.metadata.clone(),
        ))
    }

    fn import_data(&mut self, data: TreeExportData) -> Result<()> {
        if !data.is_compatible_with(TreeType::Sparse) {
            return Err(SylvaError::InvalidInput {
                message: "Export data not compatible with sparse tree".to_string(),
            });
        }

        self.clear();
        for (key, value) in data.key_value_pairs {
            let sparse_key = SparseKey::from_slice(&key);
            self.insert(sparse_key, value)?;
        }
        self.metadata = data.metadata;
        self.metadata.tree_type = TreeType::Sparse;
        Ok(())
    }

    fn validate_structure(&self) -> Result<bool> {
        let report = self.validate_consistency()?;
        Ok(report.is_consistent)
    }

    fn memory_usage(&self) -> TreeMemoryUsage {
        let stats = self.statistics();
        TreeMemoryUsage::new(
            stats.memory_usage,
            stats.memory_usage / 2, // Rough estimate for data
            std::mem::size_of::<TreeMetadata>(),
            stats.memory_usage / 2, // Rough estimate for structure
        )
    }
}

/// Statistics about a sparse Merkle tree
#[derive(Debug, Clone)]
pub struct SparseTreeStatistics {
    pub entry_count: usize,
    pub leaf_nodes: usize,
    pub internal_nodes: usize,
    pub total_nodes: usize,
    pub height: usize,
    pub memory_usage: usize,
    pub memory_efficiency: f64,
}

/// Result of a bulk operation
#[derive(Debug, Clone, Default)]
pub struct BulkOperationResult {
    pub successful_operations: usize,
    pub processed_keys: Vec<SparseKey>,
    pub errors: Vec<BulkOperationError>,
}

impl BulkOperationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn total_operations(&self) -> usize {
        self.successful_operations + self.errors.len()
    }
}

/// Error in a bulk operation
#[derive(Debug, Clone)]
pub struct BulkOperationError {
    pub key: SparseKey,
    pub operation: String,
    pub error: String,
}

/// Tree consistency validation report
#[derive(Debug, Clone)]
pub struct TreeConsistencyReport {
    pub is_consistent: bool,
    pub errors: Vec<String>,
}

impl Default for TreeConsistencyReport {
    fn default() -> Self {
        Self {
            is_consistent: true,
            errors: Vec::new(),
        }
    }
}

impl TreeConsistencyReport {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Result of tree repair operation
#[derive(Debug, Clone, Default)]
pub struct TreeRepairResult {
    pub was_consistent: bool,
    pub initial_errors: Vec<String>,
    pub nodes_repaired: usize,
    pub repair_successful: bool,
}

impl TreeRepairResult {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_key_creation() {
        let key1 = SparseKey::new([1u8; 32]);
        assert_eq!(key1.byte(0), 1);
        assert_eq!(key1.byte(31), 1);
        assert_eq!(key1.byte(32), 0);

        let key2 = SparseKey::from_slice(b"hello");
        assert_eq!(key2.byte(0), b'h');
        assert_eq!(key2.byte(4), b'o');
        assert_eq!(key2.byte(5), 0);
    }

    #[test]
    fn test_sparse_key_bits() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b10100000; // First byte: 10100000
        let key = SparseKey::new(bytes);

        assert!(key.bit(0)); // First bit is 1
        assert!(!key.bit(1)); // Second bit is 0
        assert!(key.bit(2)); // Third bit is 1
        assert!(!key.bit(3)); // Fourth bit is 0
    }

    #[test]
    fn test_sparse_key_hex() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = SparseKey::from_hex(hex).unwrap();
        assert_eq!(key.to_hex(), hex);
        assert_eq!(key.byte(31), 1);
    }

    #[test]
    fn test_empty_sparse_tree() {
        let tree = SparseMerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.entry_count(), 0);
        assert_eq!(tree.height(), SPARSE_TREE_HEIGHT);
        assert_eq!(tree.node_count(), 0);
    }

    #[test]
    fn test_sparse_tree_insert_and_get() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"test_key");
        let value = b"test_value".to_vec();

        tree.insert(key, value.clone()).unwrap();

        assert_eq!(tree.entry_count(), 1);
        assert!(!tree.is_empty());
        assert!(tree.contains_key(&key));
        assert_eq!(tree.get(&key), Some(value.as_slice()));

        let non_existent_key = SparseKey::from_slice(b"not_there");
        assert!(!tree.contains_key(&non_existent_key));
        assert_eq!(tree.get(&non_existent_key), None);
    }

    #[test]
    fn test_sparse_tree_update() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"key");
        let value1 = b"value1".to_vec();
        let value2 = b"value2".to_vec();

        tree.insert(key, value1.clone()).unwrap();
        assert_eq!(tree.entry_count(), 1);

        // Use upsert for update operation (or explicit update method)
        tree.upsert(key, value2.clone()).unwrap();
        assert_eq!(tree.entry_count(), 1); // Count shouldn't change
        assert_eq!(tree.get(&key), Some(value2.as_slice()));
    }

    #[test]
    fn test_sparse_tree_remove() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"key");
        let value = b"value".to_vec();

        tree.insert(key, value.clone()).unwrap();
        assert_eq!(tree.entry_count(), 1);

        let removed = tree.remove(&key).unwrap();
        assert_eq!(removed, Some(value));
        assert_eq!(tree.entry_count(), 0);
        assert!(!tree.contains_key(&key));

        let removed_again = tree.remove(&key).unwrap();
        assert_eq!(removed_again, None);
    }

    #[test]
    fn test_sparse_tree_multiple_entries() {
        let mut tree = SparseMerkleTree::new();
        let entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];

        for (key, value) in &entries {
            tree.insert(*key, value.clone()).unwrap();
        }

        assert_eq!(tree.entry_count(), 3);

        for (key, value) in &entries {
            assert!(tree.contains_key(key));
            assert_eq!(tree.get(key), Some(value.as_slice()));
        }

        let tree_entries = tree.entries();
        assert_eq!(tree_entries.len(), 3);
    }

    #[test]
    fn test_sparse_tree_from_entries() {
        let entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];

        let tree = SparseMerkleTree::from_entries(entries.clone()).unwrap();
        assert_eq!(tree.entry_count(), 3);

        for (key, value) in &entries {
            assert_eq!(tree.get(key), Some(value.as_slice()));
        }
    }

    #[test]
    fn test_sparse_tree_proofs() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"test_key");
        let value = b"test_value".to_vec();

        tree.insert(key, value.clone()).unwrap();

        // Test inclusion proof
        assert!(tree.verify_sparse_proof(&key, Some(&value)).unwrap());

        // Test exclusion proof
        let non_existent_key = SparseKey::from_slice(b"not_there");
        assert!(tree.verify_sparse_proof(&non_existent_key, None).unwrap());
    }

    #[test]
    fn test_sparse_tree_memory_efficiency() {
        let mut tree = SparseMerkleTree::new();

        // Test with sparse data (keys that are far apart)
        let keys = [
            SparseKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            SparseKey::from_hex("8000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            SparseKey::from_hex("c000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        ];

        for (i, key) in keys.iter().enumerate() {
            tree.insert(*key, format!("value{}", i).into_bytes())
                .unwrap();
        }

        let stats = tree.statistics();
        println!("Sparse tree stats: {:?}", stats);

        // With 3 entries in a 256-bit key space, we should have very few nodes
        assert_eq!(stats.entry_count, 3);
        assert!(stats.total_nodes < 1000); // Much less than 2^256 possible nodes
        assert!(stats.memory_efficiency > 0.001); // Reasonable efficiency for sparse data
    }

    #[test]
    fn test_sparse_tree_large_key_space() {
        let mut tree = SparseMerkleTree::new();

        // Insert 1000 random keys
        for i in 0..1000 {
            let mut key_bytes = [0u8; 32];
            key_bytes[0] = (i % 256) as u8;
            key_bytes[1] = ((i / 256) % 256) as u8;
            key_bytes[2] = ((i / 65536) % 256) as u8;

            let key = SparseKey::new(key_bytes);
            let value = format!("value_{}", i).into_bytes();
            tree.insert(key, value).unwrap();
        }

        let stats = tree.statistics();
        println!("Large sparse tree stats: {:?}", stats);

        // Memory should still be proportional to data, not key space
        assert_eq!(stats.entry_count, 1000);
        assert!(stats.total_nodes < 500000); // Much less than theoretical maximum

        // Should handle large key space efficiently
        assert!(stats.memory_efficiency > 0.001);
    }

    #[test]
    fn test_sparse_tree_clear() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"key");
        let value = b"value".to_vec();

        tree.upsert(key, value).unwrap();
        assert_eq!(tree.entry_count(), 1);

        tree.clear();
        assert_eq!(tree.entry_count(), 0);
        assert!(tree.is_empty());
        assert_eq!(tree.node_count(), 0);
    }

    // ========== CRUD OPERATIONS TESTS ==========

    #[test]
    fn test_crud_insert_operations() {
        let mut tree = SparseMerkleTree::new();
        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();
        let value2 = b"value2".to_vec();

        // Test successful insert
        assert!(tree.insert(key1, value1.clone()).is_ok());
        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.get(&key1), Some(value1.as_slice()));

        // Test insert of new key
        assert!(tree.insert(key2, value2.clone()).is_ok());
        assert_eq!(tree.entry_count(), 2);

        // Test insert duplicate key fails
        let result = tree.insert(key1, b"new_value".to_vec());
        assert!(result.is_err());
        assert_eq!(tree.get(&key1), Some(value1.as_slice())); // Original value unchanged

        // Test insert empty value fails
        let key3 = SparseKey::from_slice(b"key3");
        let result = tree.insert(key3, vec![]);
        assert!(result.is_err());
        assert!(!tree.contains_key(&key3));
    }

    #[test]
    fn test_crud_update_operations() {
        let mut tree = SparseMerkleTree::new();
        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();
        let new_value = b"new_value".to_vec();

        // Setup: insert a key
        tree.insert(key1, value1.clone()).unwrap();

        // Test successful update
        let old_value = tree.update(key1, new_value.clone()).unwrap();
        assert_eq!(old_value, value1);
        assert_eq!(tree.get(&key1), Some(new_value.as_slice()));
        assert_eq!(tree.entry_count(), 1); // Count should not change

        // Test update non-existent key fails
        let result = tree.update(key2, b"value2".to_vec());
        assert!(result.is_err());
        assert!(!tree.contains_key(&key2));

        // Test update with empty value fails
        let result = tree.update(key1, vec![]);
        assert!(result.is_err());
        assert_eq!(tree.get(&key1), Some(new_value.as_slice())); // Value unchanged
    }

    #[test]
    fn test_crud_upsert_operations() {
        let mut tree = SparseMerkleTree::new();
        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();
        let value2 = b"value2".to_vec();
        let new_value = b"new_value".to_vec();

        // Test upsert (insert) new key
        let old_value = tree.upsert(key1, value1.clone()).unwrap();
        assert_eq!(old_value, None);
        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.get(&key1), Some(value1.as_slice()));

        // Test upsert (update) existing key
        let old_value = tree.upsert(key1, new_value.clone()).unwrap();
        assert_eq!(old_value, Some(value1));
        assert_eq!(tree.entry_count(), 1);
        assert_eq!(tree.get(&key1), Some(new_value.as_slice()));

        // Test upsert another new key
        let old_value = tree.upsert(key2, value2.clone()).unwrap();
        assert_eq!(old_value, None);
        assert_eq!(tree.entry_count(), 2);

        // Test upsert with empty value fails
        let key3 = SparseKey::from_slice(b"key3");
        let result = tree.upsert(key3, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_crud_delete_operations() {
        let mut tree = SparseMerkleTree::new();
        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();
        let value2 = b"value2".to_vec();

        // Setup: insert keys
        tree.insert(key1, value1.clone()).unwrap();
        tree.insert(key2, value2.clone()).unwrap();
        assert_eq!(tree.entry_count(), 2);

        // Test successful delete
        let deleted_value = tree.delete(&key1).unwrap();
        assert_eq!(deleted_value, value1);
        assert_eq!(tree.entry_count(), 1);
        assert!(!tree.contains_key(&key1));
        assert!(tree.contains_key(&key2));

        // Test delete non-existent key fails
        let result = tree.delete(&key1);
        assert!(result.is_err());
        assert_eq!(tree.entry_count(), 1);

        // Test remove (non-failing version)
        let removed_value = tree.remove(&key2).unwrap();
        assert_eq!(removed_value, Some(value2));
        assert_eq!(tree.entry_count(), 0);

        // Test remove non-existent key returns None
        let removed_value = tree.remove(&key2).unwrap();
        assert_eq!(removed_value, None);
    }

    #[test]
    fn test_crud_get_with_proof() {
        let mut tree = SparseMerkleTree::new();
        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();

        // Insert a key
        tree.insert(key1, value1.clone()).unwrap();

        // Test get with proof for existing key
        let (value, proof) = tree.get_with_proof(&key1).unwrap();
        assert_eq!(value, Some(value1.clone()));
        assert!(tree.verify_proof(&proof, &key1, Some(&value1)).unwrap());

        // Test get with proof for non-existent key
        let (value, proof) = tree.get_with_proof(&key2).unwrap();
        assert_eq!(value, None);
        assert!(tree.verify_proof(&proof, &key2, None).unwrap());
    }

    #[test]
    fn test_crud_bulk_insert() {
        let mut tree = SparseMerkleTree::new();
        let entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];

        // Test successful bulk insert
        let result = tree.bulk_insert(entries.clone()).unwrap();
        assert!(result.is_success());
        assert_eq!(result.successful_operations, 3);
        assert_eq!(tree.entry_count(), 3);

        // Verify all entries were inserted
        for (key, value) in &entries {
            assert_eq!(tree.get(key), Some(value.as_slice()));
        }

        // Test bulk insert with duplicate keys
        let duplicate_entries = vec![
            (SparseKey::from_slice(b"key1"), b"new_value1".to_vec()),
            (SparseKey::from_slice(b"key4"), b"value4".to_vec()),
        ];

        let result = tree.bulk_insert(duplicate_entries).unwrap();
        assert!(result.has_errors());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.successful_operations, 0); // All or nothing on validation errors
        assert_eq!(tree.entry_count(), 3); // No changes made

        // Test bulk insert with empty values
        let invalid_entries = vec![
            (SparseKey::from_slice(b"key5"), vec![]),
            (SparseKey::from_slice(b"key6"), b"value6".to_vec()),
        ];

        let result = tree.bulk_insert(invalid_entries).unwrap();
        assert!(result.has_errors());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.successful_operations, 0);
    }

    #[test]
    fn test_crud_bulk_update() {
        let mut tree = SparseMerkleTree::new();

        // Setup: insert some keys
        let initial_entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];
        tree.bulk_insert(initial_entries).unwrap();

        // Test successful bulk update
        let updates = vec![
            (SparseKey::from_slice(b"key1"), b"new_value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"new_value2".to_vec()),
        ];

        let result = tree.bulk_update(updates.clone()).unwrap();
        assert!(result.is_success());
        assert_eq!(result.successful_operations, 2);
        assert_eq!(tree.entry_count(), 3); // Count unchanged

        // Verify updates
        assert_eq!(
            tree.get(&SparseKey::from_slice(b"key1")),
            Some(b"new_value1".as_slice())
        );
        assert_eq!(
            tree.get(&SparseKey::from_slice(b"key2")),
            Some(b"new_value2".as_slice())
        );

        // Test bulk update with non-existent keys
        let invalid_updates = vec![
            (SparseKey::from_slice(b"key4"), b"value4".to_vec()),
            (SparseKey::from_slice(b"key5"), b"value5".to_vec()),
        ];

        let result = tree.bulk_update(invalid_updates).unwrap();
        assert!(result.has_errors());
        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.successful_operations, 0);
    }

    #[test]
    fn test_crud_bulk_upsert() {
        let mut tree = SparseMerkleTree::new();

        // Setup: insert one key
        tree.insert(SparseKey::from_slice(b"key1"), b"value1".to_vec())
            .unwrap();

        // Test bulk upsert (mix of updates and inserts)
        let upserts = vec![
            (SparseKey::from_slice(b"key1"), b"new_value1".to_vec()), // Update
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),     // Insert
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),     // Insert
        ];

        let result = tree.bulk_upsert(upserts).unwrap();
        assert!(result.is_success());
        assert_eq!(result.successful_operations, 3);
        assert_eq!(tree.entry_count(), 3);

        // Verify all operations
        assert_eq!(
            tree.get(&SparseKey::from_slice(b"key1")),
            Some(b"new_value1".as_slice())
        );
        assert_eq!(
            tree.get(&SparseKey::from_slice(b"key2")),
            Some(b"value2".as_slice())
        );
        assert_eq!(
            tree.get(&SparseKey::from_slice(b"key3")),
            Some(b"value3".as_slice())
        );
    }

    #[test]
    fn test_crud_bulk_delete() {
        let mut tree = SparseMerkleTree::new();

        // Setup: insert some keys
        let entries = vec![
            (SparseKey::from_slice(b"key1"), b"value1".to_vec()),
            (SparseKey::from_slice(b"key2"), b"value2".to_vec()),
            (SparseKey::from_slice(b"key3"), b"value3".to_vec()),
        ];
        tree.bulk_insert(entries).unwrap();

        // Test successful bulk delete
        let keys_to_delete = vec![
            SparseKey::from_slice(b"key1"),
            SparseKey::from_slice(b"key2"),
        ];

        let result = tree.bulk_delete(keys_to_delete).unwrap();
        assert!(result.is_success());
        assert_eq!(result.successful_operations, 2);
        assert_eq!(tree.entry_count(), 1);

        // Verify deletions
        assert!(!tree.contains_key(&SparseKey::from_slice(b"key1")));
        assert!(!tree.contains_key(&SparseKey::from_slice(b"key2")));
        assert!(tree.contains_key(&SparseKey::from_slice(b"key3")));

        // Test bulk delete with non-existent keys
        let invalid_keys = vec![
            SparseKey::from_slice(b"key1"), // Already deleted
            SparseKey::from_slice(b"key4"), // Never existed
        ];

        let result = tree.bulk_delete(invalid_keys).unwrap();
        assert!(result.has_errors());
        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.successful_operations, 0);
    }

    #[test]
    fn test_tree_consistency_validation() {
        let mut tree = SparseMerkleTree::new();
        let key = SparseKey::from_slice(b"test_key");
        let value = b"test_value".to_vec();

        tree.insert(key, value).unwrap();

        // Test that a valid tree passes consistency check
        let report = tree.validate_consistency().unwrap();
        assert!(report.is_consistent);
        assert!(report.errors.is_empty());

        // Test repair on consistent tree
        let repair_result = tree.repair_if_needed().unwrap();
        assert!(repair_result.was_consistent);
        assert_eq!(repair_result.nodes_repaired, 0);
        assert!(repair_result.repair_successful);
    }

    #[test]
    fn test_root_hash_recalculation() {
        let mut tree = SparseMerkleTree::new();
        let initial_root = tree.root_hash().clone();

        let key1 = SparseKey::from_slice(b"key1");
        let key2 = SparseKey::from_slice(b"key2");
        let value1 = b"value1".to_vec();
        let value2 = b"value2".to_vec();

        // Root should change after insert
        tree.insert(key1, value1.clone()).unwrap();
        let root_after_insert = tree.root_hash().clone();
        assert_ne!(initial_root, root_after_insert);

        // Root should change after another insert
        tree.insert(key2, value2.clone()).unwrap();
        let root_after_second_insert = tree.root_hash().clone();
        assert_ne!(root_after_insert, root_after_second_insert);

        // Root should change after update
        tree.update(key1, b"new_value1".to_vec()).unwrap();
        let root_after_update = tree.root_hash().clone();
        assert_ne!(root_after_second_insert, root_after_update);

        // Root should change after delete
        tree.delete(&key1).unwrap();
        let root_after_delete = tree.root_hash().clone();
        assert_ne!(root_after_update, root_after_delete);

        // Root should return to single-entry state
        tree.delete(&key2).unwrap();
        let final_root = tree.root_hash().clone();
        assert_eq!(final_root, initial_root);
    }

    // ========== PERFORMANCE TESTS ==========

    #[test]
    fn test_crud_operation_performance() {
        use std::time::Instant;

        let mut tree = SparseMerkleTree::new();
        let num_operations = 1000;

        // Generate test data
        let mut test_keys = Vec::new();
        let mut test_values = Vec::new();

        for i in 0..num_operations {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            test_keys.push(SparseKey::new(key_bytes));
            test_values.push(format!("value_{}", i).into_bytes());
        }

        // Test insert performance - should be O(log height)
        let start = Instant::now();
        for (i, (key, value)) in test_keys.iter().zip(test_values.iter()).enumerate() {
            tree.insert(*key, value.clone()).unwrap();

            // Verify tree properties after every 100 insertions
            if (i + 1) % 100 == 0 {
                assert_eq!(tree.entry_count(), i + 1);
                let consistency = tree.validate_consistency().unwrap();
                assert!(
                    consistency.is_consistent,
                    "Tree inconsistent after {} insertions",
                    i + 1
                );
            }
        }
        let insert_time = start.elapsed();
        println!(
            "Insert {} entries: {:?} ({:.2}μs per operation)",
            num_operations,
            insert_time,
            insert_time.as_micros() as f64 / num_operations as f64
        );

        // Test get performance
        let start = Instant::now();
        for key in &test_keys {
            assert!(tree.get(key).is_some());
        }
        let get_time = start.elapsed();
        println!(
            "Get {} entries: {:?} ({:.2}μs per operation)",
            num_operations,
            get_time,
            get_time.as_micros() as f64 / num_operations as f64
        );

        // Test update performance
        let start = Instant::now();
        for (i, key) in test_keys.iter().enumerate() {
            let new_value = format!("updated_value_{}", i).into_bytes();
            tree.update(*key, new_value).unwrap();
        }
        let update_time = start.elapsed();
        println!(
            "Update {} entries: {:?} ({:.2}μs per operation)",
            num_operations,
            update_time,
            update_time.as_micros() as f64 / num_operations as f64
        );

        // Test delete performance
        let start = Instant::now();
        for key in &test_keys {
            tree.delete(key).unwrap();
        }
        let delete_time = start.elapsed();
        println!(
            "Delete {} entries: {:?} ({:.2}μs per operation)",
            num_operations,
            delete_time,
            delete_time.as_micros() as f64 / num_operations as f64
        );

        assert_eq!(tree.entry_count(), 0);

        // Verify performance is reasonable for a 256-level tree
        let max_time_per_op = std::time::Duration::from_millis(20); // 20ms per operation max (reasonable for 256 levels)
        assert!(
            insert_time / num_operations < max_time_per_op,
            "Insert performance too slow: {:?} per op",
            insert_time / num_operations
        );
        assert!(
            get_time / num_operations < max_time_per_op,
            "Get performance too slow: {:?} per op",
            get_time / num_operations
        );
        assert!(
            update_time / num_operations < max_time_per_op,
            "Update performance too slow: {:?} per op",
            update_time / num_operations
        );
        assert!(
            delete_time / num_operations < max_time_per_op,
            "Delete performance too slow: {:?} per op",
            delete_time / num_operations
        );
    }

    #[test]
    fn test_proof_generation_performance() {
        use std::time::Instant;

        let mut tree = SparseMerkleTree::new();
        let num_entries = 100;

        // Insert test data
        let mut test_keys = Vec::new();
        for i in 0..num_entries {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let key = SparseKey::new(key_bytes);
            let value = format!("value_{}", i).into_bytes();

            tree.insert(key, value).unwrap();
            test_keys.push(key);
        }

        // Test proof generation performance
        let start = Instant::now();
        for key in &test_keys {
            let (value, proof) = tree.get_with_proof(key).unwrap();
            assert!(value.is_some());
            assert_eq!(proof.path.len(), SPARSE_TREE_HEIGHT); // Should be exactly 256 for sparse trees
        }
        let proof_time = start.elapsed();
        println!(
            "Generate {} proofs: {:?} ({:.2}μs per proof)",
            num_entries,
            proof_time,
            proof_time.as_micros() as f64 / num_entries as f64
        );

        // Test proof verification performance
        let proofs: Vec<_> = test_keys
            .iter()
            .map(|key| tree.get_with_proof(key).unwrap())
            .collect();

        let start = Instant::now();
        for (i, (key, (value, proof))) in test_keys.iter().zip(proofs.iter()).enumerate() {
            let is_valid = tree
                .verify_proof(proof, key, value.as_ref().map(|v| v.as_slice()))
                .unwrap();
            assert!(is_valid, "Proof verification failed for entry {}", i);
        }
        let verify_time = start.elapsed();
        println!(
            "Verify {} proofs: {:?} ({:.2}μs per verification)",
            num_entries,
            verify_time,
            verify_time.as_micros() as f64 / num_entries as f64
        );

        // Proof operations should be reasonable for 256-level proofs
        let max_time_per_proof = std::time::Duration::from_millis(10); // 10ms per proof max
        assert!(
            proof_time / num_entries < max_time_per_proof,
            "Proof generation too slow: {:?} per proof",
            proof_time / num_entries
        );
        assert!(
            verify_time / num_entries < max_time_per_proof,
            "Proof verification too slow: {:?} per verification",
            verify_time / num_entries
        );
    }

    #[test]
    fn test_bulk_operation_performance() {
        use std::time::Instant;

        let num_entries = 1000;

        // Prepare bulk data
        let entries: Vec<_> = (0..num_entries)
            .map(|i| {
                let mut key_bytes = [0u8; 32];
                key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                (
                    SparseKey::new(key_bytes),
                    format!("value_{}", i).into_bytes(),
                )
            })
            .collect();

        // Test bulk insert vs individual inserts
        let mut tree1 = SparseMerkleTree::new();
        let start = Instant::now();
        for (key, value) in &entries {
            tree1.insert(*key, value.clone()).unwrap();
        }
        let individual_time = start.elapsed();

        let mut tree2 = SparseMerkleTree::new();
        let start = Instant::now();
        let result = tree2.bulk_insert(entries.clone()).unwrap();
        let bulk_time = start.elapsed();

        assert!(result.is_success());
        assert_eq!(result.successful_operations, num_entries);
        assert_eq!(tree1.entry_count(), tree2.entry_count());

        println!(
            "Individual inserts: {:?} ({:.2}μs per op)",
            individual_time,
            individual_time.as_micros() as f64 / num_entries as f64
        );
        println!(
            "Bulk insert: {:?} ({:.2}μs per op)",
            bulk_time,
            bulk_time.as_micros() as f64 / num_entries as f64
        );

        // Bulk operations should be competitive with individual operations
        // (They're not necessarily faster due to validation overhead, but should be close)
        assert!(
            bulk_time.as_millis() < individual_time.as_millis() * 2,
            "Bulk operations significantly slower than individual"
        );
    }

    #[test]
    fn test_tree_scaling_performance() {
        use std::time::Instant;

        let sizes = vec![10, 100, 1000];

        for size in sizes {
            let mut tree = SparseMerkleTree::new();

            // Measure time to build tree of given size
            let start = Instant::now();
            for i in 0..size {
                let mut key_bytes = [0u8; 32];
                key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                let key = SparseKey::new(key_bytes);
                let value = format!("value_{}", i).into_bytes();
                tree.insert(key, value).unwrap();
            }
            let build_time = start.elapsed();

            // Measure time for random access
            let test_key_idx = size / 2;
            let mut test_key_bytes = [0u8; 32];
            test_key_bytes[0..8].copy_from_slice(&(test_key_idx as u64).to_le_bytes());
            let test_key = SparseKey::new(test_key_bytes);

            let start = Instant::now();
            for _ in 0..10 {
                assert!(tree.get(&test_key).is_some());
            }
            let access_time = start.elapsed();

            println!(
                "Size {}: build {:?} ({:.2}μs per entry), access {:?} (10 ops)",
                size,
                build_time,
                build_time.as_micros() as f64 / size as f64,
                access_time
            );

            // Verify tree consistency
            let consistency = tree.validate_consistency().unwrap();
            assert!(
                consistency.is_consistent,
                "Tree inconsistent at size {}",
                size
            );
        }
    }

    #[test]
    fn test_default_empty_hashes() {
        // Test that empty hashes are precomputed correctly
        assert_eq!(EMPTY_HASHES.len(), SPARSE_TREE_HEIGHT + 1);

        // Each level should have a different hash
        for i in 0..SPARSE_TREE_HEIGHT {
            assert_ne!(EMPTY_HASHES[i], EMPTY_HASHES[i + 1]);
        }
    }
}
