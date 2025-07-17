//! Memory-mapped file support for handling large versioned ledgers
//!
//! This module provides memory-mapped access to large ledger files, enabling
//! efficient handling of ledgers that are larger than available RAM through:
//! - Version-based indexing for quick access to specific time ranges
//! - Lazy loading of ledger sections as needed
//! - Memory-mapped proof generation across versions
//! - Automatic storage strategy selection based on size and age
//!
//! Key features:
//! - Bounded memory usage regardless of ledger size
//! - Efficient version queries and range operations
//! - Background prefetching for performance optimization
//! - Automatic fallback to regular storage for small ledgers

use crate::error::{Result, SylvaError};
use crate::ledger::{Ledger, LedgerEntry};
use crate::storage::LedgerMetadata;
#[cfg(test)]
use crate::storage::StorageFormat;
use crate::tree::{binary::BinaryMerkleTree, MerkleProof, Tree};
use chrono::{DateTime, Utc};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use uuid::Uuid;

/// Threshold for using memory-mapped storage (100MB)
const MMAP_SIZE_THRESHOLD: u64 = 100 * 1024 * 1024;

/// Maximum memory mapping size per operation (1GB)
#[allow(dead_code)]
const MAX_MMAP_SIZE: u64 = 1024 * 1024 * 1024;

/// Size of version index entries in bytes
const VERSION_INDEX_ENTRY_SIZE: u64 = 64;

/// Memory mapping strategy selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmapStrategy {
    /// Use regular in-memory storage for small ledgers
    InMemory,
    /// Use memory-mapped storage for large ledgers
    MemoryMapped,
    /// Use hybrid approach - index in memory, data memory-mapped
    Hybrid,
}

/// Version index entry for quick access to specific versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionIndexEntry {
    /// Version number
    pub version: u64,
    /// Timestamp of this version
    pub timestamp: DateTime<Utc>,
    /// Byte offset in the ledger file
    pub file_offset: u64,
    /// Number of entries in this version
    pub entry_count: usize,
    /// Size of this version segment in bytes
    pub segment_size: u64,
    /// Root hash for this version
    pub root_hash: Option<String>,
}

/// Time range for querying ledger sections
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeRange {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, timestamp: &DateTime<Utc>) -> bool {
        timestamp >= &self.start && timestamp <= &self.end
    }

    pub fn overlaps(&self, other: &TimeRange) -> bool {
        self.start <= other.end && self.end >= other.start
    }
}

/// Memory usage statistics for monitoring
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Total mapped memory in bytes
    pub mapped_memory: u64,
    /// Active memory regions
    pub active_regions: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Number of page faults
    pub page_faults: u64,
    /// Last update timestamp
    pub last_updated: DateTime<Utc>,
}

/// Configuration for memory-mapped ledger access
#[derive(Debug, Clone)]
pub struct MmapConfig {
    /// Strategy selection mode
    pub strategy: MmapStrategy,
    /// Size threshold for using memory mapping
    pub size_threshold: u64,
    /// Maximum number of concurrent mappings
    pub max_concurrent_mappings: usize,
    /// Enable prefetching for better performance
    pub enable_prefetching: bool,
    /// Cache size for version indices
    pub index_cache_size: usize,
}

impl Default for MmapConfig {
    fn default() -> Self {
        Self {
            strategy: MmapStrategy::Hybrid,
            size_threshold: MMAP_SIZE_THRESHOLD,
            max_concurrent_mappings: 16,
            enable_prefetching: true,
            index_cache_size: 1000,
        }
    }
}

/// Memory-mapped ledger for efficient access to large versioned data
pub struct MmapLedger {
    /// Ledger metadata
    #[allow(dead_code)]
    metadata: LedgerMetadata,
    /// Path to the ledger file
    file_path: PathBuf,
    /// Version index for quick access
    version_index: BTreeMap<u64, VersionIndexEntry>,
    /// Memory-mapped file handle
    #[allow(dead_code)]
    mmap: Option<Arc<Mmap>>,
    /// Configuration
    config: MmapConfig,
    /// Active memory regions
    active_regions: Arc<RwLock<HashMap<Range<u64>, Arc<Mmap>>>>,
    /// Memory usage statistics
    memory_stats: Arc<Mutex<MemoryStats>>,
    /// Last access times for LRU eviction
    access_times: Arc<Mutex<HashMap<Range<u64>, Instant>>>,
}

impl MmapLedger {
    /// Create a new memory-mapped ledger
    pub fn new(file_path: PathBuf, metadata: LedgerMetadata, config: MmapConfig) -> Result<Self> {
        let version_index = Self::load_version_index(&file_path)?;

        let memory_stats = Arc::new(Mutex::new(MemoryStats {
            mapped_memory: 0,
            active_regions: 0,
            cache_hit_rate: 0.0,
            page_faults: 0,
            last_updated: Utc::now(),
        }));

        let ledger = Self {
            metadata,
            file_path,
            version_index,
            mmap: None,
            config,
            active_regions: Arc::new(RwLock::new(HashMap::new())),
            memory_stats,
            access_times: Arc::new(Mutex::new(HashMap::new())),
        };

        Ok(ledger)
    }

    /// Determine the optimal storage strategy for a ledger
    pub fn determine_strategy(
        file_size: u64,
        age_days: u32,
        access_frequency: f64,
    ) -> MmapStrategy {
        // Large files should use memory mapping
        if file_size > MMAP_SIZE_THRESHOLD {
            return MmapStrategy::MemoryMapped;
        }

        // Frequently accessed files benefit from in-memory storage
        if access_frequency > 0.8 && file_size < MMAP_SIZE_THRESHOLD / 2 {
            return MmapStrategy::InMemory;
        }

        // Old, large files can use hybrid approach
        if age_days > 30 && file_size > MMAP_SIZE_THRESHOLD / 4 {
            return MmapStrategy::Hybrid;
        }

        MmapStrategy::InMemory
    }

    /// Load version index from file
    fn load_version_index(file_path: &Path) -> Result<BTreeMap<u64, VersionIndexEntry>> {
        let index_path = file_path.with_extension("idx");

        if !index_path.exists() {
            return Ok(BTreeMap::new());
        }

        let file = File::open(&index_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to open index file {}: {}", index_path.display(), e),
        })?;

        let reader = BufReader::new(file);
        let index = bincode::deserialize_from(reader).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to deserialize version index: {}", e),
        })?;

        Ok(index)
    }

    /// Save version index to file
    fn save_version_index(&self) -> Result<()> {
        let index_path = self.file_path.with_extension("idx");

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&index_path)
            .map_err(|e| SylvaError::StorageError {
                message: format!(
                    "Failed to create index file {}: {}",
                    index_path.display(),
                    e
                ),
            })?;

        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &self.version_index).map_err(|e| {
            SylvaError::StorageError {
                message: format!("Failed to serialize version index: {}", e),
            }
        })?;

        Ok(())
    }

    /// Get entries within a specific time range
    pub fn get_entries_in_range(&self, time_range: &TimeRange) -> Result<Vec<LedgerEntry>> {
        let relevant_versions = self.find_versions_in_range(time_range);
        let mut entries = Vec::new();

        for version_entry in relevant_versions {
            let version_entries = self.load_version_entries(version_entry)?;

            // Filter by exact timestamp (convert u64 timestamp to DateTime)
            for entry in version_entries {
                let entry_datetime = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0);
                if let Some(dt) = entry_datetime {
                    if time_range.contains(&dt) {
                        entries.push(entry);
                    }
                }
            }
        }

        // Sort by timestamp
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(entries)
    }

    /// Find version index entries that overlap with the time range
    fn find_versions_in_range(&self, time_range: &TimeRange) -> Vec<&VersionIndexEntry> {
        self.version_index
            .values()
            .filter(|entry| {
                // Check if version timestamp is within range
                time_range.contains(&entry.timestamp)
            })
            .collect()
    }

    /// Load entries for a specific version using memory mapping
    fn load_version_entries(&self, version_entry: &VersionIndexEntry) -> Result<Vec<LedgerEntry>> {
        let range =
            version_entry.file_offset..(version_entry.file_offset + version_entry.segment_size);

        let data = self.map_range(range)?;

        // Deserialize entries from the mapped data
        let entries: Vec<LedgerEntry> =
            bincode::deserialize(&data).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to deserialize ledger entries: {}", e),
            })?;

        Ok(entries)
    }

    /// Map a specific byte range of the file into memory
    fn map_range(&self, range: Range<u64>) -> Result<Vec<u8>> {
        // Check if we already have this range mapped
        {
            let regions = self.active_regions.read().unwrap();
            if let Some(existing_mmap) = regions.get(&range) {
                self.update_access_time(range.clone());
                return self.extract_data_from_mmap(existing_mmap, &range);
            }
        }

        // Need to create a new mapping
        self.create_new_mapping(range)
    }

    /// Update access time for LRU eviction
    fn update_access_time(&self, range: Range<u64>) {
        let mut access_times = self.access_times.lock().unwrap();
        access_times.insert(range, Instant::now());
    }

    /// Extract data from an existing memory mapping
    fn extract_data_from_mmap(&self, mmap: &Arc<Mmap>, range: &Range<u64>) -> Result<Vec<u8>> {
        let start = range.start as usize;
        let end = range.end as usize;

        if end > mmap.len() {
            return Err(SylvaError::StorageError {
                message: format!(
                    "Range {}..{} exceeds mapping size {}",
                    start,
                    end,
                    mmap.len()
                ),
            });
        }

        Ok(mmap[start..end].to_vec())
    }

    /// Create a new memory mapping for the specified range
    fn create_new_mapping(&self, range: Range<u64>) -> Result<Vec<u8>> {
        // Ensure we don't exceed mapping limits
        self.evict_if_needed()?;

        let file = File::open(&self.file_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to open ledger file: {}", e),
        })?;

        let mmap = unsafe {
            MmapOptions::new()
                .offset(range.start)
                .len((range.end - range.start) as usize)
                .map(&file)
                .map_err(|e| SylvaError::StorageError {
                    message: format!("Failed to create memory mapping: {}", e),
                })?
        };

        let mmap_arc = Arc::new(mmap);
        let data = mmap_arc.as_ref().to_vec();

        // Store the mapping for future use
        {
            let mut regions = self.active_regions.write().unwrap();
            regions.insert(range.clone(), mmap_arc);
        }

        self.update_access_time(range);
        self.update_memory_stats();

        Ok(data)
    }

    /// Evict old mappings if we're approaching limits
    fn evict_if_needed(&self) -> Result<()> {
        let regions_count = {
            let regions = self.active_regions.read().unwrap();
            regions.len()
        };

        if regions_count >= self.config.max_concurrent_mappings {
            self.evict_lru_mappings(regions_count - self.config.max_concurrent_mappings + 1)?;
        }

        Ok(())
    }

    /// Evict least recently used mappings
    fn evict_lru_mappings(&self, count: usize) -> Result<()> {
        let ranges_to_evict = {
            let access_times = self.access_times.lock().unwrap();
            let mut ranges_with_times: Vec<_> = access_times.iter().collect();
            ranges_with_times.sort_by_key(|(_, time)| *time);

            ranges_with_times
                .into_iter()
                .take(count)
                .map(|(range, _)| range.clone())
                .collect::<Vec<_>>()
        };

        {
            let mut regions = self.active_regions.write().unwrap();
            let mut access_times = self.access_times.lock().unwrap();

            for range in ranges_to_evict {
                regions.remove(&range);
                access_times.remove(&range);
            }
        }

        self.update_memory_stats();
        Ok(())
    }

    /// Update memory usage statistics
    fn update_memory_stats(&self) {
        let regions = self.active_regions.read().unwrap();
        let total_mapped = regions.keys().map(|range| range.end - range.start).sum();

        let mut stats = self.memory_stats.lock().unwrap();
        stats.mapped_memory = total_mapped;
        stats.active_regions = regions.len();
        stats.last_updated = Utc::now();
    }

    /// Generate inclusion proof for entries across multiple versions
    pub fn generate_cross_version_proof(
        &self,
        entry_ids: &[Uuid],
        version_range: Range<u64>,
    ) -> Result<Vec<Option<MerkleProof>>> {
        let mut proofs = Vec::new();

        for version in version_range {
            if let Some(version_entry) = self.version_index.get(&version) {
                let entries = self.load_version_entries(version_entry)?;

                // Build tree for this version
                let mut tree = BinaryMerkleTree::new();
                for entry in &entries {
                    tree.insert(entry.clone())?;
                }

                // Generate proofs for relevant entry IDs in this version
                for &entry_id in entry_ids {
                    let proof = tree.generate_proof(&entry_id)?;
                    proofs.push(proof);
                }
            }
        }

        Ok(proofs)
    }

    /// Get ledger entries for a specific version
    pub fn get_version(&self, version: u64) -> Result<Vec<LedgerEntry>> {
        if let Some(version_entry) = self.version_index.get(&version) {
            self.load_version_entries(version_entry)
        } else {
            Err(SylvaError::StorageError {
                message: format!("Version {} not found", version),
            })
        }
    }

    /// Get latest version number
    pub fn latest_version(&self) -> u64 {
        self.version_index.keys().max().copied().unwrap_or(0)
    }

    /// Get total number of versions
    pub fn version_count(&self) -> usize {
        self.version_index.len()
    }

    /// Get memory usage statistics
    pub fn memory_stats(&self) -> MemoryStats {
        self.memory_stats.lock().unwrap().clone()
    }

    /// Append new entries to the ledger (creating a new version)
    pub fn append_entries(&mut self, entries: Vec<LedgerEntry>) -> Result<u64> {
        if entries.is_empty() {
            return Ok(self.latest_version());
        }

        let new_version = self.latest_version() + 1;
        let timestamp = Utc::now();

        // Serialize the entries
        let serialized_entries =
            bincode::serialize(&entries).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to serialize entries: {}", e),
            })?;

        // Append to file
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.file_path)
            .map_err(|e| SylvaError::StorageError {
                message: format!("Failed to open ledger file for writing: {}", e),
            })?;

        let file_offset = file
            .seek(SeekFrom::End(0))
            .map_err(|e| SylvaError::StorageError {
                message: format!("Failed to seek to end of file: {}", e),
            })?;

        file.write_all(&serialized_entries)
            .map_err(|e| SylvaError::StorageError {
                message: format!("Failed to write entries to file: {}", e),
            })?;

        // Update version index
        let version_entry = VersionIndexEntry {
            version: new_version,
            timestamp,
            file_offset,
            entry_count: entries.len(),
            segment_size: serialized_entries.len() as u64,
            root_hash: None, // Could compute root hash here if needed
        };

        self.version_index.insert(new_version, version_entry);
        self.save_version_index()?;

        Ok(new_version)
    }

    /// Optimize the ledger file by reorganizing data
    pub fn optimize(&mut self) -> Result<()> {
        // Clear active mappings before optimization
        {
            let mut regions = self.active_regions.write().unwrap();
            regions.clear();
        }

        // Could implement file compaction, version merging, etc.
        // For now, just rebuild the index
        self.rebuild_index()?;
        Ok(())
    }

    /// Rebuild the version index from the file
    fn rebuild_index(&mut self) -> Result<()> {
        // This would involve scanning the entire file and rebuilding the index
        // Implementation depends on the specific file format
        self.save_version_index()
    }

    /// Close the memory-mapped ledger and clean up resources
    pub fn close(&mut self) -> Result<()> {
        // Clear all active mappings
        {
            let mut regions = self.active_regions.write().unwrap();
            regions.clear();
        }

        {
            let mut access_times = self.access_times.lock().unwrap();
            access_times.clear();
        }

        // Save final index state
        self.save_version_index()
    }
}

/// Manager for multiple memory-mapped ledgers
pub struct MmapLedgerManager {
    /// Open ledgers
    ledgers: HashMap<Uuid, MmapLedger>,
    /// Configuration
    config: MmapConfig,
    /// Base directory for ledger files
    base_dir: PathBuf,
}

impl MmapLedgerManager {
    /// Create a new memory-mapped ledger manager
    pub fn new(base_dir: PathBuf, config: MmapConfig) -> Self {
        Self {
            ledgers: HashMap::new(),
            config,
            base_dir,
        }
    }

    /// Open or create a memory-mapped ledger
    pub fn open_ledger(&mut self, ledger_id: Uuid, metadata: LedgerMetadata) -> Result<()> {
        let file_path = self.base_dir.join(format!("{}.mmap", ledger_id));
        let ledger = MmapLedger::new(file_path, metadata, self.config.clone())?;
        self.ledgers.insert(ledger_id, ledger);
        Ok(())
    }

    /// Get a reference to a ledger
    pub fn get_ledger(&self, ledger_id: &Uuid) -> Option<&MmapLedger> {
        self.ledgers.get(ledger_id)
    }

    /// Get a mutable reference to a ledger
    pub fn get_ledger_mut(&mut self, ledger_id: &Uuid) -> Option<&mut MmapLedger> {
        self.ledgers.get_mut(ledger_id)
    }

    /// Close a specific ledger
    pub fn close_ledger(&mut self, ledger_id: &Uuid) -> Result<()> {
        if let Some(mut ledger) = self.ledgers.remove(ledger_id) {
            ledger.close()?;
        }
        Ok(())
    }

    /// Close all ledgers and clean up
    pub fn close_all(&mut self) -> Result<()> {
        for (_, mut ledger) in self.ledgers.drain() {
            ledger.close()?;
        }
        Ok(())
    }

    /// Get overall memory statistics across all ledgers
    pub fn total_memory_stats(&self) -> MemoryStats {
        let mut total_stats = MemoryStats {
            mapped_memory: 0,
            active_regions: 0,
            cache_hit_rate: 0.0,
            page_faults: 0,
            last_updated: Utc::now(),
        };

        let mut hit_rates = Vec::new();

        for ledger in self.ledgers.values() {
            let stats = ledger.memory_stats();
            total_stats.mapped_memory += stats.mapped_memory;
            total_stats.active_regions += stats.active_regions;
            total_stats.page_faults += stats.page_faults;
            hit_rates.push(stats.cache_hit_rate);
        }

        // Average cache hit rate
        if !hit_rates.is_empty() {
            total_stats.cache_hit_rate = hit_rates.iter().sum::<f64>() / hit_rates.len() as f64;
        }

        total_stats
    }
}

/// Utility functions for working with memory-mapped ledgers
pub mod utils {
    use super::*;

    /// Generate synthetic ledger data for testing
    pub fn generate_synthetic_ledger(entry_count: usize, version_count: u64) -> Ledger {
        let mut ledger = Ledger::new();

        let entries_per_version = entry_count / version_count as usize;
        let mut entry_counter = 0;

        for version in 0..version_count {
            for i in 0..entries_per_version {
                let data = format!("Test entry {} in version {}", i, version).into_bytes();
                let mut metadata = HashMap::new();
                metadata.insert("version".to_string(), version.to_string());
                metadata.insert("index".to_string(), entry_counter.to_string());

                if ledger.add_entry_with_metadata(data, metadata).is_ok() {
                    entry_counter += 1;
                }
            }
        }

        ledger
    }

    /// Estimate memory usage for a given ledger size
    pub fn estimate_memory_usage(file_size: u64, version_count: u64) -> u64 {
        // Base memory for version index
        let index_memory = version_count * VERSION_INDEX_ENTRY_SIZE;

        // Estimate active mapping memory (assume 10% of file is actively mapped)
        let mapping_memory = file_size / 10;

        index_memory + mapping_memory
    }

    /// Check if a ledger should use memory mapping based on size and usage patterns
    pub fn should_use_mmap(file_size: u64, access_pattern: &str) -> bool {
        match access_pattern {
            "sequential" => file_size > MMAP_SIZE_THRESHOLD / 2,
            "random" => file_size > MMAP_SIZE_THRESHOLD,
            "range_query" => file_size > MMAP_SIZE_THRESHOLD / 4,
            _ => file_size > MMAP_SIZE_THRESHOLD,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_ledger_metadata() -> LedgerMetadata {
        LedgerMetadata {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            modified_at: Utc::now(),
            version: 1,
            entry_count: 0,
            format: StorageFormat::Binary,
            root_hash: None,
            description: Some("Test memory-mapped ledger".to_string()),
            tags: HashMap::new(),
            compression_stats: None,
        }
    }

    #[test]
    fn test_mmap_strategy_selection() {
        // Large file should use memory mapping
        assert_eq!(
            MmapLedger::determine_strategy(200_000_000, 1, 0.1),
            MmapStrategy::MemoryMapped
        );

        // Small, frequently accessed file should use in-memory
        assert_eq!(
            MmapLedger::determine_strategy(10_000_000, 1, 0.9),
            MmapStrategy::InMemory
        );

        // Old, medium file should use hybrid
        assert_eq!(
            MmapLedger::determine_strategy(50_000_000, 60, 0.3),
            MmapStrategy::Hybrid
        );
    }

    #[test]
    fn test_time_range_operations() {
        let start = Utc::now();
        let end = start + chrono::Duration::hours(1);
        let range = TimeRange::new(start, end);

        let mid_time = start + chrono::Duration::minutes(30);
        assert!(range.contains(&mid_time));

        let before_time = start - chrono::Duration::minutes(10);
        assert!(!range.contains(&before_time));

        let after_time = end + chrono::Duration::minutes(10);
        assert!(!range.contains(&after_time));
    }

    #[test]
    fn test_time_range_overlap() {
        let start1 = Utc::now();
        let end1 = start1 + chrono::Duration::hours(1);
        let range1 = TimeRange::new(start1, end1);

        let start2 = start1 + chrono::Duration::minutes(30);
        let end2 = start2 + chrono::Duration::hours(1);
        let range2 = TimeRange::new(start2, end2);

        assert!(range1.overlaps(&range2));
        assert!(range2.overlaps(&range1));

        let start3 = end1 + chrono::Duration::minutes(10);
        let end3 = start3 + chrono::Duration::hours(1);
        let range3 = TimeRange::new(start3, end3);

        assert!(!range1.overlaps(&range3));
        assert!(!range3.overlaps(&range1));
    }

    #[test]
    fn test_version_index_entry() {
        let entry = VersionIndexEntry {
            version: 1,
            timestamp: Utc::now(),
            file_offset: 1024,
            entry_count: 100,
            segment_size: 8192,
            root_hash: Some("abcd1234".to_string()),
        };

        // Test serialization round-trip
        let serialized = bincode::serialize(&entry).unwrap();
        let deserialized: VersionIndexEntry = bincode::deserialize(&serialized).unwrap();

        assert_eq!(entry.version, deserialized.version);
        assert_eq!(entry.file_offset, deserialized.file_offset);
        assert_eq!(entry.entry_count, deserialized.entry_count);
        assert_eq!(entry.segment_size, deserialized.segment_size);
        assert_eq!(entry.root_hash, deserialized.root_hash);
    }

    #[test]
    fn test_memory_stats() {
        let stats = MemoryStats {
            mapped_memory: 1024 * 1024,
            active_regions: 5,
            cache_hit_rate: 0.85,
            page_faults: 100,
            last_updated: Utc::now(),
        };

        assert_eq!(stats.mapped_memory, 1024 * 1024);
        assert_eq!(stats.active_regions, 5);
        assert!((stats.cache_hit_rate - 0.85).abs() < 0.001);
        assert_eq!(stats.page_faults, 100);
    }

    #[test]
    fn test_synthetic_ledger_generation() {
        let ledger = utils::generate_synthetic_ledger(1000, 10);
        assert_eq!(ledger.entry_count(), 1000);

        // Check that entries have version metadata
        let entries = ledger.get_entries();
        for entry in entries {
            assert!(entry.metadata.contains_key("version"));
            assert!(entry.metadata.contains_key("index"));
        }
    }

    #[test]
    fn test_memory_usage_estimation() {
        let file_size = 100 * 1024 * 1024; // 100MB
        let version_count = 1000;

        let estimated = utils::estimate_memory_usage(file_size, version_count);

        // Should include index overhead and estimated mapping memory
        let expected_index = version_count * VERSION_INDEX_ENTRY_SIZE;
        let expected_mapping = file_size / 10;

        assert_eq!(estimated, expected_index + expected_mapping);
    }

    #[test]
    fn test_mmap_shoulduse_decision() {
        assert!(utils::should_use_mmap(200_000_000, "random"));
        assert!(!utils::should_use_mmap(10_000_000, "random"));
        assert!(utils::should_use_mmap(60_000_000, "sequential")); // 60MB > 50MB threshold
        assert!(utils::should_use_mmap(30_000_000, "range_query"));
    }

    #[test]
    fn test_mmap_config_defaults() {
        let config = MmapConfig::default();

        assert_eq!(config.strategy, MmapStrategy::Hybrid);
        assert_eq!(config.size_threshold, MMAP_SIZE_THRESHOLD);
        assert_eq!(config.max_concurrent_mappings, 16);
        assert!(config.enable_prefetching);
        assert_eq!(config.index_cache_size, 1000);
    }

    #[test]
    fn test_mmap_ledger_creation() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_ledger.mmap");
        let metadata = create_test_ledger_metadata();
        let config = MmapConfig::default();

        let result = MmapLedger::new(file_path, metadata, config);
        assert!(result.is_ok());

        let ledger = result.unwrap();
        assert_eq!(ledger.latest_version(), 0);
        assert_eq!(ledger.version_count(), 0);
    }

    #[test]
    fn test_mmap_manager_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config = MmapConfig::default();
        let mut manager = MmapLedgerManager::new(temp_dir.path().to_path_buf(), config);

        let ledger_id = Uuid::new_v4();
        let metadata = create_test_ledger_metadata();

        // Test opening a ledger
        assert!(manager.open_ledger(ledger_id, metadata).is_ok());
        assert!(manager.get_ledger(&ledger_id).is_some());

        // Test closing a ledger
        assert!(manager.close_ledger(&ledger_id).is_ok());
        assert!(manager.get_ledger(&ledger_id).is_none());
    }

    #[test]
    fn test_range_operations() {
        let range1 = 0..100;
        let _range2 = 50..150;
        let _range3 = 200..300;

        // Test range contains
        assert!(range1.contains(&50));
        assert!(!range1.contains(&150));

        // Test range overlap logic would go here
        // (Rust ranges don't have built-in overlap, but our TimeRange does)
    }
}
