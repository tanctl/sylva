//! Configurable streaming buffer with version awareness

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

use super::StreamingEntry;

#[cfg(test)]
use uuid::Uuid;

/// Configuration for streaming buffers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Maximum buffer size in bytes
    pub max_size_bytes: usize,
    /// Maximum number of entries to buffer
    pub max_entries: usize,
    /// Buffer strategy for version-aware operations
    pub strategy: BufferStrategy,
    /// Enable adaptive buffer sizing based on entry sizes
    pub adaptive_sizing: bool,
    /// Memory pressure threshold (0.0-1.0)
    pub memory_pressure_threshold: f64,
    /// Auto-flush threshold
    pub auto_flush_threshold: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 8 * 1024 * 1024, // 8MB
            max_entries: 10000,
            strategy: BufferStrategy::VersionAware,
            adaptive_sizing: true,
            memory_pressure_threshold: 0.8,
            auto_flush_threshold: 1000,
        }
    }
}

/// Buffer strategy for handling versioned entries
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BufferStrategy {
    /// Simple FIFO buffering
    Fifo,
    /// Version-aware buffering with ordering
    VersionAware,
    /// Priority-based buffering (newer versions first)
    Priority,
    /// Adaptive strategy based on access patterns
    Adaptive,
}

/// Statistics about buffer usage
#[derive(Debug, Clone)]
pub struct BufferStats {
    /// Current number of entries in buffer
    pub entry_count: usize,
    /// Current buffer size in bytes
    pub size_bytes: usize,
    /// Memory utilization percentage
    pub memory_utilization: f64,
    /// Number of version conflicts resolved
    pub version_conflicts: usize,
    /// Number of auto-flushes performed
    pub auto_flushes: usize,
    /// Average entry size
    pub avg_entry_size: usize,
}

/// Version-aware streaming buffer
pub struct StreamingBuffer {
    config: BufferConfig,
    entries: VecDeque<StreamingEntry>,
    version_index: BTreeMap<u64, Vec<usize>>, // version -> entry indices
    size_bytes: usize,
    stats: BufferStats,
    adaptive_size_history: VecDeque<usize>,
}

impl StreamingBuffer {
    /// Create a new streaming buffer
    pub fn new(config: BufferConfig) -> Self {
        Self {
            config,
            entries: VecDeque::new(),
            version_index: BTreeMap::new(),
            size_bytes: 0,
            stats: BufferStats {
                entry_count: 0,
                size_bytes: 0,
                memory_utilization: 0.0,
                version_conflicts: 0,
                auto_flushes: 0,
                avg_entry_size: 0,
            },
            adaptive_size_history: VecDeque::new(),
        }
    }

    /// Add an entry to the buffer
    pub fn push(&mut self, entry: StreamingEntry) -> Result<Option<Vec<StreamingEntry>>> {
        let entry_size = self.calculate_entry_size(&entry);

        // Check if we need to make space
        let mut flushed_entries = None;
        if self.should_flush(entry_size) {
            flushed_entries = Some(self.flush_entries()?);
        }

        // Add entry based on strategy
        match self.config.strategy {
            BufferStrategy::Fifo => self.push_fifo(entry, entry_size),
            BufferStrategy::VersionAware => self.push_version_aware(entry, entry_size)?,
            BufferStrategy::Priority => self.push_priority(entry, entry_size),
            BufferStrategy::Adaptive => self.push_adaptive(entry, entry_size)?,
        }

        self.update_stats();
        Ok(flushed_entries)
    }

    /// Get entries by version range
    pub fn get_version_range(&self, start_version: u64, end_version: u64) -> Vec<&StreamingEntry> {
        let mut result = Vec::new();

        for (&_version, indices) in self.version_index.range(start_version..end_version) {
            for &index in indices {
                if let Some(entry) = self.entries.get(index) {
                    result.push(entry);
                }
            }
        }

        result.sort_by_key(|entry| entry.entry.timestamp);
        result
    }

    /// Get all entries in temporal order
    pub fn get_temporal_order(&self) -> Vec<&StreamingEntry> {
        let mut entries: Vec<&StreamingEntry> = self.entries.iter().collect();
        entries.sort_by_key(|entry| entry.entry.timestamp);
        entries
    }

    /// Peek at the next entry without removing it
    pub fn peek(&self) -> Option<&StreamingEntry> {
        self.entries.front()
    }

    /// Pop the next entry from the buffer
    pub fn pop(&mut self) -> Option<StreamingEntry> {
        if let Some(entry) = self.entries.pop_front() {
            self.size_bytes = self
                .size_bytes
                .saturating_sub(self.calculate_entry_size(&entry));
            self.rebuild_version_index();
            self.update_stats();
            Some(entry)
        } else {
            None
        }
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.config.max_entries
            || self.size_bytes >= self.config.max_size_bytes
    }

    /// Get current buffer statistics
    pub fn stats(&self) -> &BufferStats {
        &self.stats
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.entries.clear();
        self.version_index.clear();
        self.size_bytes = 0;
        self.update_stats();
    }

    /// Flush entries based on strategy
    pub fn flush_entries(&mut self) -> Result<Vec<StreamingEntry>> {
        let flush_count = match self.config.strategy {
            BufferStrategy::Fifo => self.config.auto_flush_threshold,
            BufferStrategy::VersionAware => self.calculate_version_aware_flush_count(),
            BufferStrategy::Priority => self.calculate_priority_flush_count(),
            BufferStrategy::Adaptive => self.calculate_adaptive_flush_count(),
        };

        let mut flushed = Vec::new();
        for _ in 0..flush_count.min(self.entries.len()) {
            if let Some(entry) = self.pop() {
                flushed.push(entry);
            }
        }

        self.stats.auto_flushes += 1;
        Ok(flushed)
    }

    /// Set buffer configuration
    pub fn set_config(&mut self, config: BufferConfig) {
        self.config = config;

        // Adjust current buffer if necessary
        if self.entries.len() > self.config.max_entries
            || self.size_bytes > self.config.max_size_bytes
        {
            // Trigger flush if over limits
            let _ = self.flush_entries();
        }
    }

    /// Get version distribution in buffer
    pub fn version_distribution(&self) -> BTreeMap<u64, usize> {
        self.version_index
            .iter()
            .map(|(&version, indices)| (version, indices.len()))
            .collect()
    }

    // Private helper methods

    fn should_flush(&self, incoming_entry_size: usize) -> bool {
        self.entries.len() >= self.config.max_entries
            || self.size_bytes + incoming_entry_size > self.config.max_size_bytes
            || self.memory_utilization() > self.config.memory_pressure_threshold
    }

    fn push_fifo(&mut self, entry: StreamingEntry, entry_size: usize) {
        let index = self.entries.len();
        self.entries.push_back(entry);
        self.size_bytes += entry_size;
        self.update_version_index(index);
    }

    fn push_version_aware(&mut self, entry: StreamingEntry, entry_size: usize) -> Result<()> {
        let version = entry.entry.version;

        // Check for version conflicts
        if let Some(existing_indices) = self.version_index.get(&version) {
            if !existing_indices.is_empty() {
                self.stats.version_conflicts += 1;
                // Handle conflict based on timestamp
                self.resolve_version_conflict(entry, entry_size)?;
                return Ok(());
            }
        }

        // Insert in version order
        let insert_position = self.find_version_insert_position(version);
        self.entries.insert(insert_position, entry);
        self.size_bytes += entry_size;
        self.rebuild_version_index();

        Ok(())
    }

    fn push_priority(&mut self, entry: StreamingEntry, entry_size: usize) {
        let version = entry.entry.version;

        // Higher versions get priority (inserted closer to front)
        let insert_position = self
            .entries
            .iter()
            .position(|e| e.entry.version < version)
            .unwrap_or(self.entries.len());

        self.entries.insert(insert_position, entry);
        self.size_bytes += entry_size;
        self.rebuild_version_index();
    }

    fn push_adaptive(&mut self, entry: StreamingEntry, entry_size: usize) -> Result<()> {
        // Track entry size for adaptive sizing
        if self.config.adaptive_sizing {
            self.adaptive_size_history.push_back(entry_size);
            if self.adaptive_size_history.len() > 100 {
                self.adaptive_size_history.pop_front();
            }
        }

        // Use version-aware strategy as base, but adapt based on patterns
        if self.detect_sequential_pattern() {
            self.push_fifo(entry, entry_size);
        } else {
            self.push_version_aware(entry, entry_size)?;
        }

        Ok(())
    }

    fn resolve_version_conflict(&mut self, entry: StreamingEntry, entry_size: usize) -> Result<()> {
        let version = entry.entry.version;

        if let Some(indices) = self.version_index.get(&version).cloned() {
            // Find entry with same version and replace if newer timestamp
            for &index in &indices {
                if let Some(existing_entry) = self.entries.get(index) {
                    if entry.entry.timestamp > existing_entry.entry.timestamp {
                        let old_size = self.calculate_entry_size(existing_entry);
                        // Now get mutable reference
                        if let Some(existing_entry_mut) = self.entries.get_mut(index) {
                            *existing_entry_mut = entry;
                            self.size_bytes = self.size_bytes.saturating_sub(old_size) + entry_size;
                            return Ok(());
                        }
                    }
                }
            }
        }

        // If we can't replace, just add normally
        self.push_fifo(entry, entry_size);
        Ok(())
    }

    fn find_version_insert_position(&self, version: u64) -> usize {
        self.entries
            .iter()
            .position(|entry| entry.entry.version > version)
            .unwrap_or(self.entries.len())
    }

    fn calculate_entry_size(&self, entry: &StreamingEntry) -> usize {
        std::mem::size_of::<StreamingEntry>()
            + entry.entry.data.len()
            + entry.entry.metadata.len() * 64 // Rough estimate for metadata
    }

    fn update_version_index(&mut self, index: usize) {
        if let Some(entry) = self.entries.get(index) {
            let version = entry.entry.version;
            self.version_index.entry(version).or_default().push(index);
        }
    }

    fn rebuild_version_index(&mut self) {
        self.version_index.clear();
        for (index, entry) in self.entries.iter().enumerate() {
            let version = entry.entry.version;
            self.version_index.entry(version).or_default().push(index);
        }
    }

    fn update_stats(&mut self) {
        self.stats.entry_count = self.entries.len();
        self.stats.size_bytes = self.size_bytes;
        self.stats.memory_utilization = self.memory_utilization();
        self.stats.avg_entry_size = if self.entries.is_empty() {
            0
        } else {
            self.size_bytes / self.entries.len()
        };
    }

    fn memory_utilization(&self) -> f64 {
        let max_size = self.config.max_size_bytes.max(1);
        self.size_bytes as f64 / max_size as f64
    }

    fn calculate_version_aware_flush_count(&self) -> usize {
        // Flush older versions first, keep recent versions
        let total_versions = self.version_index.len();
        if total_versions > 10 {
            self.config.auto_flush_threshold / 2
        } else {
            self.config.auto_flush_threshold
        }
    }

    fn calculate_priority_flush_count(&self) -> usize {
        // Flush lower priority (older) entries
        self.config.auto_flush_threshold
    }

    fn calculate_adaptive_flush_count(&self) -> usize {
        // Adaptive flush based on entry size variance
        let avg_size = self.stats.avg_entry_size;
        if avg_size > 1024 {
            // Large entries
            self.config.auto_flush_threshold / 4
        } else {
            self.config.auto_flush_threshold / 2
        }
    }

    fn detect_sequential_pattern(&self) -> bool {
        if self.entries.len() < 5 {
            return false;
        }

        // Check if recent entries follow sequential version pattern
        let recent_entries: Vec<_> = self.entries.iter().rev().take(5).collect();
        let mut is_sequential = true;

        for window in recent_entries.windows(2) {
            let diff = window[0].entry.version.abs_diff(window[1].entry.version);
            if diff > 2 {
                is_sequential = false;
                break;
            }
        }

        is_sequential
    }
}

/// Buffered stream adapter
pub struct BufferedStream<S> {
    _inner: S,
    buffer: StreamingBuffer,
    config: BufferConfig,
}

impl<S> BufferedStream<S> {
    /// Create a new buffered stream
    pub fn new(stream: S, config: BufferConfig) -> Self {
        let buffer = StreamingBuffer::new(config.clone());
        Self {
            _inner: stream,
            buffer,
            config,
        }
    }

    /// Get buffer statistics
    pub fn buffer_stats(&self) -> &BufferStats {
        self.buffer.stats()
    }

    /// Update buffer configuration
    pub fn set_buffer_config(&mut self, config: BufferConfig) {
        self.buffer.set_config(config.clone());
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerEntry;

    fn create_test_entry(version: u64, timestamp: u64, data: &str) -> StreamingEntry {
        let mut entry = LedgerEntry::new(data.as_bytes().to_vec(), version);
        entry.timestamp = timestamp;

        StreamingEntry {
            entry,
            source_position: 0,
            processing_metadata: super::super::StreamingMetadata {
                stream_id: Uuid::new_v4(),
                batch_id: 0,
                position_in_batch: 0,
                timestamp_received: timestamp,
                memory_footprint: data.len(),
            },
        }
    }

    #[test]
    fn test_buffer_config_default() {
        let config = BufferConfig::default();
        assert_eq!(config.max_size_bytes, 8 * 1024 * 1024);
        assert_eq!(config.max_entries, 10000);
        assert!(config.adaptive_sizing);
    }

    #[test]
    fn test_fifo_buffer_strategy() {
        let config = BufferConfig {
            strategy: BufferStrategy::Fifo,
            max_entries: 3,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add entries
        let entry1 = create_test_entry(1, 1000, "data1");
        let entry2 = create_test_entry(2, 2000, "data2");
        let entry3 = create_test_entry(3, 3000, "data3");

        assert!(buffer.push(entry1).unwrap().is_none());
        assert!(buffer.push(entry2).unwrap().is_none());
        assert!(buffer.push(entry3).unwrap().is_none());

        // Buffer should be full
        assert!(buffer.is_full());

        // Next push should cause flush
        let entry4 = create_test_entry(4, 4000, "data4");
        let flushed = buffer.push(entry4).unwrap();
        assert!(flushed.is_some());
    }

    #[test]
    fn test_version_aware_buffer_strategy() {
        let config = BufferConfig {
            strategy: BufferStrategy::VersionAware,
            max_entries: 10,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add entries out of version order
        let entry3 = create_test_entry(3, 3000, "data3");
        let entry1 = create_test_entry(1, 1000, "data1");
        let entry2 = create_test_entry(2, 2000, "data2");

        buffer.push(entry3).unwrap();
        buffer.push(entry1).unwrap();
        buffer.push(entry2).unwrap();

        // Entries should be in version order
        let temporal_entries = buffer.get_temporal_order();
        assert_eq!(temporal_entries.len(), 3);
        assert_eq!(temporal_entries[0].entry.version, 1);
        assert_eq!(temporal_entries[1].entry.version, 2);
        assert_eq!(temporal_entries[2].entry.version, 3);
    }

    #[test]
    fn test_version_range_query() {
        let config = BufferConfig::default();
        let mut buffer = StreamingBuffer::new(config);

        // Add entries with different versions
        for i in 0..10 {
            let entry = create_test_entry(i, i * 1000, &format!("data{}", i));
            buffer.push(entry).unwrap();
        }

        // Query version range 3-7
        let range_entries = buffer.get_version_range(3, 7);
        assert_eq!(range_entries.len(), 4); // versions 3, 4, 5, 6

        for entry in range_entries {
            assert!(entry.entry.version >= 3 && entry.entry.version < 7);
        }
    }

    #[test]
    fn test_version_conflict_resolution() {
        let config = BufferConfig {
            strategy: BufferStrategy::VersionAware,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add entry with version 1
        let entry1 = create_test_entry(1, 1000, "data1");
        buffer.push(entry1).unwrap();

        // Add another entry with version 1 but later timestamp
        let entry1_updated = create_test_entry(1, 2000, "updated_data1");
        buffer.push(entry1_updated).unwrap();

        assert_eq!(buffer.stats.version_conflicts, 1);

        // Should have the updated entry
        let version_entries = buffer.get_version_range(1, 2);
        assert_eq!(version_entries.len(), 1);
        assert_eq!(version_entries[0].entry.timestamp, 2000);
    }

    #[test]
    fn test_priority_buffer_strategy() {
        let config = BufferConfig {
            strategy: BufferStrategy::Priority,
            max_entries: 5,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add entries with different versions
        let entry1 = create_test_entry(1, 1000, "data1");
        let entry5 = create_test_entry(5, 5000, "data5");
        let entry3 = create_test_entry(3, 3000, "data3");

        buffer.push(entry1).unwrap();
        buffer.push(entry5).unwrap();
        buffer.push(entry3).unwrap();

        // Higher versions should be first
        let first_entry = buffer.peek().unwrap();
        assert_eq!(first_entry.entry.version, 5);
    }

    #[test]
    fn test_buffer_memory_management() {
        let config = BufferConfig {
            max_size_bytes: 100, // Very small limit
            max_entries: 1000,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add large entry that exceeds memory limit
        let large_data = "x".repeat(200);
        let large_entry = create_test_entry(1, 1000, &large_data);

        let result = buffer.push(large_entry);
        assert!(result.is_ok());

        // Should trigger auto-flush due to memory pressure
        let stats = buffer.stats();
        assert!(stats.memory_utilization > 0.0);
    }

    #[test]
    fn test_buffer_statistics() {
        let config = BufferConfig::default();
        let mut buffer = StreamingBuffer::new(config);

        assert_eq!(buffer.stats().entry_count, 0);
        assert_eq!(buffer.stats().size_bytes, 0);

        // Add some entries
        for i in 0..5 {
            let entry = create_test_entry(i, i * 1000, &format!("data{}", i));
            buffer.push(entry).unwrap();
        }

        let stats = buffer.stats();
        assert_eq!(stats.entry_count, 5);
        assert!(stats.size_bytes > 0);
        assert!(stats.avg_entry_size > 0);
    }

    #[test]
    fn test_version_distribution() {
        let config = BufferConfig {
            strategy: BufferStrategy::Fifo,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add multiple entries for some versions
        buffer.push(create_test_entry(1, 1000, "data1")).unwrap();
        buffer.push(create_test_entry(1, 1100, "data1b")).unwrap();
        buffer.push(create_test_entry(2, 2000, "data2")).unwrap();
        buffer.push(create_test_entry(3, 3000, "data3")).unwrap();

        let distribution = buffer.version_distribution();
        assert_eq!(distribution.get(&1), Some(&2)); // 2 entries for version 1
        assert_eq!(distribution.get(&2), Some(&1)); // 1 entry for version 2
        assert_eq!(distribution.get(&3), Some(&1)); // 1 entry for version 3
    }

    #[test]
    fn test_adaptive_buffer_strategy() {
        let config = BufferConfig {
            strategy: BufferStrategy::Adaptive,
            adaptive_sizing: true,
            ..Default::default()
        };
        let mut buffer = StreamingBuffer::new(config);

        // Add sequential entries to trigger pattern detection
        for i in 0..10 {
            let entry = create_test_entry(i, i * 1000, &format!("data{}", i));
            buffer.push(entry).unwrap();
        }

        assert!(buffer.stats().entry_count > 0);
        // Adaptive strategy should handle the sequential pattern
    }
}
