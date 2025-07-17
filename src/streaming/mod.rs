//! Streaming operations for memory-efficient versioned ledger handling
//!
//! This module provides streaming capabilities for processing large versioned ledgers
//! with constant memory usage, enabling temporal queries and proof generation without
//! loading complete ledger history into memory.

use crate::error::{Result, SylvaError};
use crate::ledger::LedgerEntry;
use crate::storage::{LedgerMetadata, LedgerStorage, TimeRange};
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use uuid::Uuid;

pub mod buffer;
pub mod builder;
pub mod progress;
pub mod proof;
pub mod recovery;
pub mod temporal;

pub use buffer::{BufferConfig, StreamingBuffer};
pub use builder::StreamingLedgerBuilder;
pub use progress::{ProgressCallback, ProgressReporter};
pub use proof::StreamingProofGenerator;
pub use recovery::{CheckpointManager, StreamRecovery};
pub use temporal::{TemporalStreamer, TimeRangeQuery};

/// Configuration for streaming operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// Buffer size for streaming operations
    pub buffer_size: usize,
    /// Maximum number of entries to process in a single batch
    pub batch_size: usize,
    /// Version-aware buffering strategy
    pub version_awareness: VersionStrategy,
    /// Enable checkpoint creation for recovery
    pub enable_checkpoints: bool,
    /// Checkpoint interval (number of entries processed)
    pub checkpoint_interval: usize,
    /// Memory limit for streaming operations (bytes)
    pub memory_limit: Option<usize>,
    /// Temporal ordering strategy
    pub temporal_ordering: TemporalOrdering,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1024,
            batch_size: 256,
            version_awareness: VersionStrategy::Ordered,
            enable_checkpoints: true,
            checkpoint_interval: 10000,
            memory_limit: Some(64 * 1024 * 1024), // 64MB default
            temporal_ordering: TemporalOrdering::Timestamp,
        }
    }
}

/// Strategy for handling version-aware operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VersionStrategy {
    /// Process entries in version order
    Ordered,
    /// Process entries as they arrive (fastest)
    Unordered,
    /// Buffer and sort within version ranges
    BufferedSort,
}

/// Temporal ordering strategy for streaming
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TemporalOrdering {
    /// Order by timestamp
    Timestamp,
    /// Order by version
    Version,
    /// Order by insertion order
    Insertion,
    /// Mixed ordering (timestamp within version)
    Mixed,
}

/// Streaming context for maintaining state across operations
#[derive(Debug, Clone)]
pub struct StreamingContext {
    pub config: StreamingConfig,
    pub current_version: u64,
    pub current_position: usize,
    pub entries_processed: usize,
    pub start_time: std::time::Instant,
    pub last_checkpoint: Option<std::time::Instant>,
    pub memory_usage: usize,
}

impl StreamingContext {
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            config,
            current_version: 0,
            current_position: 0,
            entries_processed: 0,
            start_time: std::time::Instant::now(),
            last_checkpoint: None,
            memory_usage: 0,
        }
    }

    pub fn should_checkpoint(&self) -> bool {
        self.config.enable_checkpoints
            && self.entries_processed > 0
            && self.entries_processed % self.config.checkpoint_interval == 0
    }

    pub fn memory_exceeded(&self) -> bool {
        if let Some(limit) = self.config.memory_limit {
            self.memory_usage > limit
        } else {
            false
        }
    }

    pub fn update_memory_usage(&mut self, delta: isize) {
        if delta >= 0 {
            self.memory_usage += delta as usize;
        } else {
            self.memory_usage = self.memory_usage.saturating_sub((-delta) as usize);
        }
    }
}

/// Entry in a streaming operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingEntry {
    pub entry: LedgerEntry,
    pub source_position: usize,
    pub processing_metadata: StreamingMetadata,
}

/// Metadata for streaming operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingMetadata {
    pub stream_id: Uuid,
    pub batch_id: usize,
    pub position_in_batch: usize,
    pub timestamp_received: u64,
    pub memory_footprint: usize,
}

/// Result of a streaming operation
#[derive(Debug)]
pub struct StreamingResult<T> {
    pub data: T,
    pub entries_processed: usize,
    pub memory_peak: usize,
    pub processing_time: std::time::Duration,
    pub checkpoints_created: usize,
}

/// Main streaming engine
pub struct StreamingEngine {
    config: StreamingConfig,
    storage: Arc<LedgerStorage>,
    context: Arc<Mutex<StreamingContext>>,
}

impl StreamingEngine {
    pub fn new(config: StreamingConfig, storage: Arc<LedgerStorage>) -> Self {
        let context = Arc::new(Mutex::new(StreamingContext::new(config.clone())));
        Self {
            config,
            storage,
            context,
        }
    }

    /// Create a streaming ledger builder
    pub fn builder(&self) -> StreamingLedgerBuilder {
        StreamingLedgerBuilder::new(self.config.clone(), self.storage.clone())
    }

    /// Create a streaming proof generator
    pub fn proof_generator(&self) -> StreamingProofGenerator {
        StreamingProofGenerator::new(self.config.clone(), self.storage.clone())
    }

    /// Create a temporal streamer for time-range queries
    pub fn temporal_streamer(&self) -> TemporalStreamer {
        TemporalStreamer::new(self.config.clone(), self.storage.clone())
    }

    /// Stream entries from a ledger with constant memory usage
    pub fn stream_entries(&self, ledger_id: &Uuid) -> Result<EntryStream> {
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        Ok(EntryStream::new(
            self.storage.clone(),
            *ledger_id,
            metadata,
            self.config.clone(),
        ))
    }

    /// Stream entries within a time range
    pub fn stream_time_range(
        &self,
        ledger_id: &Uuid,
        time_range: TimeRange,
    ) -> Result<TemporalEntryStream> {
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        Ok(TemporalEntryStream::new(
            self.storage.clone(),
            *ledger_id,
            metadata,
            time_range,
            self.config.clone(),
        ))
    }

    /// Get current streaming statistics
    pub async fn get_statistics(&self) -> StreamingStatistics {
        let context = self.context.lock().await;
        StreamingStatistics {
            entries_processed: context.entries_processed,
            current_memory_usage: context.memory_usage,
            processing_time: context.start_time.elapsed(),
            current_version: context.current_version,
            checkpoints_created: if context.last_checkpoint.is_some() {
                1
            } else {
                0
            },
        }
    }
}

/// Statistics for streaming operations
#[derive(Debug, Clone)]
pub struct StreamingStatistics {
    pub entries_processed: usize,
    pub current_memory_usage: usize,
    pub processing_time: std::time::Duration,
    pub current_version: u64,
    pub checkpoints_created: usize,
}

/// Stream of ledger entries with constant memory usage
pub struct EntryStream {
    storage: Arc<LedgerStorage>,
    ledger_id: Uuid,
    metadata: LedgerMetadata,
    config: StreamingConfig,
    buffer: VecDeque<StreamingEntry>,
    current_position: usize,
    finished: bool,
}

impl EntryStream {
    fn new(
        storage: Arc<LedgerStorage>,
        ledger_id: Uuid,
        metadata: LedgerMetadata,
        config: StreamingConfig,
    ) -> Self {
        Self {
            storage,
            ledger_id,
            metadata,
            config,
            buffer: VecDeque::new(),
            current_position: 0,
            finished: false,
        }
    }

    fn load_next_batch(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        // Load next batch from storage with memory-efficient pagination
        let batch_end = std::cmp::min(
            self.current_position + self.config.batch_size,
            self.metadata.entry_count,
        );

        if self.current_position >= self.metadata.entry_count {
            self.finished = true;
            return Ok(());
        }

        // Use memory-mapped access for large ledgers
        let entries =
            self.storage
                .load_entries_range(&self.ledger_id, self.current_position, batch_end)?;

        for (idx, entry) in entries.into_iter().enumerate() {
            let data_len = entry.data.len();
            let streaming_entry = StreamingEntry {
                entry,
                source_position: self.current_position + idx,
                processing_metadata: StreamingMetadata {
                    stream_id: Uuid::new_v4(),
                    batch_id: self.current_position / self.config.batch_size,
                    position_in_batch: idx,
                    timestamp_received: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    memory_footprint: std::mem::size_of::<LedgerEntry>() + data_len,
                },
            };
            self.buffer.push_back(streaming_entry);
        }

        self.current_position = batch_end;
        Ok(())
    }
}

impl Stream for EntryStream {
    type Item = Result<StreamingEntry>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.buffer.is_empty() && !self.finished {
            if let Err(e) = self.load_next_batch() {
                return Poll::Ready(Some(Err(e)));
            }
        }

        if let Some(entry) = self.buffer.pop_front() {
            Poll::Ready(Some(Ok(entry)))
        } else if self.finished {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// Temporal entry stream for time-range queries
pub struct TemporalEntryStream {
    storage: Arc<LedgerStorage>,
    ledger_id: Uuid,
    _metadata: LedgerMetadata,
    time_range: TimeRange,
    config: StreamingConfig,
    buffer: VecDeque<StreamingEntry>,
    current_position: usize,
    finished: bool,
}

impl TemporalEntryStream {
    fn new(
        storage: Arc<LedgerStorage>,
        ledger_id: Uuid,
        metadata: LedgerMetadata,
        time_range: TimeRange,
        config: StreamingConfig,
    ) -> Self {
        Self {
            storage,
            ledger_id,
            _metadata: metadata,
            time_range,
            config,
            buffer: VecDeque::new(),
            current_position: 0,
            finished: false,
        }
    }

    fn load_next_temporal_batch(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        // Load entries within time range using temporal indexing
        let entries = self.storage.load_entries_time_range(
            &self.ledger_id,
            &self.time_range,
            self.current_position,
            self.config.batch_size,
        )?;

        if entries.is_empty() {
            self.finished = true;
            return Ok(());
        }

        let entries_len = entries.len();
        for (idx, entry) in entries.into_iter().enumerate() {
            let data_len = entry.data.len();
            let streaming_entry = StreamingEntry {
                entry,
                source_position: self.current_position + idx,
                processing_metadata: StreamingMetadata {
                    stream_id: Uuid::new_v4(),
                    batch_id: self.current_position / self.config.batch_size,
                    position_in_batch: idx,
                    timestamp_received: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    memory_footprint: std::mem::size_of::<LedgerEntry>() + data_len,
                },
            };
            self.buffer.push_back(streaming_entry);
        }

        self.current_position += entries_len;
        Ok(())
    }
}

impl Stream for TemporalEntryStream {
    type Item = Result<StreamingEntry>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.buffer.is_empty() && !self.finished {
            if let Err(e) = self.load_next_temporal_batch() {
                return Poll::Ready(Some(Err(e)));
            }
        }

        if let Some(entry) = self.buffer.pop_front() {
            Poll::Ready(Some(Ok(entry)))
        } else if self.finished {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        assert_eq!(config.buffer_size, 1024);
        assert_eq!(config.batch_size, 256);
        assert!(config.enable_checkpoints);
        assert!(config.memory_limit.is_some());
    }

    #[tokio::test]
    async fn test_streaming_context() {
        let config = StreamingConfig::default();
        let mut context = StreamingContext::new(config);

        assert_eq!(context.entries_processed, 0);
        assert!(!context.should_checkpoint());

        context.entries_processed = 10000;
        assert!(context.should_checkpoint());

        context.update_memory_usage(1024);
        assert_eq!(context.memory_usage, 1024);

        context.update_memory_usage(-512);
        assert_eq!(context.memory_usage, 512);
    }

    #[tokio::test]
    async fn test_streaming_engine_creation() {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = Arc::new(LedgerStorage::new(&workspace).unwrap());
        let config = StreamingConfig::default();

        let engine = StreamingEngine::new(config, storage);
        let stats = engine.get_statistics().await;

        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.current_memory_usage, 0);
        assert_eq!(stats.current_version, 0);
    }
}
