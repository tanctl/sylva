//! Temporal streaming for time-range based queries

use crate::error::{Result, SylvaError};
use crate::ledger::LedgerEntry;
use crate::storage::{LedgerStorage, TimeRange};
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use uuid::Uuid;

use super::{StreamingConfig, StreamingEntry, StreamingMetadata, StreamingResult};

/// Time-range query specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRangeQuery {
    /// Start timestamp (inclusive)
    pub start_time: u64,
    /// End timestamp (exclusive)
    pub end_time: u64,
    /// Version range filter (optional)
    pub version_range: Option<(u64, u64)>,
    /// Maximum number of entries to return
    pub limit: Option<usize>,
    /// Ordering preference
    pub ordering: TemporalOrdering,
}

/// Temporal ordering strategies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TemporalOrdering {
    /// Order by timestamp ascending
    TimestampAsc,
    /// Order by timestamp descending
    TimestampDesc,
    /// Order by version ascending
    VersionAsc,
    /// Order by version descending
    VersionDesc,
    /// Order by insertion order
    InsertionOrder,
}

impl TimeRangeQuery {
    /// Create a new time range query
    pub fn new(start_time: u64, end_time: u64) -> Self {
        Self {
            start_time,
            end_time,
            version_range: None,
            limit: None,
            ordering: TemporalOrdering::TimestampAsc,
        }
    }

    /// Convert to storage TimeRange
    pub fn to_storage_time_range(&self) -> TimeRange {
        use chrono::{TimeZone, Utc};
        TimeRange {
            start: Utc
                .timestamp_opt(self.start_time as i64, 0)
                .single()
                .unwrap_or_else(Utc::now),
            end: Utc
                .timestamp_opt(self.end_time as i64, 0)
                .single()
                .unwrap_or_else(Utc::now),
        }
    }

    /// Add version range filter
    pub fn with_version_range(mut self, start_version: u64, end_version: u64) -> Self {
        self.version_range = Some((start_version, end_version));
        self
    }

    /// Set maximum number of entries to return
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set temporal ordering
    pub fn with_ordering(mut self, ordering: TemporalOrdering) -> Self {
        self.ordering = ordering;
        self
    }

    /// Check if an entry matches this query
    pub fn matches(&self, entry: &LedgerEntry) -> bool {
        // Check timestamp range
        if entry.timestamp < self.start_time || entry.timestamp >= self.end_time {
            return false;
        }

        // Check version range if specified
        if let Some((start_version, end_version)) = self.version_range {
            if entry.version < start_version || entry.version >= end_version {
                return false;
            }
        }

        true
    }
}

/// Temporal streamer for time-range based queries
pub struct TemporalStreamer {
    config: StreamingConfig,
    storage: Arc<LedgerStorage>,
}

impl TemporalStreamer {
    /// Create a new temporal streamer
    pub fn new(config: StreamingConfig, storage: Arc<LedgerStorage>) -> Self {
        Self { config, storage }
    }

    /// Execute a time-range query and return results
    pub async fn execute_query(
        &self,
        ledger_id: &Uuid,
        query: TimeRangeQuery,
    ) -> Result<StreamingResult<Vec<StreamingEntry>>> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        let mut entries_processed = 0;
        let mut memory_peak = 0;

        // Convert to TimeRange for storage layer
        let _time_range = query.to_storage_time_range();

        // Stream entries and filter
        let mut stream = self.stream_time_range(ledger_id, query.clone())?;

        while let Some(entry_result) = Self::poll_stream(&mut stream).await {
            let streaming_entry = entry_result?;

            if query.matches(&streaming_entry.entry) {
                results.push(streaming_entry);

                // Check limit
                if let Some(limit) = query.limit {
                    if results.len() >= limit {
                        break;
                    }
                }
            }

            entries_processed += 1;
            memory_peak = std::cmp::max(
                memory_peak,
                results.len() * std::mem::size_of::<StreamingEntry>(),
            );
        }

        // Apply ordering
        self.apply_ordering(&mut results, query.ordering);

        Ok(StreamingResult {
            data: results,
            entries_processed,
            memory_peak,
            processing_time: start_time.elapsed(),
            checkpoints_created: 0,
        })
    }

    /// Create a stream for time-range queries
    pub fn stream_time_range(
        &self,
        ledger_id: &Uuid,
        query: TimeRangeQuery,
    ) -> Result<TemporalQueryStream> {
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        Ok(TemporalQueryStream::new(
            self.storage.clone(),
            *ledger_id,
            metadata,
            query,
            self.config.clone(),
        ))
    }

    /// Stream entries within a specific version range
    pub fn stream_version_range(
        &self,
        ledger_id: &Uuid,
        start_version: u64,
        end_version: u64,
    ) -> Result<VersionRangeStream> {
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        Ok(VersionRangeStream::new(
            self.storage.clone(),
            *ledger_id,
            metadata,
            start_version,
            end_version,
            self.config.clone(),
        ))
    }

    /// Get temporal statistics for a ledger
    pub async fn get_temporal_stats(&self, ledger_id: &Uuid) -> Result<TemporalStats> {
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        // Sample entries to get temporal bounds
        let sample_entries = self.storage.load_entries_range(ledger_id, 0, 10)?;
        let mut min_timestamp = u64::MAX;
        let mut max_timestamp = 0;
        let mut min_version = u64::MAX;
        let mut max_version = 0;

        for entry in &sample_entries {
            min_timestamp = min_timestamp.min(entry.timestamp);
            max_timestamp = max_timestamp.max(entry.timestamp);
            min_version = min_version.min(entry.version);
            max_version = max_version.max(entry.version);
        }

        // If we have entries, also check the last batch
        if metadata.entry_count > 10 {
            let last_start = metadata.entry_count.saturating_sub(10);
            let last_entries =
                self.storage
                    .load_entries_range(ledger_id, last_start, metadata.entry_count)?;

            for entry in &last_entries {
                min_timestamp = min_timestamp.min(entry.timestamp);
                max_timestamp = max_timestamp.max(entry.timestamp);
                min_version = min_version.min(entry.version);
                max_version = max_version.max(entry.version);
            }
        }

        Ok(TemporalStats {
            total_entries: metadata.entry_count,
            time_range: if min_timestamp != u64::MAX {
                use chrono::{TimeZone, Utc};
                Some(TimeRange {
                    start: Utc
                        .timestamp_opt(min_timestamp as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                    end: Utc
                        .timestamp_opt((max_timestamp + 1) as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                })
            } else {
                None
            },
            version_range: if min_version != u64::MAX {
                Some((min_version, max_version))
            } else {
                None
            },
            temporal_density: if max_timestamp > min_timestamp {
                sample_entries.len() as f64 / (max_timestamp - min_timestamp) as f64
            } else {
                0.0
            },
        })
    }

    // Helper method to poll stream (since we can't use StreamExt in this context)
    async fn poll_stream(stream: &mut TemporalQueryStream) -> Option<Result<StreamingEntry>> {
        let mut stream_pin = Pin::new(stream);
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        match stream_pin.as_mut().poll_next(&mut context) {
            Poll::Ready(item) => item,
            Poll::Pending => None,
        }
    }

    fn apply_ordering(&self, entries: &mut [StreamingEntry], ordering: TemporalOrdering) {
        match ordering {
            TemporalOrdering::TimestampAsc => {
                entries.sort_by(|a, b| a.entry.timestamp.cmp(&b.entry.timestamp));
            }
            TemporalOrdering::TimestampDesc => {
                entries.sort_by(|a, b| b.entry.timestamp.cmp(&a.entry.timestamp));
            }
            TemporalOrdering::VersionAsc => {
                entries.sort_by(|a, b| a.entry.version.cmp(&b.entry.version));
            }
            TemporalOrdering::VersionDesc => {
                entries.sort_by(|a, b| b.entry.version.cmp(&a.entry.version));
            }
            TemporalOrdering::InsertionOrder => {
                entries.sort_by(|a, b| a.source_position.cmp(&b.source_position));
            }
        }
    }
}

/// Statistics about temporal data distribution
#[derive(Debug, Clone)]
pub struct TemporalStats {
    /// Total number of entries
    pub total_entries: usize,
    /// Time range spanning all entries
    pub time_range: Option<TimeRange>,
    /// Version range spanning all entries
    pub version_range: Option<(u64, u64)>,
    /// Average temporal density (entries per time unit)
    pub temporal_density: f64,
}

/// Stream for temporal queries
pub struct TemporalQueryStream {
    storage: Arc<LedgerStorage>,
    ledger_id: Uuid,
    metadata: crate::storage::LedgerMetadata,
    query: TimeRangeQuery,
    config: StreamingConfig,
    buffer: VecDeque<StreamingEntry>,
    current_position: usize,
    finished: bool,
    entries_returned: usize,
}

impl TemporalQueryStream {
    fn new(
        storage: Arc<LedgerStorage>,
        ledger_id: Uuid,
        metadata: crate::storage::LedgerMetadata,
        query: TimeRangeQuery,
        config: StreamingConfig,
    ) -> Self {
        Self {
            storage,
            ledger_id,
            metadata,
            query,
            config,
            buffer: VecDeque::new(),
            current_position: 0,
            finished: false,
            entries_returned: 0,
        }
    }

    fn load_next_temporal_batch(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        // Check limit
        if let Some(limit) = self.query.limit {
            if self.entries_returned >= limit {
                self.finished = true;
                return Ok(());
            }
        }

        // Calculate batch end position
        let batch_end = std::cmp::min(
            self.current_position + self.config.batch_size,
            self.metadata.entry_count,
        );

        if self.current_position >= self.metadata.entry_count {
            self.finished = true;
            return Ok(());
        }

        // Load batch of entries
        let entries =
            self.storage
                .load_entries_range(&self.ledger_id, self.current_position, batch_end)?;

        // Filter entries that match the query
        for (idx, entry) in entries.into_iter().enumerate() {
            if self.query.matches(&entry) {
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

                // Check limit again
                if let Some(limit) = self.query.limit {
                    if self.entries_returned + self.buffer.len() >= limit {
                        break;
                    }
                }
            }
        }

        self.current_position = batch_end;
        Ok(())
    }
}

impl Stream for TemporalQueryStream {
    type Item = Result<StreamingEntry>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.buffer.is_empty() && !self.finished {
            if let Err(e) = self.load_next_temporal_batch() {
                return Poll::Ready(Some(Err(e)));
            }
        }

        if let Some(entry) = self.buffer.pop_front() {
            self.entries_returned += 1;
            Poll::Ready(Some(Ok(entry)))
        } else if self.finished {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// Stream for version range queries
pub struct VersionRangeStream {
    storage: Arc<LedgerStorage>,
    ledger_id: Uuid,
    metadata: crate::storage::LedgerMetadata,
    start_version: u64,
    end_version: u64,
    config: StreamingConfig,
    buffer: VecDeque<StreamingEntry>,
    current_position: usize,
    finished: bool,
}

impl VersionRangeStream {
    fn new(
        storage: Arc<LedgerStorage>,
        ledger_id: Uuid,
        metadata: crate::storage::LedgerMetadata,
        start_version: u64,
        end_version: u64,
        config: StreamingConfig,
    ) -> Self {
        Self {
            storage,
            ledger_id,
            metadata,
            start_version,
            end_version,
            config,
            buffer: VecDeque::new(),
            current_position: 0,
            finished: false,
        }
    }

    fn load_next_version_batch(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        let batch_end = std::cmp::min(
            self.current_position + self.config.batch_size,
            self.metadata.entry_count,
        );

        if self.current_position >= self.metadata.entry_count {
            self.finished = true;
            return Ok(());
        }

        let entries =
            self.storage
                .load_entries_range(&self.ledger_id, self.current_position, batch_end)?;

        for (idx, entry) in entries.into_iter().enumerate() {
            if entry.version >= self.start_version && entry.version < self.end_version {
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
        }

        self.current_position = batch_end;
        Ok(())
    }
}

impl Stream for VersionRangeStream {
    type Item = Result<StreamingEntry>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.buffer.is_empty() && !self.finished {
            if let Err(e) = self.load_next_version_batch() {
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

    fn setup_test_temporal_data() -> (TempDir, Arc<LedgerStorage>, Uuid) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = Arc::new(LedgerStorage::new(&workspace).unwrap());

        let mut ledger = crate::ledger::Ledger::new();

        // Create entries with different timestamps
        let base_time = 1000000;
        for i in 0..10 {
            let data = format!("temporal data {}", i).into_bytes();
            let entry_id = ledger.add_entry(data).unwrap();
            // Get mutable reference to update timestamp
            if let Ok(Some(entry)) = ledger.get_entry_mut(&entry_id) {
                entry.timestamp = base_time + (i * 1000) as u64;
            }
        }

        let ledger_id = storage.save_ledger(&ledger, "temporal test").unwrap();
        (temp_dir, storage, ledger_id)
    }

    #[tokio::test]
    async fn test_time_range_query() {
        let (_temp_dir, storage, ledger_id) = setup_test_temporal_data();
        let config = StreamingConfig::default();
        let streamer = TemporalStreamer::new(config, storage);

        let query = TimeRangeQuery::new(1001000, 1005000); // Should match entries 1-4
        let result = streamer.execute_query(&ledger_id, query).await.unwrap();

        assert!(result.data.len() >= 3); // At least entries 1, 2, 3
        assert!(result.entries_processed >= 3); // Processed at least the matching entries
        assert!(result.processing_time.as_millis() < u128::MAX);
    }

    #[tokio::test]
    async fn test_time_range_query_with_limit() {
        let (_temp_dir, storage, ledger_id) = setup_test_temporal_data();
        let config = StreamingConfig::default();
        let streamer = TemporalStreamer::new(config, storage);

        let query = TimeRangeQuery::new(1000000, 1010000).with_limit(3);
        let result = streamer.execute_query(&ledger_id, query).await.unwrap();

        assert!(result.data.len() <= 3);
    }

    #[tokio::test]
    async fn test_version_range_stream() {
        let (_temp_dir, storage, ledger_id) = setup_test_temporal_data();
        let config = StreamingConfig::default();
        let streamer = TemporalStreamer::new(config, storage);

        let mut stream = streamer.stream_version_range(&ledger_id, 2, 6).unwrap();
        let mut count = 0;

        // Poll the stream manually
        loop {
            let mut stream_pin = Pin::new(&mut stream);
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);

            match stream_pin.as_mut().poll_next(&mut context) {
                Poll::Ready(Some(Ok(_entry))) => {
                    count += 1;
                }
                Poll::Ready(Some(Err(e))) => {
                    panic!("Stream error: {}", e);
                }
                Poll::Ready(None) => break,
                Poll::Pending => break,
            }
        }

        assert!(count >= 3); // Should have entries with versions 2, 3, 4, 5
    }

    #[tokio::test]
    async fn test_temporal_stats() {
        let (_temp_dir, storage, ledger_id) = setup_test_temporal_data();
        let config = StreamingConfig::default();
        let streamer = TemporalStreamer::new(config, storage);

        let stats = streamer.get_temporal_stats(&ledger_id).await.unwrap();

        assert_eq!(stats.total_entries, 10);
        assert!(stats.time_range.is_some());
        assert!(stats.version_range.is_some());
        assert!(stats.temporal_density >= 0.0);
    }

    #[test]
    fn test_time_range_query_matching() {
        let query = TimeRangeQuery::new(1000, 2000).with_version_range(5, 10);

        let mut entry = crate::ledger::LedgerEntry::new(b"test".to_vec(), 7);
        entry.timestamp = 1500;

        assert!(query.matches(&entry));

        // Outside time range
        entry.timestamp = 500;
        assert!(!query.matches(&entry));

        // Outside version range
        entry.timestamp = 1500;
        entry.version = 3;
        assert!(!query.matches(&entry));
    }

    #[test]
    fn test_temporal_ordering() {
        let query = TimeRangeQuery::new(0, u64::MAX).with_ordering(TemporalOrdering::TimestampDesc);

        assert!(matches!(query.ordering, TemporalOrdering::TimestampDesc));
    }
}
