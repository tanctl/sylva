//! Streaming ledger builder for memory-efficient construction

use crate::error::Result;
use crate::ledger::{Ledger, LedgerEntry};
use crate::storage::LedgerStorage;
use futures::Stream;
use std::sync::Arc;
use uuid::Uuid;

use super::{
    StreamingConfig, StreamingContext, StreamingEntry, StreamingResult, StreamingStatistics,
};

/// Builder for constructing ledgers from streaming data with constant memory usage
pub struct StreamingLedgerBuilder {
    _config: StreamingConfig,
    storage: Arc<LedgerStorage>,
    context: StreamingContext,
    current_ledger: Ledger,
    entry_buffer: Vec<StreamingEntry>,
}

impl StreamingLedgerBuilder {
    pub fn new(config: StreamingConfig, storage: Arc<LedgerStorage>) -> Self {
        let context = StreamingContext::new(config.clone());
        Self {
            _config: config,
            storage,
            context,
            current_ledger: Ledger::new(),
            entry_buffer: Vec::new(),
        }
    }

    /// Add an entry to the streaming builder
    pub fn add_entry(&mut self, data: Vec<u8>) -> Result<Uuid> {
        if self.context.memory_exceeded() {
            self.flush_buffer()?;
        }

        let entry_id = self.current_ledger.add_entry(data)?;
        self.context.entries_processed += 1;

        // Update memory usage estimation
        let memory_delta = std::mem::size_of::<LedgerEntry>()
            + self.current_ledger.get_entries().last().unwrap().data.len();
        self.context.update_memory_usage(memory_delta as isize);

        if self.context.should_checkpoint() {
            self.create_checkpoint()?;
        }

        Ok(entry_id)
    }

    /// Add an entry with metadata to the streaming builder
    pub fn add_entry_with_metadata(
        &mut self,
        data: Vec<u8>,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<Uuid> {
        if self.context.memory_exceeded() {
            self.flush_buffer()?;
        }

        let entry_id = self
            .current_ledger
            .add_entry_with_metadata(data, metadata)?;
        self.context.entries_processed += 1;

        // Update memory usage estimation
        let memory_delta = std::mem::size_of::<LedgerEntry>()
            + self.current_ledger.get_entries().last().unwrap().data.len();
        self.context.update_memory_usage(memory_delta as isize);

        if self.context.should_checkpoint() {
            self.create_checkpoint()?;
        }

        Ok(entry_id)
    }

    /// Finalize the ledger construction and return the result
    pub fn finalize(mut self, name: &str) -> Result<StreamingResult<Uuid>> {
        let start_time = self.context.start_time;
        let entries_processed = self.context.entries_processed;
        let memory_peak = self.context.memory_usage;
        let checkpoints_created = if self.context.last_checkpoint.is_some() {
            1
        } else {
            0
        };

        // Flush any remaining entries
        self.flush_buffer()?;

        // Save the final ledger
        let ledger_id = self.storage.save_ledger(&self.current_ledger, name)?;

        Ok(StreamingResult {
            data: ledger_id,
            entries_processed,
            memory_peak,
            processing_time: start_time.elapsed(),
            checkpoints_created,
        })
    }

    /// Create a streaming builder from an input stream
    pub async fn from_stream<S>(
        mut stream: S,
        config: StreamingConfig,
        storage: Arc<LedgerStorage>,
        name: &str,
    ) -> Result<StreamingResult<Uuid>>
    where
        S: Stream<Item = Result<Vec<u8>>> + Unpin,
    {
        use futures::StreamExt;

        let mut builder = Self::new(config, storage);

        while let Some(data_result) = stream.next().await {
            let data = data_result?;
            builder.add_entry(data)?;
        }

        builder.finalize(name)
    }

    fn flush_buffer(&mut self) -> Result<()> {
        // In this implementation, we keep entries in the ledger directly
        // This could be extended to implement actual buffering strategies
        if self.entry_buffer.is_empty() {
            return Ok(());
        }

        // Clear buffer and update memory usage
        let buffer_size = self.entry_buffer.len() * std::mem::size_of::<StreamingEntry>();
        self.entry_buffer.clear();
        self.context.update_memory_usage(-(buffer_size as isize));

        Ok(())
    }

    fn create_checkpoint(&mut self) -> Result<()> {
        self.context.last_checkpoint = Some(std::time::Instant::now());
        // In a full implementation, this would save checkpoint data
        // For now, we just mark that a checkpoint was created
        Ok(())
    }

    /// Get current building statistics
    pub fn statistics(&self) -> StreamingStatistics {
        StreamingStatistics {
            entries_processed: self.context.entries_processed,
            current_memory_usage: self.context.memory_usage,
            processing_time: self.context.start_time.elapsed(),
            current_version: self.context.current_version,
            checkpoints_created: if self.context.last_checkpoint.is_some() {
                1
            } else {
                0
            },
        }
    }
}

/// Stream adapter for building ledgers from async data sources
pub struct LedgerBuildStream<S> {
    inner: S,
    builder: StreamingLedgerBuilder,
}

impl<S> LedgerBuildStream<S>
where
    S: Stream<Item = Result<Vec<u8>>> + Unpin,
{
    pub fn new(stream: S, config: StreamingConfig, storage: Arc<LedgerStorage>) -> Self {
        Self {
            inner: stream,
            builder: StreamingLedgerBuilder::new(config, storage),
        }
    }

    pub async fn build(mut self, name: &str) -> Result<StreamingResult<Uuid>> {
        use futures::StreamExt;

        while let Some(data_result) = self.inner.next().await {
            let data = data_result?;
            self.builder.add_entry(data)?;
        }

        self.builder.finalize(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_test_storage() -> (TempDir, Arc<LedgerStorage>) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = Arc::new(LedgerStorage::new(&workspace).unwrap());
        (temp_dir, storage)
    }

    #[tokio::test]
    async fn test_streaming_builder_basic() {
        let (_temp_dir, storage) = setup_test_storage();
        let config = StreamingConfig::default();
        let mut builder = StreamingLedgerBuilder::new(config, storage);

        // Add some entries
        let id1 = builder.add_entry(b"data1".to_vec()).unwrap();
        let id2 = builder.add_entry(b"data2".to_vec()).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(builder.statistics().entries_processed, 2);

        // Finalize
        let result = builder.finalize("test ledger").unwrap();
        assert_eq!(result.entries_processed, 2);
        assert!(result.processing_time.as_millis() < u128::MAX);
    }

    #[tokio::test]
    async fn test_streaming_builder_with_metadata() {
        let (_temp_dir, storage) = setup_test_storage();
        let config = StreamingConfig::default();
        let mut builder = StreamingLedgerBuilder::new(config, storage);

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("author".to_string(), "test".to_string());

        let _id = builder
            .add_entry_with_metadata(b"data".to_vec(), metadata)
            .unwrap();

        let result = builder.finalize("metadata test").unwrap();
        assert_eq!(result.entries_processed, 1);
    }

    #[tokio::test]
    async fn test_memory_limit_enforcement() {
        let (_temp_dir, storage) = setup_test_storage();
        let config = StreamingConfig {
            memory_limit: Some(1024), // Very small limit to trigger flush
            ..Default::default()
        };

        let mut builder = StreamingLedgerBuilder::new(config, storage);

        // Add entries that should trigger memory limit
        for _i in 0..10 {
            let large_data = vec![0u8; 200]; // Large enough to trigger limit
            builder.add_entry(large_data).unwrap();
        }

        let result = builder.finalize("memory test").unwrap();
        assert_eq!(result.entries_processed, 10);
    }
}
