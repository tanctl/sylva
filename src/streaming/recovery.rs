//! Error recovery and resumption for interrupted streams

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::{StreamingConfig, StreamingContext, StreamingEntry};

/// Checkpoint data for stream recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCheckpoint {
    /// Unique checkpoint ID
    pub checkpoint_id: Uuid,
    /// Operation ID this checkpoint belongs to
    pub operation_id: String,
    /// Timestamp when checkpoint was created
    pub created_at: u64,
    /// Current stream position
    pub stream_position: usize,
    /// Number of entries processed so far
    pub entries_processed: usize,
    /// Current version being processed
    pub current_version: u64,
    /// Memory usage at checkpoint time
    pub memory_usage: usize,
    /// Streaming configuration
    pub config: StreamingConfig,
    /// Custom recovery metadata
    pub metadata: HashMap<String, String>,
    /// Buffered entries at checkpoint time
    pub buffered_entries: Vec<StreamingEntry>,
    /// Processing phase information
    pub phase_info: PhaseInfo,
}

/// Information about the current processing phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseInfo {
    /// Current phase name
    pub phase_name: String,
    /// Phase-specific state data
    pub phase_state: HashMap<String, String>,
    /// Sub-operations completed in this phase
    pub completed_sub_ops: Vec<String>,
    /// Error information if phase failed
    pub last_error: Option<String>,
}

/// Recovery options for resuming interrupted streams
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Maximum age of checkpoint to consider valid
    pub max_checkpoint_age: Duration,
    /// Whether to skip validation on recovery
    pub skip_validation: bool,
    /// Whether to reset memory counters
    pub reset_memory_counters: bool,
    /// Whether to resume from exact position or nearest safe point
    pub exact_position_recovery: bool,
    /// Custom recovery strategy
    pub recovery_strategy: RecoveryStrategy,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            max_checkpoint_age: Duration::from_secs(24 * 60 * 60),
            skip_validation: false,
            reset_memory_counters: true,
            exact_position_recovery: true,
            recovery_strategy: RecoveryStrategy::FromLastCheckpoint,
        }
    }
}

/// Strategy for recovering from failures
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Resume from the last valid checkpoint
    FromLastCheckpoint,
    /// Resume from a specific checkpoint ID
    FromSpecificCheckpoint(Uuid),
    /// Restart from the beginning with lessons learned
    RestartWithOptimizations,
    /// Resume from the nearest safe point before error
    FromSafePoint,
    // /// Custom recovery logic - disabled due to Clone trait issues
    // Custom(Box<dyn Fn(&StreamCheckpoint) -> Result<usize> + Send + Sync>),
}

/// Recovery manager for streaming operations
pub struct StreamRecovery {
    checkpoint_dir: PathBuf,
    active_operations: HashMap<String, Uuid>, // operation_id -> latest_checkpoint_id
    _cleanup_interval: Duration,
    max_checkpoints_per_operation: usize,
}

impl StreamRecovery {
    /// Create a new stream recovery manager
    pub fn new<P: AsRef<Path>>(checkpoint_dir: P) -> Result<Self> {
        let checkpoint_dir = checkpoint_dir.as_ref().to_path_buf();

        // Ensure checkpoint directory exists
        if !checkpoint_dir.exists() {
            fs::create_dir_all(&checkpoint_dir).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to create checkpoint directory: {}", e),
            })?;
        }

        Ok(Self {
            checkpoint_dir,
            active_operations: HashMap::new(),
            _cleanup_interval: Duration::from_secs(3600), // 1 hour
            max_checkpoints_per_operation: 10,
        })
    }

    /// Create a checkpoint for the current streaming state
    pub fn create_checkpoint(
        &mut self,
        operation_id: &str,
        context: &StreamingContext,
        buffered_entries: Vec<StreamingEntry>,
        phase_info: PhaseInfo,
    ) -> Result<Uuid> {
        let checkpoint_id = Uuid::new_v4();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let checkpoint = StreamCheckpoint {
            checkpoint_id,
            operation_id: operation_id.to_string(),
            created_at: now,
            stream_position: context.current_position,
            entries_processed: context.entries_processed,
            current_version: context.current_version,
            memory_usage: context.memory_usage,
            config: context.config.clone(),
            metadata: HashMap::new(),
            buffered_entries,
            phase_info,
        };

        // Save checkpoint to disk
        self.save_checkpoint(&checkpoint)?;

        // Update active operations
        self.active_operations
            .insert(operation_id.to_string(), checkpoint_id);

        // Cleanup old checkpoints
        self.cleanup_old_checkpoints(operation_id)?;

        Ok(checkpoint_id)
    }

    /// Load a checkpoint by ID
    pub fn load_checkpoint(&self, checkpoint_id: &Uuid) -> Result<StreamCheckpoint> {
        let checkpoint_path = self.checkpoint_file_path(checkpoint_id);

        if !checkpoint_path.exists() {
            return Err(SylvaError::NotFound {
                item_type: "checkpoint".to_string(),
                identifier: checkpoint_id.to_string(),
            });
        }

        let data = fs::read(&checkpoint_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read checkpoint file: {}", e),
        })?;

        let checkpoint: StreamCheckpoint =
            bincode::deserialize(&data).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to deserialize checkpoint: {}", e),
            })?;

        Ok(checkpoint)
    }

    /// Find the latest checkpoint for an operation
    pub fn find_latest_checkpoint(&self, operation_id: &str) -> Result<Option<StreamCheckpoint>> {
        if let Some(checkpoint_id) = self.active_operations.get(operation_id) {
            return Ok(Some(self.load_checkpoint(checkpoint_id)?));
        }

        // Search for checkpoints in directory
        let mut latest_checkpoint = None;
        let mut latest_timestamp = 0;

        for entry in fs::read_dir(&self.checkpoint_dir).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read checkpoint directory: {}", e),
        })? {
            let entry = entry.map_err(|e| SylvaError::StorageError {
                message: format!("Failed to read directory entry: {}", e),
            })?;

            if let Some(filename) = entry.file_name().to_str() {
                if let Some(stripped) = filename.strip_suffix(".checkpoint") {
                    if let Ok(checkpoint_id) = Uuid::parse_str(stripped) {
                        if let Ok(checkpoint) = self.load_checkpoint(&checkpoint_id) {
                            if checkpoint.operation_id == operation_id
                                && checkpoint.created_at > latest_timestamp
                            {
                                latest_timestamp = checkpoint.created_at;
                                latest_checkpoint = Some(checkpoint);
                            }
                        }
                    }
                }
            }
        }

        Ok(latest_checkpoint)
    }

    /// Recover a streaming operation from checkpoint
    pub fn recover_operation(
        &self,
        operation_id: &str,
        options: RecoveryOptions,
    ) -> Result<Option<RecoveryResult>> {
        let checkpoint = match options.recovery_strategy {
            RecoveryStrategy::FromLastCheckpoint => self.find_latest_checkpoint(operation_id)?,
            RecoveryStrategy::FromSpecificCheckpoint(checkpoint_id) => {
                Some(self.load_checkpoint(&checkpoint_id)?)
            }
            RecoveryStrategy::RestartWithOptimizations => {
                // Return None to indicate restart from beginning
                return Ok(None);
            }
            RecoveryStrategy::FromSafePoint => self.find_safe_checkpoint(operation_id, &options)?, // Note: Custom variant was removed due to Clone trait requirements
        };

        if let Some(checkpoint) = checkpoint {
            // Validate checkpoint
            if !options.skip_validation {
                self.validate_checkpoint(&checkpoint, &options)?;
            }

            // Create recovery result
            let mut context = StreamingContext::new(checkpoint.config.clone());
            context.current_position = checkpoint.stream_position;
            context.entries_processed = checkpoint.entries_processed;
            context.current_version = checkpoint.current_version;

            if !options.reset_memory_counters {
                context.memory_usage = checkpoint.memory_usage;
            }

            let recovery_position = if options.exact_position_recovery {
                checkpoint.stream_position
            } else {
                self.find_safe_position(&checkpoint)?
            };

            let recovery_result = RecoveryResult {
                checkpoint_id: checkpoint.checkpoint_id,
                recovered_context: context,
                buffered_entries: checkpoint.buffered_entries,
                phase_info: checkpoint.phase_info,
                recovery_position,
                metadata: checkpoint.metadata,
            };

            Ok(Some(recovery_result))
        } else {
            Ok(None)
        }
    }

    /// List all checkpoints for an operation
    pub fn list_checkpoints(&self, operation_id: &str) -> Result<Vec<StreamCheckpoint>> {
        let mut checkpoints = Vec::new();

        for entry in fs::read_dir(&self.checkpoint_dir).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read checkpoint directory: {}", e),
        })? {
            let entry = entry.map_err(|e| SylvaError::StorageError {
                message: format!("Failed to read directory entry: {}", e),
            })?;

            if let Some(filename) = entry.file_name().to_str() {
                if let Some(stripped) = filename.strip_suffix(".checkpoint") {
                    if let Ok(checkpoint_id) = Uuid::parse_str(stripped) {
                        if let Ok(checkpoint) = self.load_checkpoint(&checkpoint_id) {
                            if checkpoint.operation_id == operation_id {
                                checkpoints.push(checkpoint);
                            }
                        }
                    }
                }
            }
        }

        // Sort by creation time
        checkpoints.sort_by_key(|c| c.created_at);
        Ok(checkpoints)
    }

    /// Delete a specific checkpoint
    pub fn delete_checkpoint(&mut self, checkpoint_id: &Uuid) -> Result<()> {
        let checkpoint_path = self.checkpoint_file_path(checkpoint_id);

        if checkpoint_path.exists() {
            fs::remove_file(&checkpoint_path).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to delete checkpoint file: {}", e),
            })?;
        }

        // Remove from active operations if it was the latest
        self.active_operations.retain(|_, id| id != checkpoint_id);

        Ok(())
    }

    /// Clean up old checkpoints for an operation
    pub fn cleanup_operation(&mut self, operation_id: &str) -> Result<usize> {
        let checkpoints = self.list_checkpoints(operation_id)?;
        let mut deleted_count = 0;

        for checkpoint in checkpoints {
            self.delete_checkpoint(&checkpoint.checkpoint_id)?;
            deleted_count += 1;
        }

        self.active_operations.remove(operation_id);
        Ok(deleted_count)
    }

    /// Validate that a checkpoint is suitable for recovery
    pub fn validate_checkpoint(
        &self,
        checkpoint: &StreamCheckpoint,
        options: &RecoveryOptions,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check checkpoint age
        let checkpoint_age = Duration::from_secs(now.saturating_sub(checkpoint.created_at));
        if checkpoint_age > options.max_checkpoint_age {
            return Err(SylvaError::InvalidOperation {
                message: format!(
                    "Checkpoint is too old: {} > {}",
                    checkpoint_age.as_secs(),
                    options.max_checkpoint_age.as_secs()
                ),
            });
        }

        // Validate checkpoint integrity
        if checkpoint.stream_position > checkpoint.entries_processed {
            return Err(SylvaError::InvalidOperation {
                message: "Checkpoint has invalid stream position".to_string(),
            });
        }

        // Check for errors in last phase
        if let Some(error) = &checkpoint.phase_info.last_error {
            return Err(SylvaError::InvalidOperation {
                message: format!("Checkpoint contains error state: {}", error),
            });
        }

        Ok(())
    }

    // Private helper methods

    fn save_checkpoint(&self, checkpoint: &StreamCheckpoint) -> Result<()> {
        let checkpoint_path = self.checkpoint_file_path(&checkpoint.checkpoint_id);

        let data = bincode::serialize(checkpoint).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to serialize checkpoint: {}", e),
        })?;

        fs::write(&checkpoint_path, data).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to write checkpoint file: {}", e),
        })?;

        Ok(())
    }

    fn checkpoint_file_path(&self, checkpoint_id: &Uuid) -> PathBuf {
        self.checkpoint_dir
            .join(format!("{}.checkpoint", checkpoint_id))
    }

    fn cleanup_old_checkpoints(&mut self, operation_id: &str) -> Result<()> {
        let mut checkpoints = self.list_checkpoints(operation_id)?;

        // Keep only the most recent checkpoints
        if checkpoints.len() > self.max_checkpoints_per_operation {
            checkpoints.sort_by_key(|c| c.created_at);
            let to_delete = checkpoints.len() - self.max_checkpoints_per_operation;

            for checkpoint in checkpoints.iter().take(to_delete) {
                self.delete_checkpoint(&checkpoint.checkpoint_id)?;
            }
        }

        Ok(())
    }

    fn find_safe_checkpoint(
        &self,
        operation_id: &str,
        _options: &RecoveryOptions,
    ) -> Result<Option<StreamCheckpoint>> {
        let checkpoints = self.list_checkpoints(operation_id)?;

        // Find the most recent checkpoint without errors
        for checkpoint in checkpoints.iter().rev() {
            if checkpoint.phase_info.last_error.is_none() {
                return Ok(Some(checkpoint.clone()));
            }
        }

        Ok(None)
    }

    fn find_safe_position(&self, checkpoint: &StreamCheckpoint) -> Result<usize> {
        // For now, return the exact position
        // In a more sophisticated implementation, this could analyze
        // the checkpoint state to find a safer resume point
        Ok(checkpoint.stream_position)
    }
}

/// Result of a recovery operation
#[derive(Debug, Clone)]
pub struct RecoveryResult {
    /// ID of the checkpoint used for recovery
    pub checkpoint_id: Uuid,
    /// Recovered streaming context
    pub recovered_context: StreamingContext,
    /// Entries that were buffered at checkpoint time
    pub buffered_entries: Vec<StreamingEntry>,
    /// Phase information at recovery point
    pub phase_info: PhaseInfo,
    /// Position to resume from
    pub recovery_position: usize,
    /// Custom metadata from checkpoint
    pub metadata: HashMap<String, String>,
}

/// Checkpoint manager for automated checkpoint creation
pub struct CheckpointManager {
    recovery: StreamRecovery,
    auto_checkpoint_interval: Duration,
    last_checkpoint_time: SystemTime,
    checkpoint_triggers: Vec<CheckpointTrigger>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new<P: AsRef<Path>>(
        checkpoint_dir: P,
        auto_checkpoint_interval: Duration,
    ) -> Result<Self> {
        let recovery = StreamRecovery::new(checkpoint_dir)?;

        Ok(Self {
            recovery,
            auto_checkpoint_interval,
            last_checkpoint_time: SystemTime::now(),
            checkpoint_triggers: Vec::new(),
        })
    }

    /// Add a checkpoint trigger
    pub fn add_trigger(&mut self, trigger: CheckpointTrigger) {
        self.checkpoint_triggers.push(trigger);
    }

    /// Check if a checkpoint should be created
    pub fn should_checkpoint(&self, context: &StreamingContext) -> bool {
        // Check time-based trigger
        if self.last_checkpoint_time.elapsed().unwrap_or_default() >= self.auto_checkpoint_interval
        {
            return true;
        }

        // Check custom triggers
        for trigger in &self.checkpoint_triggers {
            if trigger.should_trigger(context) {
                return true;
            }
        }

        false
    }

    /// Get the underlying recovery manager
    pub fn recovery(&mut self) -> &mut StreamRecovery {
        &mut self.recovery
    }
}

/// Trigger conditions for automatic checkpoint creation
#[derive(Debug, Clone)]
pub enum CheckpointTrigger {
    /// Trigger after processing N entries
    EntryCount(usize),
    /// Trigger when memory usage exceeds threshold
    MemoryThreshold(usize),
    /// Trigger at specific phases
    PhaseTransition(Vec<String>),
    /// Custom trigger function
    Custom(fn(&StreamingContext) -> bool),
}

impl CheckpointTrigger {
    fn should_trigger(&self, context: &StreamingContext) -> bool {
        match self {
            CheckpointTrigger::EntryCount(threshold) => {
                context.entries_processed >= *threshold
                    && context.entries_processed % threshold == 0
            }
            CheckpointTrigger::MemoryThreshold(threshold) => context.memory_usage >= *threshold,
            CheckpointTrigger::PhaseTransition(_phases) => {
                // This would need additional context about phase changes
                false
            }
            CheckpointTrigger::Custom(func) => func(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_checkpoint() -> StreamCheckpoint {
        StreamCheckpoint {
            checkpoint_id: Uuid::new_v4(),
            operation_id: "test_operation".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            stream_position: 500,
            entries_processed: 500,
            current_version: 10,
            memory_usage: 1024 * 1024,
            config: StreamingConfig::default(),
            metadata: HashMap::new(),
            buffered_entries: Vec::new(),
            phase_info: PhaseInfo {
                phase_name: "processing".to_string(),
                phase_state: HashMap::new(),
                completed_sub_ops: Vec::new(),
                last_error: None,
            },
        }
    }

    #[test]
    fn test_stream_recovery_creation() {
        let temp_dir = TempDir::new().unwrap();
        let recovery = StreamRecovery::new(temp_dir.path()).unwrap();

        assert!(temp_dir.path().exists());
        assert_eq!(recovery.active_operations.len(), 0);
    }

    #[test]
    fn test_checkpoint_creation_and_loading() {
        let temp_dir = TempDir::new().unwrap();
        let mut recovery = StreamRecovery::new(temp_dir.path()).unwrap();

        let context = StreamingContext::new(StreamingConfig::default());
        let phase_info = PhaseInfo {
            phase_name: "test_phase".to_string(),
            phase_state: HashMap::new(),
            completed_sub_ops: Vec::new(),
            last_error: None,
        };

        let checkpoint_id = recovery
            .create_checkpoint("test_op", &context, Vec::new(), phase_info)
            .unwrap();

        let loaded_checkpoint = recovery.load_checkpoint(&checkpoint_id).unwrap();
        assert_eq!(loaded_checkpoint.operation_id, "test_op");
        assert_eq!(loaded_checkpoint.stream_position, context.current_position);
    }

    #[test]
    fn test_find_latest_checkpoint() {
        let temp_dir = TempDir::new().unwrap();
        let mut recovery = StreamRecovery::new(temp_dir.path()).unwrap();

        let context = StreamingContext::new(StreamingConfig::default());
        let phase_info = PhaseInfo {
            phase_name: "test_phase".to_string(),
            phase_state: HashMap::new(),
            completed_sub_ops: Vec::new(),
            last_error: None,
        };

        // Create multiple checkpoints
        recovery
            .create_checkpoint("test_op", &context, Vec::new(), phase_info.clone())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let latest_id = recovery
            .create_checkpoint("test_op", &context, Vec::new(), phase_info)
            .unwrap();

        let latest_checkpoint = recovery.find_latest_checkpoint("test_op").unwrap().unwrap();
        assert_eq!(latest_checkpoint.checkpoint_id, latest_id);
    }

    #[test]
    fn test_checkpoint_validation() {
        let temp_dir = TempDir::new().unwrap();
        let recovery = StreamRecovery::new(temp_dir.path()).unwrap();

        let checkpoint = create_test_checkpoint();
        let options = RecoveryOptions::default();

        // Should pass validation
        assert!(recovery.validate_checkpoint(&checkpoint, &options).is_ok());

        // Test with old checkpoint
        let mut old_checkpoint = checkpoint.clone();
        old_checkpoint.created_at = 0; // Very old timestamp

        let mut strict_options = options.clone();
        strict_options.max_checkpoint_age = Duration::from_secs(1);

        assert!(recovery
            .validate_checkpoint(&old_checkpoint, &strict_options)
            .is_err());
    }

    #[test]
    fn test_recovery_operation() {
        let temp_dir = TempDir::new().unwrap();
        let mut recovery = StreamRecovery::new(temp_dir.path()).unwrap();

        let context = StreamingContext::new(StreamingConfig::default());
        let phase_info = PhaseInfo {
            phase_name: "test_phase".to_string(),
            phase_state: HashMap::new(),
            completed_sub_ops: Vec::new(),
            last_error: None,
        };

        // Create a checkpoint
        recovery
            .create_checkpoint("test_op", &context, Vec::new(), phase_info)
            .unwrap();

        // Recover the operation
        let options = RecoveryOptions::default();
        let recovery_result = recovery.recover_operation("test_op", options).unwrap();

        assert!(recovery_result.is_some());
        let result = recovery_result.unwrap();
        assert_eq!(result.recovery_position, context.current_position);
    }

    #[test]
    fn test_checkpoint_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let mut recovery = StreamRecovery::new(temp_dir.path()).unwrap();
        recovery.max_checkpoints_per_operation = 2;

        let context = StreamingContext::new(StreamingConfig::default());
        let phase_info = PhaseInfo {
            phase_name: "test_phase".to_string(),
            phase_state: HashMap::new(),
            completed_sub_ops: Vec::new(),
            last_error: None,
        };

        // Create more checkpoints than the limit
        for _ in 0..5 {
            recovery
                .create_checkpoint("test_op", &context, Vec::new(), phase_info.clone())
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let checkpoints = recovery.list_checkpoints("test_op").unwrap();
        assert!(checkpoints.len() <= recovery.max_checkpoints_per_operation);
    }

    #[test]
    fn test_checkpoint_manager() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = CheckpointManager::new(temp_dir.path(), Duration::from_secs(60)).unwrap();

        manager.add_trigger(CheckpointTrigger::EntryCount(1000));
        manager.add_trigger(CheckpointTrigger::MemoryThreshold(1024 * 1024));

        let mut context = StreamingContext::new(StreamingConfig::default());

        // Should not trigger initially
        assert!(!manager.should_checkpoint(&context));

        // Should trigger on entry count
        context.entries_processed = 1000;
        assert!(manager.should_checkpoint(&context));

        // Should trigger on memory threshold
        context.entries_processed = 500;
        context.memory_usage = 2 * 1024 * 1024;
        assert!(manager.should_checkpoint(&context));
    }

    #[test]
    fn test_checkpoint_triggers() {
        let context = StreamingContext::new(StreamingConfig::default());

        let entry_trigger = CheckpointTrigger::EntryCount(100);
        let memory_trigger = CheckpointTrigger::MemoryThreshold(1024);
        let custom_trigger = CheckpointTrigger::Custom(|ctx| ctx.current_version > 5);

        // Test triggers with different contexts
        let mut test_context = context.clone();
        test_context.entries_processed = 100;
        assert!(entry_trigger.should_trigger(&test_context));

        test_context.memory_usage = 2048;
        assert!(memory_trigger.should_trigger(&test_context));

        test_context.current_version = 10;
        assert!(custom_trigger.should_trigger(&test_context));
    }

    #[test]
    fn test_phase_info_serialization() {
        let phase_info = PhaseInfo {
            phase_name: "processing".to_string(),
            phase_state: {
                let mut state = HashMap::new();
                state.insert("current_batch".to_string(), "5".to_string());
                state
            },
            completed_sub_ops: vec!["load_data".to_string(), "validate".to_string()],
            last_error: Some("Network timeout".to_string()),
        };

        let serialized = serde_json::to_string(&phase_info).unwrap();
        let deserialized: PhaseInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.phase_name, phase_info.phase_name);
        assert_eq!(deserialized.phase_state, phase_info.phase_state);
        assert_eq!(deserialized.completed_sub_ops, phase_info.completed_sub_ops);
        assert_eq!(deserialized.last_error, phase_info.last_error);
    }
}
