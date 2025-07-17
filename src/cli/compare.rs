//! Git-like ledger comparison and merging functionality for versioned data

use crate::error::{Result, SylvaError};
use crate::ledger::{Ledger, LedgerEntry};
use crate::storage::{LedgerMetadata, LedgerStorage};
use crate::workspace::Workspace;
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use uuid::Uuid;

/// Ledger comparison and merge commands
#[derive(Subcommand)]
pub enum CompareCommand {
    /// Compare two ledgers and show differences
    Diff(DiffArgs),
    /// Merge two ledgers using specified strategy
    Merge(MergeArgs),
    /// Show merge status and conflicts
    Status(StatusArgs),
    /// Validate a merge result
    Validate(ValidateArgs),
    /// Rollback a merge operation
    Rollback(RollbackArgs),
}

/// Arguments for diff command
#[derive(Args)]
pub struct DiffArgs {
    /// First ledger ID to compare
    pub ledger_a: String,
    /// Second ledger ID to compare
    pub ledger_b: String,
    /// Show detailed temporal changes
    #[arg(long)]
    pub temporal: bool,
    /// Show only summary statistics
    #[arg(long)]
    pub summary: bool,
    /// Output format (text, json, csv)
    #[arg(long, default_value = "text")]
    pub format: String,
    /// Include entry content in diff
    #[arg(long)]
    pub content: bool,
    /// Version range to compare (format: start..end)
    #[arg(long)]
    pub version_range: Option<String>,
}

/// Arguments for merge command
#[derive(Args)]
pub struct MergeArgs {
    /// Source ledger ID to merge from
    pub source: String,
    /// Target ledger ID to merge into
    pub target: String,
    /// Output ledger name for merge result
    pub output: String,
    /// Merge strategy to use
    #[arg(long, default_value = "timestamp")]
    pub strategy: String,
    /// Dry run - show what would be merged without executing
    #[arg(long)]
    pub dry_run: bool,
    /// Force merge even with conflicts
    #[arg(long)]
    pub force: bool,
    /// Manual conflict resolution file
    #[arg(long)]
    pub resolution_file: Option<PathBuf>,
}

/// Arguments for status command
#[derive(Args)]
pub struct StatusArgs {
    /// Ledger ID to check merge status
    pub ledger_id: String,
}

/// Arguments for validate command
#[derive(Args)]
pub struct ValidateArgs {
    /// Ledger ID to validate
    pub ledger_id: String,
    /// Strict validation mode
    #[arg(long)]
    pub strict: bool,
}

/// Arguments for rollback command
#[derive(Args)]
pub struct RollbackArgs {
    /// Ledger ID to rollback
    pub ledger_id: String,
    /// Version to rollback to
    pub target_version: u64,
    /// Confirm rollback operation
    #[arg(long)]
    pub confirm: bool,
}

/// Ledger comparison result showing differences between two ledgers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerDiff {
    /// Source ledger metadata
    pub source_metadata: LedgerMetadata,
    /// Target ledger metadata
    pub target_metadata: LedgerMetadata,
    /// Entries added in target ledger
    pub added_entries: Vec<EntryDiff>,
    /// Entries removed from source ledger
    pub removed_entries: Vec<EntryDiff>,
    /// Entries modified between ledgers
    pub modified_entries: Vec<EntryModification>,
    /// Temporal changes detected
    pub temporal_changes: Vec<TemporalChange>,
    /// Diff statistics
    pub statistics: DiffStatistics,
}

/// Difference for a single entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryDiff {
    /// Entry ID
    pub entry_id: Uuid,
    /// Entry version
    pub version: u64,
    /// Entry timestamp
    pub timestamp: u64,
    /// Entry content (if included)
    pub content: Option<Vec<u8>>,
    /// Entry metadata
    pub metadata: HashMap<String, String>,
    /// Position in ledger
    pub position: usize,
}

/// Modification between two versions of an entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryModification {
    /// Entry ID
    pub entry_id: Uuid,
    /// Original entry state
    pub original: EntryDiff,
    /// Modified entry state
    pub modified: EntryDiff,
    /// Type of modification
    pub modification_type: ModificationType,
    /// Detailed changes
    pub changes: Vec<FieldChange>,
}

/// Type of modification detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModificationType {
    /// Content changed
    ContentChange,
    /// Metadata changed
    MetadataChange,
    /// Timestamp changed
    TimestampChange,
    /// Version changed
    VersionChange,
    /// Multiple changes
    MultipleChanges,
}

/// Field-level change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Field name
    pub field: String,
    /// Original value
    pub old_value: Option<String>,
    /// New value
    pub new_value: Option<String>,
    /// Change type
    pub change_type: ChangeType,
}

/// Type of field change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    /// Field added
    Added,
    /// Field removed
    Removed,
    /// Field modified
    Modified,
}

/// Temporal change detected in ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalChange {
    /// Change ID
    pub change_id: Uuid,
    /// Type of temporal change
    pub change_type: TemporalChangeType,
    /// Affected entry IDs
    pub affected_entries: Vec<Uuid>,
    /// Timestamp of change
    pub change_timestamp: u64,
    /// Description of change
    pub description: String,
    /// Severity level
    pub severity: TemporalSeverity,
}

/// Type of temporal change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalChangeType {
    /// Entry reordered in time
    Reordering,
    /// Timeline fork detected
    Fork,
    /// Temporal gap introduced
    Gap,
    /// Timestamp conflict
    Conflict,
    /// Version inconsistency
    VersionInconsistency,
}

/// Severity of temporal change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalSeverity {
    /// Low impact
    Low,
    /// Medium impact
    Medium,
    /// High impact - requires attention
    High,
    /// Critical - may break temporal integrity
    Critical,
}

/// Statistics about the diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffStatistics {
    /// Total entries in source ledger
    pub source_entries: usize,
    /// Total entries in target ledger
    pub target_entries: usize,
    /// Number of added entries
    pub added_count: usize,
    /// Number of removed entries
    pub removed_count: usize,
    /// Number of modified entries
    pub modified_count: usize,
    /// Number of temporal changes
    pub temporal_changes_count: usize,
    /// Similarity percentage (0-100)
    pub similarity_percentage: f64,
}

/// Ledger merge result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResult {
    /// Merge ID for tracking
    pub merge_id: Uuid,
    /// Source ledger ID
    pub source_ledger: Uuid,
    /// Target ledger ID
    pub target_ledger: Uuid,
    /// Result ledger ID
    pub result_ledger: Uuid,
    /// Merge strategy used
    pub strategy: MergeStrategy,
    /// Merge conflicts encountered
    pub conflicts: Vec<MergeConflict>,
    /// Merge statistics
    pub statistics: MergeStatistics,
    /// Merge timestamp
    pub merge_timestamp: u64,
    /// Validation result
    pub validation: MergeValidation,
}

/// Merge strategy for resolving conflicts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Use timestamp to resolve conflicts (earliest wins)
    TimestampBased,
    /// Last writer wins (latest version wins)
    LastWriterWins,
    /// Manual resolution using provided rules
    ManualResolution(HashMap<String, ResolutionRule>),
    /// Interactive resolution (prompt user)
    Interactive,
    /// Fail on any conflict
    FailOnConflict,
}

/// Resolution rule for manual conflict resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionRule {
    /// Use source entry
    UseSource,
    /// Use target entry
    UseTarget,
    /// Create custom entry with specific values
    Custom(HashMap<String, String>),
    /// Skip conflicting entry
    Skip,
}

/// Merge conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeConflict {
    /// Conflict ID
    pub conflict_id: Uuid,
    /// Type of conflict
    pub conflict_type: ConflictType,
    /// Source entry involved in conflict
    pub source_entry: Option<EntryDiff>,
    /// Target entry involved in conflict
    pub target_entry: Option<EntryDiff>,
    /// Resolution applied
    pub resolution: Option<ConflictResolution>,
    /// Description of conflict
    pub description: String,
}

/// Type of merge conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    /// Same entry ID with different content
    ContentConflict,
    /// Same entry ID with different timestamps
    TimestampConflict,
    /// Version ordering conflict
    VersionConflict,
    /// Metadata conflict
    MetadataConflict,
    /// Temporal ordering conflict
    TemporalConflict,
}

/// Resolution applied to a conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolution {
    /// Resolution strategy used
    pub strategy: ResolutionRule,
    /// Resulting entry
    pub resolved_entry: Option<EntryDiff>,
    /// Resolution timestamp
    pub resolution_timestamp: u64,
}

/// Statistics about merge operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeStatistics {
    /// Total entries merged
    pub total_entries: usize,
    /// Entries from source
    pub source_entries: usize,
    /// Entries from target
    pub target_entries: usize,
    /// Conflicts encountered
    pub conflicts_count: usize,
    /// Conflicts resolved automatically
    pub auto_resolved_count: usize,
    /// Conflicts requiring manual resolution
    pub manual_resolution_count: usize,
    /// Processing time
    pub processing_time_ms: u64,
}

/// Merge validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeValidation {
    /// Validation passed
    pub is_valid: bool,
    /// Temporal integrity maintained
    pub temporal_integrity: bool,
    /// Version consistency maintained
    pub version_consistency: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

/// Main compare functionality handler
pub struct CompareHandler {
    storage: LedgerStorage,
}

impl CompareHandler {
    /// Create a new compare handler
    pub fn new(workspace: Workspace) -> Result<Self> {
        let storage = LedgerStorage::new(&workspace)?;
        Ok(Self { storage })
    }

    /// Execute compare command
    pub fn execute(&self, command: CompareCommand) -> Result<()> {
        match command {
            CompareCommand::Diff(args) => self.handle_diff(args),
            CompareCommand::Merge(args) => self.handle_merge(args),
            CompareCommand::Status(args) => self.handle_status(args),
            CompareCommand::Validate(args) => self.handle_validate(args),
            CompareCommand::Rollback(args) => self.handle_rollback(args),
        }
    }

    /// Handle diff command
    fn handle_diff(&self, args: DiffArgs) -> Result<()> {
        let ledger_a_id =
            Uuid::parse_str(&args.ledger_a).map_err(|_| SylvaError::InvalidInput {
                message: "Invalid ledger A ID format".to_string(),
            })?;

        let ledger_b_id =
            Uuid::parse_str(&args.ledger_b).map_err(|_| SylvaError::InvalidInput {
                message: "Invalid ledger B ID format".to_string(),
            })?;

        // Load ledgers
        let ledger_a = self.storage.load_ledger(&ledger_a_id)?;
        let ledger_b = self.storage.load_ledger(&ledger_b_id)?;

        // Parse version range if provided
        let version_range = if let Some(range_str) = args.version_range {
            Some(self.parse_version_range(&range_str)?)
        } else {
            None
        };

        // Compute diff
        let diff = self.compute_diff(
            &ledger_a.ledger,
            &ledger_b.ledger,
            &ledger_a.metadata,
            &ledger_b.metadata,
            args.temporal,
            args.content,
            version_range,
        )?;

        // Output results
        self.output_diff(&diff, &args.format, args.summary)?;

        Ok(())
    }

    /// Handle merge command
    fn handle_merge(&self, args: MergeArgs) -> Result<()> {
        let source_id = Uuid::parse_str(&args.source).map_err(|_| SylvaError::InvalidInput {
            message: "Invalid source ledger ID format".to_string(),
        })?;

        let target_id = Uuid::parse_str(&args.target).map_err(|_| SylvaError::InvalidInput {
            message: "Invalid target ledger ID format".to_string(),
        })?;

        // Load ledgers
        let source_ledger = self.storage.load_ledger(&source_id)?;
        let target_ledger = self.storage.load_ledger(&target_id)?;

        // Parse merge strategy
        let strategy = self.parse_merge_strategy(&args.strategy, &args.resolution_file)?;

        // Perform merge
        let merge_result = self.merge_ledgers(
            &source_ledger.ledger,
            &target_ledger.ledger,
            &source_ledger.metadata,
            &target_ledger.metadata,
            strategy,
            args.force,
        )?;

        if args.dry_run {
            println!("Dry run - merge would produce:");
            self.output_merge_preview(&merge_result)?;
        } else {
            // Save merged ledger
            let result_ledger = self.create_merged_ledger(&merge_result)?;
            let result_id = self.storage.save_ledger(&result_ledger, &args.output)?;

            println!("Merge completed successfully!");
            println!("Result ledger ID: {}", result_id);
            self.output_merge_summary(&merge_result)?;
        }

        Ok(())
    }

    /// Handle status command
    fn handle_status(&self, args: StatusArgs) -> Result<()> {
        let ledger_id = Uuid::parse_str(&args.ledger_id).map_err(|_| SylvaError::InvalidInput {
            message: "Invalid ledger ID format".to_string(),
        })?;

        let ledger = self.storage.load_ledger(&ledger_id)?;
        self.output_ledger_status(&ledger.ledger, &ledger.metadata)?;

        Ok(())
    }

    /// Handle validate command
    fn handle_validate(&self, args: ValidateArgs) -> Result<()> {
        let ledger_id = Uuid::parse_str(&args.ledger_id).map_err(|_| SylvaError::InvalidInput {
            message: "Invalid ledger ID format".to_string(),
        })?;

        let ledger = self.storage.load_ledger(&ledger_id)?;
        let validation = self.validate_ledger(&ledger.ledger, args.strict)?;

        self.output_validation_result(&validation)?;

        if !validation.is_valid {
            return Err(SylvaError::ValidationError {
                message: "Ledger validation failed".to_string(),
            });
        }

        Ok(())
    }

    /// Handle rollback command
    fn handle_rollback(&self, args: RollbackArgs) -> Result<()> {
        let ledger_id = Uuid::parse_str(&args.ledger_id).map_err(|_| SylvaError::InvalidInput {
            message: "Invalid ledger ID format".to_string(),
        })?;

        if !args.confirm {
            return Err(SylvaError::InvalidInput {
                message: "Rollback requires --confirm flag for safety".to_string(),
            });
        }

        let rollback_result = self.rollback_ledger(&ledger_id, args.target_version)?;
        println!("Rollback completed: {}", rollback_result);

        Ok(())
    }

    /// Compute diff between two ledgers
    #[allow(clippy::too_many_arguments)]
    pub fn compute_diff(
        &self,
        ledger_a: &Ledger,
        ledger_b: &Ledger,
        metadata_a: &LedgerMetadata,
        metadata_b: &LedgerMetadata,
        include_temporal: bool,
        include_content: bool,
        version_range: Option<(u64, u64)>,
    ) -> Result<LedgerDiff> {
        let entries_a = self.filter_entries_by_version(ledger_a.get_entries(), version_range);
        let entries_b = self.filter_entries_by_version(ledger_b.get_entries(), version_range);

        // Create maps for efficient lookup
        let map_a: HashMap<Uuid, &LedgerEntry> =
            entries_a.iter().map(|entry| (entry.id, *entry)).collect();
        let map_b: HashMap<Uuid, &LedgerEntry> =
            entries_b.iter().map(|entry| (entry.id, *entry)).collect();

        let mut added_entries = Vec::new();
        let mut removed_entries = Vec::new();
        let mut modified_entries = Vec::new();

        // Find added entries (in B but not in A)
        for entry in &entries_b {
            if !map_a.contains_key(&entry.id) {
                added_entries.push(self.create_entry_diff(
                    entry,
                    include_content,
                    entries_b.iter().position(|e| e.id == entry.id).unwrap(),
                ));
            }
        }

        // Find removed entries (in A but not in B)
        for entry in &entries_a {
            if !map_b.contains_key(&entry.id) {
                removed_entries.push(self.create_entry_diff(
                    entry,
                    include_content,
                    entries_a.iter().position(|e| e.id == entry.id).unwrap(),
                ));
            }
        }

        // Find modified entries (in both but different)
        for entry_a in &entries_a {
            if let Some(entry_b) = map_b.get(&entry_a.id) {
                if let Some(modification) =
                    self.compare_entries(entry_a, entry_b, include_content)?
                {
                    modified_entries.push(modification);
                }
            }
        }

        // Detect temporal changes if requested
        let temporal_changes = if include_temporal {
            self.detect_temporal_changes(&entries_a, &entries_b)?
        } else {
            Vec::new()
        };

        // Calculate statistics
        let statistics = DiffStatistics {
            source_entries: entries_a.len(),
            target_entries: entries_b.len(),
            added_count: added_entries.len(),
            removed_count: removed_entries.len(),
            modified_count: modified_entries.len(),
            temporal_changes_count: temporal_changes.len(),
            similarity_percentage: self.calculate_similarity(&entries_a, &entries_b),
        };

        Ok(LedgerDiff {
            source_metadata: metadata_a.clone(),
            target_metadata: metadata_b.clone(),
            added_entries,
            removed_entries,
            modified_entries,
            temporal_changes,
            statistics,
        })
    }

    /// Parse version range string (format: "start..end")
    fn parse_version_range(&self, range_str: &str) -> Result<(u64, u64)> {
        let parts: Vec<&str> = range_str.split("..").collect();
        if parts.len() != 2 {
            return Err(SylvaError::InvalidInput {
                message: "Version range must be in format 'start..end'".to_string(),
            });
        }

        let start = parts[0]
            .parse::<u64>()
            .map_err(|_| SylvaError::InvalidInput {
                message: "Invalid start version".to_string(),
            })?;

        let end = parts[1]
            .parse::<u64>()
            .map_err(|_| SylvaError::InvalidInput {
                message: "Invalid end version".to_string(),
            })?;

        if start >= end {
            return Err(SylvaError::InvalidInput {
                message: "Start version must be less than end version".to_string(),
            });
        }

        Ok((start, end))
    }

    /// Filter entries by version range
    fn filter_entries_by_version<'a>(
        &self,
        entries: &'a [LedgerEntry],
        version_range: Option<(u64, u64)>,
    ) -> Vec<&'a LedgerEntry> {
        match version_range {
            Some((start, end)) => entries
                .iter()
                .filter(|entry| entry.version >= start && entry.version < end)
                .collect(),
            None => entries.iter().collect(),
        }
    }

    /// Create EntryDiff from LedgerEntry
    fn create_entry_diff(
        &self,
        entry: &LedgerEntry,
        include_content: bool,
        position: usize,
    ) -> EntryDiff {
        EntryDiff {
            entry_id: entry.id,
            version: entry.version,
            timestamp: entry.timestamp,
            content: if include_content {
                Some(entry.data.clone())
            } else {
                None
            },
            metadata: entry.metadata.clone(),
            position,
        }
    }

    /// Compare two entries and return modification if different
    fn compare_entries(
        &self,
        entry_a: &LedgerEntry,
        entry_b: &LedgerEntry,
        include_content: bool,
    ) -> Result<Option<EntryModification>> {
        let mut changes = Vec::new();
        let mut modification_types = Vec::new();

        // Compare content
        if entry_a.data != entry_b.data {
            changes.push(FieldChange {
                field: "content".to_string(),
                old_value: if include_content {
                    Some(hex::encode(&entry_a.data))
                } else {
                    Some("...".to_string())
                },
                new_value: if include_content {
                    Some(hex::encode(&entry_b.data))
                } else {
                    Some("...".to_string())
                },
                change_type: ChangeType::Modified,
            });
            modification_types.push(ModificationType::ContentChange);
        }

        // Compare timestamps
        if entry_a.timestamp != entry_b.timestamp {
            changes.push(FieldChange {
                field: "timestamp".to_string(),
                old_value: Some(entry_a.timestamp.to_string()),
                new_value: Some(entry_b.timestamp.to_string()),
                change_type: ChangeType::Modified,
            });
            modification_types.push(ModificationType::TimestampChange);
        }

        // Compare versions
        if entry_a.version != entry_b.version {
            changes.push(FieldChange {
                field: "version".to_string(),
                old_value: Some(entry_a.version.to_string()),
                new_value: Some(entry_b.version.to_string()),
                change_type: ChangeType::Modified,
            });
            modification_types.push(ModificationType::VersionChange);
        }

        // Compare metadata
        let metadata_changes = self.compare_metadata(&entry_a.metadata, &entry_b.metadata);
        if !metadata_changes.is_empty() {
            changes.extend(metadata_changes);
            modification_types.push(ModificationType::MetadataChange);
        }

        if changes.is_empty() {
            return Ok(None);
        }

        let modification_type = if modification_types.len() > 1 {
            ModificationType::MultipleChanges
        } else {
            modification_types.into_iter().next().unwrap()
        };

        Ok(Some(EntryModification {
            entry_id: entry_a.id,
            original: self.create_entry_diff(entry_a, include_content, 0),
            modified: self.create_entry_diff(entry_b, include_content, 0),
            modification_type,
            changes,
        }))
    }

    /// Compare metadata maps
    fn compare_metadata(
        &self,
        meta_a: &HashMap<String, String>,
        meta_b: &HashMap<String, String>,
    ) -> Vec<FieldChange> {
        let mut changes = Vec::new();
        let all_keys: HashSet<String> = meta_a.keys().chain(meta_b.keys()).cloned().collect();

        for key in all_keys {
            match (meta_a.get(&key), meta_b.get(&key)) {
                (Some(old_val), Some(new_val)) if old_val != new_val => {
                    changes.push(FieldChange {
                        field: format!("metadata.{}", key),
                        old_value: Some(old_val.clone()),
                        new_value: Some(new_val.clone()),
                        change_type: ChangeType::Modified,
                    });
                }
                (Some(old_val), None) => {
                    changes.push(FieldChange {
                        field: format!("metadata.{}", key),
                        old_value: Some(old_val.clone()),
                        new_value: None,
                        change_type: ChangeType::Removed,
                    });
                }
                (None, Some(new_val)) => {
                    changes.push(FieldChange {
                        field: format!("metadata.{}", key),
                        old_value: None,
                        new_value: Some(new_val.clone()),
                        change_type: ChangeType::Added,
                    });
                }
                _ => {} // No change
            }
        }

        changes
    }

    /// Detect temporal changes between ledgers
    fn detect_temporal_changes(
        &self,
        entries_a: &[&LedgerEntry],
        entries_b: &[&LedgerEntry],
    ) -> Result<Vec<TemporalChange>> {
        let mut temporal_changes = Vec::new();

        // Sort entries by timestamp for temporal analysis
        let mut sorted_a = entries_a.to_vec();
        let mut sorted_b = entries_b.to_vec();
        sorted_a.sort_by_key(|e| e.timestamp);
        sorted_b.sort_by_key(|e| e.timestamp);

        // Detect reordering
        temporal_changes.extend(self.detect_reordering(&sorted_a, &sorted_b)?);

        // Detect temporal gaps
        temporal_changes.extend(self.detect_temporal_gaps(&sorted_a, &sorted_b)?);

        // Detect timestamp conflicts
        temporal_changes.extend(self.detect_timestamp_conflicts(&sorted_a, &sorted_b)?);

        Ok(temporal_changes)
    }

    /// Detect entry reordering between ledgers
    fn detect_reordering(
        &self,
        entries_a: &[&LedgerEntry],
        entries_b: &[&LedgerEntry],
    ) -> Result<Vec<TemporalChange>> {
        let mut changes = Vec::new();

        // Create position maps
        let pos_a: HashMap<Uuid, usize> = entries_a
            .iter()
            .enumerate()
            .map(|(i, entry)| (entry.id, i))
            .collect();

        let pos_b: HashMap<Uuid, usize> = entries_b
            .iter()
            .enumerate()
            .map(|(i, entry)| (entry.id, i))
            .collect();

        // Find entries that changed relative position significantly
        for (id, &pos_a_val) in &pos_a {
            if let Some(&pos_b_val) = pos_b.get(id) {
                let position_change = (pos_a_val as i64 - pos_b_val as i64).abs();
                if position_change > 5 {
                    // Threshold for significant reordering
                    changes.push(TemporalChange {
                        change_id: Uuid::new_v4(),
                        change_type: TemporalChangeType::Reordering,
                        affected_entries: vec![*id],
                        change_timestamp: chrono::Utc::now().timestamp() as u64,
                        description: format!(
                            "Entry moved from position {} to {}",
                            pos_a_val, pos_b_val
                        ),
                        severity: if position_change > 20 {
                            TemporalSeverity::High
                        } else {
                            TemporalSeverity::Medium
                        },
                    });
                }
            }
        }

        Ok(changes)
    }

    /// Detect temporal gaps
    fn detect_temporal_gaps(
        &self,
        entries_a: &[&LedgerEntry],
        entries_b: &[&LedgerEntry],
    ) -> Result<Vec<TemporalChange>> {
        let mut changes = Vec::new();

        // Analyze timestamp distributions
        let timestamps_a: Vec<u64> = entries_a.iter().map(|e| e.timestamp).collect();
        let timestamps_b: Vec<u64> = entries_b.iter().map(|e| e.timestamp).collect();

        let avg_gap_a = self.calculate_average_gap(&timestamps_a);
        let avg_gap_b = self.calculate_average_gap(&timestamps_b);

        // Detect significant changes in temporal density
        if (avg_gap_a as f64 - avg_gap_b as f64).abs() > avg_gap_a as f64 * 0.5 {
            changes.push(TemporalChange {
                change_id: Uuid::new_v4(),
                change_type: TemporalChangeType::Gap,
                affected_entries: entries_b.iter().map(|e| e.id).collect(),
                change_timestamp: chrono::Utc::now().timestamp() as u64,
                description: format!(
                    "Temporal density changed: {} -> {} avg gap",
                    avg_gap_a, avg_gap_b
                ),
                severity: TemporalSeverity::Medium,
            });
        }

        Ok(changes)
    }

    /// Detect timestamp conflicts
    fn detect_timestamp_conflicts(
        &self,
        entries_a: &[&LedgerEntry],
        entries_b: &[&LedgerEntry],
    ) -> Result<Vec<TemporalChange>> {
        let mut changes = Vec::new();

        // Find entries with same timestamp in each ledger
        let mut timestamp_groups_a: HashMap<u64, Vec<Uuid>> = HashMap::new();
        let mut timestamp_groups_b: HashMap<u64, Vec<Uuid>> = HashMap::new();

        for entry in entries_a {
            timestamp_groups_a
                .entry(entry.timestamp)
                .or_default()
                .push(entry.id);
        }

        for entry in entries_b {
            timestamp_groups_b
                .entry(entry.timestamp)
                .or_default()
                .push(entry.id);
        }

        // Detect conflicts where timestamp groups changed significantly
        for (&timestamp, ids_b) in &timestamp_groups_b {
            if let Some(ids_a) = timestamp_groups_a.get(&timestamp) {
                if ids_a.len() != ids_b.len() || !ids_a.iter().all(|id| ids_b.contains(id)) {
                    changes.push(TemporalChange {
                        change_id: Uuid::new_v4(),
                        change_type: TemporalChangeType::Conflict,
                        affected_entries: ids_b.clone(),
                        change_timestamp: timestamp,
                        description: format!(
                            "Timestamp conflict at {}: {} entries changed",
                            timestamp,
                            ids_b.len()
                        ),
                        severity: TemporalSeverity::High,
                    });
                }
            }
        }

        Ok(changes)
    }

    /// Calculate average gap between timestamps
    fn calculate_average_gap(&self, timestamps: &[u64]) -> u64 {
        if timestamps.len() < 2 {
            return 0;
        }

        let mut gaps = Vec::new();
        for window in timestamps.windows(2) {
            gaps.push(window[1] - window[0]);
        }

        gaps.iter().sum::<u64>() / gaps.len() as u64
    }

    /// Calculate similarity percentage between two sets of entries
    fn calculate_similarity(&self, entries_a: &[&LedgerEntry], entries_b: &[&LedgerEntry]) -> f64 {
        let ids_a: HashSet<Uuid> = entries_a.iter().map(|e| e.id).collect();
        let ids_b: HashSet<Uuid> = entries_b.iter().map(|e| e.id).collect();

        let intersection = ids_a.intersection(&ids_b).count();
        let union = ids_a.union(&ids_b).count();

        if union == 0 {
            100.0
        } else {
            (intersection as f64 / union as f64) * 100.0
        }
    }

    /// Parse merge strategy from string
    fn parse_merge_strategy(
        &self,
        strategy_str: &str,
        resolution_file: &Option<PathBuf>,
    ) -> Result<MergeStrategy> {
        match strategy_str.to_lowercase().as_str() {
            "timestamp" => Ok(MergeStrategy::TimestampBased),
            "last-writer-wins" | "lww" => Ok(MergeStrategy::LastWriterWins),
            "manual" => {
                if let Some(file_path) = resolution_file {
                    let rules = self.load_resolution_rules(file_path)?;
                    Ok(MergeStrategy::ManualResolution(rules))
                } else {
                    Err(SylvaError::InvalidInput {
                        message: "Manual merge strategy requires resolution file".to_string(),
                    })
                }
            }
            "interactive" => Ok(MergeStrategy::Interactive),
            "fail-on-conflict" => Ok(MergeStrategy::FailOnConflict),
            _ => Err(SylvaError::InvalidInput {
                message: format!("Unknown merge strategy: {}", strategy_str),
            }),
        }
    }

    /// Load resolution rules from file
    fn load_resolution_rules(
        &self,
        file_path: &PathBuf,
    ) -> Result<HashMap<String, ResolutionRule>> {
        let content = std::fs::read_to_string(file_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read resolution file: {}", e),
        })?;

        let rules: HashMap<String, ResolutionRule> =
            serde_json::from_str(&content).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to parse resolution file: {}", e),
            })?;

        Ok(rules)
    }

    /// Merge two ledgers using specified strategy
    pub fn merge_ledgers(
        &self,
        source: &Ledger,
        target: &Ledger,
        source_metadata: &LedgerMetadata,
        target_metadata: &LedgerMetadata,
        strategy: MergeStrategy,
        force: bool,
    ) -> Result<MergeResult> {
        let merge_id = Uuid::new_v4();
        let merge_timestamp = chrono::Utc::now().timestamp() as u64;

        let source_entries = source.get_entries();
        let target_entries = target.get_entries();

        // Create entry maps for efficient lookup
        let source_map: HashMap<Uuid, &LedgerEntry> = source_entries
            .iter()
            .map(|entry| (entry.id, entry))
            .collect();
        let target_map: HashMap<Uuid, &LedgerEntry> = target_entries
            .iter()
            .map(|entry| (entry.id, entry))
            .collect();

        let mut conflicts = Vec::new();
        let mut merged_entries = HashMap::new();

        // Process all unique entry IDs
        let all_ids: HashSet<Uuid> = source_map
            .keys()
            .chain(target_map.keys())
            .cloned()
            .collect();

        let start_time = std::time::Instant::now();

        for entry_id in all_ids {
            match (source_map.get(&entry_id), target_map.get(&entry_id)) {
                (Some(source_entry), Some(target_entry)) => {
                    // Conflict resolution needed
                    match self.resolve_conflict(source_entry, target_entry, &strategy, force)? {
                        Ok(resolved_entry) => {
                            merged_entries.insert(entry_id, resolved_entry);
                        }
                        Err(conflict) => {
                            conflicts.push(conflict);
                            if !force && matches!(strategy, MergeStrategy::FailOnConflict) {
                                return Err(SylvaError::MergeConflict {
                                    message: "Merge failed due to conflicts".to_string(),
                                });
                            }
                        }
                    }
                }
                (Some(source_entry), None) => {
                    // Entry only in source
                    merged_entries.insert(entry_id, (*source_entry).clone());
                }
                (None, Some(target_entry)) => {
                    // Entry only in target
                    merged_entries.insert(entry_id, (*target_entry).clone());
                }
                (None, None) => unreachable!(),
            }
        }

        let processing_time = start_time.elapsed().as_millis() as u64;

        // Create statistics
        let statistics = MergeStatistics {
            total_entries: merged_entries.len(),
            source_entries: source_entries.len(),
            target_entries: target_entries.len(),
            conflicts_count: conflicts.len(),
            auto_resolved_count: conflicts.iter().filter(|c| c.resolution.is_some()).count(),
            manual_resolution_count: conflicts.iter().filter(|c| c.resolution.is_none()).count(),
            processing_time_ms: processing_time,
        };

        // Create result ledger
        let mut result_ledger = Ledger::new();
        let mut sorted_entries: Vec<_> = merged_entries.into_values().collect();
        sorted_entries.sort_by_key(|e| (e.timestamp, e.version));

        for entry in sorted_entries {
            result_ledger.add_entry(entry.data)?;
        }

        // Validate merge result
        let validation = self.validate_merge_result(&result_ledger, &conflicts)?;

        Ok(MergeResult {
            merge_id,
            source_ledger: source_metadata.id,
            target_ledger: target_metadata.id,
            result_ledger: Uuid::new_v4(), // Will be updated when saved
            strategy,
            conflicts,
            statistics,
            merge_timestamp,
            validation,
        })
    }

    /// Resolve conflict between two entries
    fn resolve_conflict(
        &self,
        source_entry: &LedgerEntry,
        target_entry: &LedgerEntry,
        strategy: &MergeStrategy,
        _force: bool,
    ) -> Result<std::result::Result<LedgerEntry, MergeConflict>> {
        if source_entry.data == target_entry.data && source_entry.metadata == target_entry.metadata
        {
            // Only timestamp/version differs - choose based on strategy
            let resolved_entry = match strategy {
                MergeStrategy::TimestampBased => {
                    if source_entry.timestamp <= target_entry.timestamp {
                        source_entry.clone()
                    } else {
                        target_entry.clone()
                    }
                }
                MergeStrategy::LastWriterWins => {
                    if source_entry.version >= target_entry.version {
                        source_entry.clone()
                    } else {
                        target_entry.clone()
                    }
                }
                _ => target_entry.clone(), // Default to target
            };
            return Ok(Ok(resolved_entry));
        }

        // Real conflict - different content or metadata
        let conflict_type = if source_entry.data != target_entry.data {
            ConflictType::ContentConflict
        } else if source_entry.metadata != target_entry.metadata {
            ConflictType::MetadataConflict
        } else if source_entry.timestamp != target_entry.timestamp {
            ConflictType::TimestampConflict
        } else {
            ConflictType::VersionConflict
        };

        match strategy {
            MergeStrategy::TimestampBased => {
                let resolved_entry = if source_entry.timestamp <= target_entry.timestamp {
                    source_entry.clone()
                } else {
                    target_entry.clone()
                };
                Ok(Ok(resolved_entry))
            }
            MergeStrategy::LastWriterWins => {
                let resolved_entry = if source_entry.version >= target_entry.version {
                    source_entry.clone()
                } else {
                    target_entry.clone()
                };
                Ok(Ok(resolved_entry))
            }
            MergeStrategy::FailOnConflict => Ok(Err(MergeConflict {
                conflict_id: Uuid::new_v4(),
                conflict_type,
                source_entry: Some(self.create_entry_diff(source_entry, true, 0)),
                target_entry: Some(self.create_entry_diff(target_entry, true, 0)),
                resolution: None,
                description: "Conflict resolution failed - strategy is fail-on-conflict"
                    .to_string(),
            })),
            _ => {
                // For now, default to target entry for other strategies
                Ok(Ok(target_entry.clone()))
            }
        }
    }

    /// Validate merge result
    fn validate_merge_result(
        &self,
        result_ledger: &Ledger,
        conflicts: &[MergeConflict],
    ) -> Result<MergeValidation> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check temporal integrity
        let entries = result_ledger.get_entries();
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by_key(|e| e.timestamp);

        let temporal_integrity = entries
            .iter()
            .zip(sorted_entries.iter())
            .all(|(a, b)| a.timestamp == b.timestamp);
        if !temporal_integrity {
            errors.push("Temporal integrity violated - entries not in timestamp order".to_string());
        }

        // Check version consistency
        let mut version_consistent = true;
        for window in entries.windows(2) {
            if window[0].version >= window[1].version && window[0].timestamp > window[1].timestamp {
                version_consistent = false;
                warnings.push(format!(
                    "Version inconsistency between entries {} and {}",
                    window[0].id, window[1].id
                ));
            }
        }

        // Check for unresolved conflicts
        let unresolved_conflicts = conflicts.iter().filter(|c| c.resolution.is_none()).count();
        if unresolved_conflicts > 0 {
            warnings.push(format!(
                "{} unresolved conflicts remain",
                unresolved_conflicts
            ));
        }

        Ok(MergeValidation {
            is_valid: errors.is_empty(),
            temporal_integrity,
            version_consistency: version_consistent,
            errors,
            warnings,
        })
    }

    /// Create merged ledger from merge result
    fn create_merged_ledger(&self, _merge_result: &MergeResult) -> Result<Ledger> {
        // For now, return empty ledger - in real implementation,
        // this would construct the actual merged ledger
        Ok(Ledger::new())
    }

    /// Validate ledger integrity
    pub fn validate_ledger(&self, ledger: &Ledger, strict: bool) -> Result<MergeValidation> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let entries = ledger.get_entries();

        // Check for duplicate IDs
        let mut seen_ids = HashSet::new();
        for entry in entries {
            if !seen_ids.insert(entry.id) {
                errors.push(format!("Duplicate entry ID: {}", entry.id));
            }
        }

        // Check temporal ordering
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by_key(|e| e.timestamp);
        let temporal_integrity = entries
            .iter()
            .zip(sorted_entries.iter())
            .all(|(a, b)| a.id == b.id);

        if !temporal_integrity {
            if strict {
                errors.push("Temporal ordering violation".to_string());
            } else {
                warnings.push("Temporal ordering violation".to_string());
            }
        }

        // Check version sequence
        let mut sorted_by_version = entries.to_vec();
        sorted_by_version.sort_by_key(|e| e.version);
        for window in sorted_by_version.windows(2) {
            if window[1].version <= window[0].version {
                warnings.push(format!(
                    "Version sequence issue: {} -> {}",
                    window[0].version, window[1].version
                ));
            }
        }

        Ok(MergeValidation {
            is_valid: errors.is_empty(),
            temporal_integrity,
            version_consistency: warnings.is_empty(),
            errors,
            warnings,
        })
    }

    /// Rollback ledger to specific version
    pub fn rollback_ledger(&self, ledger_id: &Uuid, target_version: u64) -> Result<String> {
        let ledger = self.storage.load_ledger(ledger_id)?;
        let current_version = ledger.ledger.latest_version();

        if target_version >= current_version {
            return Err(SylvaError::InvalidInput {
                message: "Target version must be less than current version".to_string(),
            });
        }

        // Create new ledger with entries up to target version
        let mut rollback_ledger = Ledger::new();
        for entry in ledger.ledger.get_entries() {
            if entry.version <= target_version {
                rollback_ledger.add_entry(entry.data.clone())?;
            }
        }

        // Save rolled back ledger
        let rollback_name = format!("rollback_{}_to_{}", ledger_id, target_version);
        let rollback_id = self.storage.save_ledger(&rollback_ledger, &rollback_name)?;

        Ok(format!(
            "Rolled back to version {} (new ledger: {})",
            target_version, rollback_id
        ))
    }

    /// Output diff results
    fn output_diff(&self, diff: &LedgerDiff, format: &str, summary_only: bool) -> Result<()> {
        match format.to_lowercase().as_str() {
            "json" => {
                let json = serde_json::to_string_pretty(diff).map_err(|e| {
                    SylvaError::SerializationError {
                        message: format!("Failed to serialize diff to JSON: {}", e),
                    }
                })?;
                println!("{}", json);
            }
            "text" => {
                if summary_only {
                    self.output_diff_summary(diff)?;
                } else {
                    self.output_diff_detailed(diff)?;
                }
            }
            _ => {
                return Err(SylvaError::InvalidInput {
                    message: format!("Unsupported output format: {}", format),
                });
            }
        }
        Ok(())
    }

    /// Output detailed diff in text format
    fn output_diff_detailed(&self, diff: &LedgerDiff) -> Result<()> {
        println!("Ledger Diff Report");
        println!("==================");
        println!();

        // Summary statistics
        self.output_diff_summary(diff)?;
        println!();

        // Added entries
        if !diff.added_entries.is_empty() {
            println!("Added Entries ({}):", diff.added_entries.len());
            println!("-----------------");
            for entry in &diff.added_entries {
                println!(
                    "  + {} (v{}, pos:{})",
                    entry.entry_id, entry.version, entry.position
                );
                if !entry.metadata.is_empty() {
                    println!("    Metadata: {:?}", entry.metadata);
                }
            }
            println!();
        }

        // Removed entries
        if !diff.removed_entries.is_empty() {
            println!("Removed Entries ({}):", diff.removed_entries.len());
            println!("-------------------");
            for entry in &diff.removed_entries {
                println!(
                    "  - {} (v{}, pos:{})",
                    entry.entry_id, entry.version, entry.position
                );
                if !entry.metadata.is_empty() {
                    println!("    Metadata: {:?}", entry.metadata);
                }
            }
            println!();
        }

        // Modified entries
        if !diff.modified_entries.is_empty() {
            println!("Modified Entries ({}):", diff.modified_entries.len());
            println!("--------------------");
            for modification in &diff.modified_entries {
                println!(
                    "  ~ {} ({:?})",
                    modification.entry_id, modification.modification_type
                );
                for change in &modification.changes {
                    match &change.change_type {
                        ChangeType::Modified => {
                            println!(
                                "    {}: {} -> {}",
                                change.field,
                                change.old_value.as_ref().unwrap_or(&"None".to_string()),
                                change.new_value.as_ref().unwrap_or(&"None".to_string())
                            );
                        }
                        ChangeType::Added => {
                            println!(
                                "    {}: + {}",
                                change.field,
                                change.new_value.as_ref().unwrap_or(&"None".to_string())
                            );
                        }
                        ChangeType::Removed => {
                            println!(
                                "    {}: - {}",
                                change.field,
                                change.old_value.as_ref().unwrap_or(&"None".to_string())
                            );
                        }
                    }
                }
            }
            println!();
        }

        // Temporal changes
        if !diff.temporal_changes.is_empty() {
            println!("Temporal Changes ({}):", diff.temporal_changes.len());
            println!("--------------------");
            for change in &diff.temporal_changes {
                println!(
                    "  {:?} ({:?}): {}",
                    change.change_type, change.severity, change.description
                );
                if change.affected_entries.len() <= 5 {
                    println!("    Affected: {:?}", change.affected_entries);
                } else {
                    println!("    Affected: {} entries", change.affected_entries.len());
                }
            }
        }

        Ok(())
    }

    /// Output diff summary
    fn output_diff_summary(&self, diff: &LedgerDiff) -> Result<()> {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(["Metric", "Value"]);

        table.add_row([
            "Source Entries",
            &diff.statistics.source_entries.to_string(),
        ]);
        table.add_row([
            "Target Entries",
            &diff.statistics.target_entries.to_string(),
        ]);
        table.add_row(["Added", &diff.statistics.added_count.to_string()]);
        table.add_row(["Removed", &diff.statistics.removed_count.to_string()]);
        table.add_row(["Modified", &diff.statistics.modified_count.to_string()]);
        table.add_row([
            "Temporal Changes",
            &diff.statistics.temporal_changes_count.to_string(),
        ]);
        table.add_row([
            "Similarity",
            &format!("{:.1}%", diff.statistics.similarity_percentage),
        ]);

        println!("{}", table);
        Ok(())
    }

    /// Output merge preview
    fn output_merge_preview(&self, merge_result: &MergeResult) -> Result<()> {
        println!("Merge Preview");
        println!("=============");
        println!("Strategy: {:?}", merge_result.strategy);
        println!("Total entries: {}", merge_result.statistics.total_entries);
        println!("Conflicts: {}", merge_result.statistics.conflicts_count);
        println!(
            "Auto-resolved: {}",
            merge_result.statistics.auto_resolved_count
        );

        if !merge_result.conflicts.is_empty() {
            println!("\nConflicts:");
            for conflict in &merge_result.conflicts {
                println!("  {:?}: {}", conflict.conflict_type, conflict.description);
            }
        }

        Ok(())
    }

    /// Output merge summary
    fn output_merge_summary(&self, merge_result: &MergeResult) -> Result<()> {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(["Metric", "Value"]);

        table.add_row(["Merge ID", &merge_result.merge_id.to_string()]);
        table.add_row(["Strategy", &format!("{:?}", merge_result.strategy)]);
        table.add_row([
            "Total Entries",
            &merge_result.statistics.total_entries.to_string(),
        ]);
        table.add_row([
            "Source Entries",
            &merge_result.statistics.source_entries.to_string(),
        ]);
        table.add_row([
            "Target Entries",
            &merge_result.statistics.target_entries.to_string(),
        ]);
        table.add_row([
            "Conflicts",
            &merge_result.statistics.conflicts_count.to_string(),
        ]);
        table.add_row([
            "Auto Resolved",
            &merge_result.statistics.auto_resolved_count.to_string(),
        ]);
        table.add_row([
            "Processing Time",
            &format!("{}ms", merge_result.statistics.processing_time_ms),
        ]);
        table.add_row(["Valid", &merge_result.validation.is_valid.to_string()]);

        println!("{}", table);
        Ok(())
    }

    /// Output ledger status
    fn output_ledger_status(&self, ledger: &Ledger, metadata: &LedgerMetadata) -> Result<()> {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(["Property", "Value"]);

        table.add_row(["Ledger ID", &metadata.id.to_string()]);
        table.add_row(["Created", &metadata.created_at.to_string()]);
        table.add_row(["Modified", &metadata.modified_at.to_string()]);
        table.add_row(["Version", &metadata.version.to_string()]);
        table.add_row(["Entry Count", &ledger.entry_count().to_string()]);
        table.add_row(["Latest Version", &ledger.latest_version().to_string()]);
        table.add_row(["Format", &metadata.format.to_string()]);

        if let Some(description) = &metadata.description {
            table.add_row(["Description", description]);
        }

        println!("{}", table);
        Ok(())
    }

    /// Output validation result
    fn output_validation_result(&self, validation: &MergeValidation) -> Result<()> {
        println!("Validation Result");
        println!("=================");
        println!("Valid: {}", validation.is_valid);
        println!("Temporal Integrity: {}", validation.temporal_integrity);
        println!("Version Consistency: {}", validation.version_consistency);

        if !validation.errors.is_empty() {
            println!("\nErrors:");
            for error in &validation.errors {
                println!("  ❌ {}", error);
            }
        }

        if !validation.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &validation.warnings {
                println!("  ⚠️  {}", warning);
            }
        }

        Ok(())
    }
}

/// Handle compare command from CLI
pub fn handle_compare_command(matches: &clap::ArgMatches) -> Result<()> {
    let workspace = Workspace::find_workspace()?;
    let handler = CompareHandler::new(workspace)?;

    match matches.subcommand() {
        Some(("diff", sub_matches)) => {
            let args = DiffArgs {
                ledger_a: sub_matches.get_one::<String>("ledger_a").unwrap().clone(),
                ledger_b: sub_matches.get_one::<String>("ledger_b").unwrap().clone(),
                temporal: sub_matches.get_flag("temporal"),
                summary: sub_matches.get_flag("summary"),
                format: sub_matches.get_one::<String>("format").unwrap().clone(),
                content: sub_matches.get_flag("content"),
                version_range: sub_matches.get_one::<String>("version_range").cloned(),
            };
            handler.execute(CompareCommand::Diff(args))
        }
        Some(("merge", sub_matches)) => {
            let args = MergeArgs {
                source: sub_matches.get_one::<String>("source").unwrap().clone(),
                target: sub_matches.get_one::<String>("target").unwrap().clone(),
                output: sub_matches.get_one::<String>("output").unwrap().clone(),
                strategy: sub_matches.get_one::<String>("strategy").unwrap().clone(),
                dry_run: sub_matches.get_flag("dry_run"),
                force: sub_matches.get_flag("force"),
                resolution_file: sub_matches
                    .get_one::<String>("resolution_file")
                    .map(PathBuf::from),
            };
            handler.execute(CompareCommand::Merge(args))
        }
        Some(("status", sub_matches)) => {
            let args = StatusArgs {
                ledger_id: sub_matches.get_one::<String>("ledger_id").unwrap().clone(),
            };
            handler.execute(CompareCommand::Status(args))
        }
        Some(("validate", sub_matches)) => {
            let args = ValidateArgs {
                ledger_id: sub_matches.get_one::<String>("ledger_id").unwrap().clone(),
                strict: sub_matches.get_flag("strict"),
            };
            handler.execute(CompareCommand::Validate(args))
        }
        Some(("rollback", sub_matches)) => {
            let args = RollbackArgs {
                ledger_id: sub_matches.get_one::<String>("ledger_id").unwrap().clone(),
                target_version: sub_matches
                    .get_one::<String>("target_version")
                    .unwrap()
                    .parse()
                    .map_err(|_| SylvaError::InvalidInput {
                        message: "Invalid target version number".to_string(),
                    })?,
                confirm: sub_matches.get_flag("confirm"),
            };
            handler.execute(CompareCommand::Rollback(args))
        }
        _ => Err(SylvaError::InvalidInput {
            message: "No subcommand provided for compare".to_string(),
        }),
    }
}
