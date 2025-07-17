//! Storage module for versioned ledger serialization and persistence
//!
//! This module provides comprehensive storage capabilities for Sylva ledgers,
//! including both JSON (human-readable) and binary (efficient) serialization formats.
//!
//! Features:
//! - Versioned ledger serialization with integrity checks
//! - Workspace-based storage in .sylva/ledgers/ directory
//! - Version history tracking and snapshot capabilities
//! - Support for both JSON and binary formats
//! - Temporal ordering preservation
//! - Error handling for I/O operations and version conflicts

use crate::error::{Result, SylvaError};
use crate::ledger::{Ledger, LedgerEntry};
use crate::tree::{binary::BinaryMerkleTree, Tree, TreeSnapshot};
use crate::workspace::Workspace;

pub mod compression;
pub mod mmap;

use chrono::{DateTime, Utc};
pub use compression::{CompressionAlgorithm, CompressionConfig, CompressionStats, Compressor};
pub use mmap::{MemoryStats, MmapConfig, MmapLedger, MmapLedgerManager, MmapStrategy, TimeRange};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Format for ledger serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StorageFormat {
    /// JSON format (human-readable)
    #[default]
    Json,
    /// Binary format (compact and efficient)
    Binary,
    /// Compressed JSON format
    CompressedJson,
    /// Compressed binary format
    CompressedBinary,
}

/// Metadata for a stored ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerMetadata {
    /// Unique identifier for the ledger
    pub id: Uuid,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub modified_at: DateTime<Utc>,
    /// Version number
    pub version: u64,
    /// Entry count
    pub entry_count: usize,
    /// Storage format used
    pub format: StorageFormat,
    /// Root hash for integrity verification
    pub root_hash: Option<String>,
    /// Description or name of the ledger
    pub description: Option<String>,
    /// Custom metadata tags
    pub tags: HashMap<String, String>,
    /// Compression statistics (if compressed)
    pub compression_stats: Option<CompressionStats>,
}

/// Complete ledger data for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableLedger {
    /// Metadata about the ledger
    pub metadata: LedgerMetadata,
    /// The ledger data itself
    pub ledger: Ledger,
    /// Optional tree snapshot
    pub tree_snapshot: Option<TreeSnapshot>,
}

/// Version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHistoryEntry {
    /// Version number
    pub version: u64,
    /// Timestamp of this version
    pub timestamp: DateTime<Utc>,
    /// Description of changes
    pub description: Option<String>,
    /// Entry count at this version
    pub entry_count: usize,
    /// Root hash at this version
    pub root_hash: Option<String>,
}

/// Version history for a ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHistory {
    /// Ledger ID
    pub ledger_id: Uuid,
    /// History entries sorted by version
    pub entries: Vec<VersionHistoryEntry>,
}

/// Comprehensive compression report for workspace analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionReport {
    /// Total number of ledgers analyzed
    pub total_ledgers: usize,
    /// Number of ledgers using compression
    pub compressed_ledgers: usize,
    /// Number of compressions that are beneficial
    pub beneficial_compressions: usize,
    /// Total original size across all ledgers
    pub total_original_size: usize,
    /// Total compressed size across all ledgers
    pub total_compressed_size: usize,
    /// Overall compression ratio
    pub overall_compression_ratio: f64,
    /// Overall space savings percentage
    pub overall_space_savings: f64,
    /// Individual ledger compression statistics
    pub ledger_stats: Vec<(LedgerMetadata, CompressionStats)>,
}

impl CompressionReport {
    /// Display a formatted compression report
    pub fn display(&self) -> String {
        use comfy_table::{presets::UTF8_FULL, Table};

        let mut output = String::new();

        // Overall statistics
        output.push_str("📊 Compression Report\n");
        output.push_str("═══════════════════════════════════════════════════════\n");
        output.push_str(&format!("Total ledgers:        {}\n", self.total_ledgers));
        output.push_str(&format!(
            "Compressed ledgers:   {}\n",
            self.compressed_ledgers
        ));
        output.push_str(&format!(
            "Beneficial compressions: {}\n",
            self.beneficial_compressions
        ));
        output.push_str(&format!(
            "Total original size:  {} bytes\n",
            self.format_bytes(self.total_original_size)
        ));
        output.push_str(&format!(
            "Total compressed size: {} bytes\n",
            self.format_bytes(self.total_compressed_size)
        ));
        output.push_str(&format!(
            "Overall compression:  {:.2}x ({:.1}% savings)\n",
            1.0 / self.overall_compression_ratio,
            self.overall_space_savings
        ));
        output.push('\n');

        if !self.ledger_stats.is_empty() {
            // Detailed table
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header([
                "Ledger Name",
                "Original Size",
                "Compressed Size",
                "Ratio",
                "Savings",
                "Algorithm",
                "Level",
                "Beneficial",
            ]);

            for (metadata, stats) in &self.ledger_stats {
                let default_name = format!("Ledger {}", &metadata.id.to_string()[..8]);
                let ledger_name = metadata.description.as_ref().unwrap_or(&default_name);

                table.add_row(&[
                    ledger_name.clone(),
                    self.format_bytes(stats.original_size),
                    self.format_bytes(stats.compressed_size),
                    format!("{:.2}x", 1.0 / stats.compression_ratio),
                    format!("{:.1}%", stats.space_savings),
                    stats.algorithm.to_string(),
                    stats.level.to_string(),
                    if stats.is_beneficial() { "✓" } else { "✗" }.to_string(),
                ]);
            }

            output.push_str(&table.to_string());
        }

        output
    }

    fn format_bytes(&self, bytes: usize) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }

    /// Get compression efficiency percentage (0-100)
    pub fn efficiency_percentage(&self) -> f64 {
        if self.total_ledgers == 0 {
            return 0.0;
        }
        (self.beneficial_compressions as f64 / self.total_ledgers as f64) * 100.0
    }

    /// Check if compression is generally beneficial for this workspace
    pub fn is_compression_recommended(&self) -> bool {
        self.efficiency_percentage() > 50.0 && self.overall_space_savings > 10.0
    }
}

/// Storage manager for versioned ledgers
pub struct LedgerStorage {
    /// Base storage directory
    storage_dir: PathBuf,
    /// Default format for new ledgers
    default_format: StorageFormat,
    /// Compression configuration
    compression_config: CompressionConfig,
    /// Compressor instance
    compressor: Compressor,
}

impl LedgerStorage {
    /// Create a new storage manager for a workspace
    pub fn new(workspace: &Workspace) -> Result<Self> {
        let storage_dir = workspace.ledgers_dir();

        // Ensure storage directory exists
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to create storage directory: {}", e),
            })?;
        }

        let compression_config = CompressionConfig::default();
        let compressor = Compressor::new(compression_config.clone())?;

        Ok(Self {
            storage_dir,
            default_format: StorageFormat::Json,
            compression_config,
            compressor,
        })
    }

    /// Create a new storage manager with custom directory
    pub fn new_with_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let storage_dir = dir.as_ref().to_path_buf();

        // Ensure storage directory exists
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to create storage directory: {}", e),
            })?;
        }

        let compression_config = CompressionConfig::default();
        let compressor = Compressor::new(compression_config.clone())?;

        Ok(Self {
            storage_dir,
            default_format: StorageFormat::Json,
            compression_config,
            compressor,
        })
    }

    /// Create a new storage manager with custom compression configuration
    pub fn new_with_compression(
        workspace: &Workspace,
        compression_config: CompressionConfig,
    ) -> Result<Self> {
        let storage_dir = workspace.ledgers_dir();

        // Ensure storage directory exists
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to create storage directory: {}", e),
            })?;
        }

        let compressor = Compressor::new(compression_config.clone())?;

        Ok(Self {
            storage_dir,
            default_format: StorageFormat::CompressedJson,
            compression_config,
            compressor,
        })
    }

    /// Set the default storage format
    pub fn set_default_format(&mut self, format: StorageFormat) {
        self.default_format = format;
    }

    /// Get the default storage format
    pub fn default_format(&self) -> StorageFormat {
        self.default_format
    }

    /// Get compression configuration
    pub fn compression_config(&self) -> &CompressionConfig {
        &self.compression_config
    }

    /// Update compression configuration
    pub fn set_compression_config(&mut self, config: CompressionConfig) -> Result<()> {
        self.compressor = Compressor::new(config.clone())?;
        self.compression_config = config;
        Ok(())
    }

    /// Save a ledger to storage
    pub fn save_ledger(&self, ledger: &Ledger, name: &str) -> Result<Uuid> {
        self.save_ledger_with_format(ledger, name, self.default_format)
    }

    /// Save a ledger with a specific format
    pub fn save_ledger_with_format(
        &self,
        ledger: &Ledger,
        name: &str,
        format: StorageFormat,
    ) -> Result<Uuid> {
        let ledger_id = Uuid::new_v4();
        let now = Utc::now();

        // Create tree snapshot if ledger has entries
        let tree_snapshot = if !ledger.is_empty() {
            let tree = BinaryMerkleTree::from_entries(ledger.get_entries().to_vec())?;
            Some(TreeSnapshot::new(
                ledger.latest_version(),
                ledger.get_entries().to_vec(),
                tree.root_hash(),
            ))
        } else {
            None
        };

        let metadata = LedgerMetadata {
            id: ledger_id,
            created_at: now,
            modified_at: now,
            version: ledger.latest_version(),
            entry_count: ledger.entry_count(),
            format,
            root_hash: tree_snapshot
                .as_ref()
                .and_then(|ts| ts.root_hash.as_ref())
                .map(|h| h.to_string()),
            description: Some(name.to_string()),
            tags: HashMap::new(),
            compression_stats: None,
        };

        let serializable_ledger = SerializableLedger {
            metadata,
            ledger: ledger.clone(),
            tree_snapshot,
        };

        self.save_serializable_ledger(&serializable_ledger, format)?;

        // Initialize version history
        let version_entry = VersionHistoryEntry {
            version: ledger.latest_version(),
            timestamp: now,
            description: Some(format!("Initial save of ledger '{}'", name)),
            entry_count: ledger.entry_count(),
            root_hash: serializable_ledger.metadata.root_hash.clone(),
        };

        let version_history = VersionHistory {
            ledger_id,
            entries: vec![version_entry],
        };

        self.save_version_history(&version_history)?;

        Ok(ledger_id)
    }

    /// Load a ledger from storage
    pub fn load_ledger(&self, ledger_id: &Uuid) -> Result<SerializableLedger> {
        // Try all formats in order of preference
        let formats = [
            StorageFormat::CompressedJson,
            StorageFormat::CompressedBinary,
            StorageFormat::Json,
            StorageFormat::Binary,
        ];

        for format in formats {
            if let Ok(ledger) = self.load_ledger_with_format(ledger_id, format) {
                return Ok(ledger);
            }
        }

        Err(SylvaError::StorageError {
            message: format!("Ledger {} not found in any format", ledger_id),
        })
    }

    /// Load a ledger with a specific format
    pub fn load_ledger_with_format(
        &self,
        ledger_id: &Uuid,
        format: StorageFormat,
    ) -> Result<SerializableLedger> {
        let file_path = self.ledger_file_path(ledger_id, format);

        if !file_path.exists() {
            return Err(SylvaError::StorageError {
                message: format!("Ledger file {} not found", file_path.display()),
            });
        }

        let data = fs::read(&file_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read ledger file: {}", e),
        })?;

        let ledger = match format {
            StorageFormat::Json => {
                serde_json::from_slice::<SerializableLedger>(&data).map_err(|e| {
                    SylvaError::StorageError {
                        message: format!("Failed to deserialize JSON ledger: {}", e),
                    }
                })?
            }
            StorageFormat::Binary => {
                bincode::deserialize::<SerializableLedger>(&data).map_err(|e| {
                    SylvaError::StorageError {
                        message: format!("Failed to deserialize binary ledger: {}", e),
                    }
                })?
            }
            StorageFormat::CompressedJson | StorageFormat::CompressedBinary => {
                use compression::CompressedData;

                // First deserialize the compressed container
                let compressed_data: CompressedData =
                    bincode::deserialize(&data).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to deserialize compressed data container: {}", e),
                    })?;

                // Decompress the data
                let decompressed_data = self.compressor.decompress(&compressed_data)?;

                // Deserialize the actual ledger data based on the original format
                match format {
                    StorageFormat::CompressedJson => serde_json::from_slice::<SerializableLedger>(
                        &decompressed_data,
                    )
                    .map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to deserialize decompressed JSON ledger: {}", e),
                    })?,
                    StorageFormat::CompressedBinary => bincode::deserialize::<SerializableLedger>(
                        &decompressed_data,
                    )
                    .map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to deserialize decompressed binary ledger: {}", e),
                    })?,
                    _ => unreachable!(),
                }
            }
        };

        // Verify integrity
        self.verify_ledger_integrity(&ledger)?;

        Ok(ledger)
    }

    /// Update an existing ledger
    pub fn update_ledger(
        &self,
        ledger_id: &Uuid,
        ledger: &Ledger,
        description: Option<String>,
    ) -> Result<()> {
        // Load existing metadata
        let existing = self.load_ledger(ledger_id)?;
        let mut metadata = existing.metadata;

        // Update metadata
        metadata.modified_at = Utc::now();
        metadata.version = ledger.latest_version();
        metadata.entry_count = ledger.entry_count();

        // Create new tree snapshot
        let tree_snapshot = if !ledger.is_empty() {
            let tree = BinaryMerkleTree::from_entries(ledger.get_entries().to_vec())?;
            Some(TreeSnapshot::new(
                ledger.latest_version(),
                ledger.get_entries().to_vec(),
                tree.root_hash(),
            ))
        } else {
            None
        };

        metadata.root_hash = tree_snapshot
            .as_ref()
            .and_then(|ts| ts.root_hash.as_ref())
            .map(|h| h.to_string());

        let format = metadata.format;
        let serializable_ledger = SerializableLedger {
            metadata,
            ledger: ledger.clone(),
            tree_snapshot,
        };
        self.save_serializable_ledger(&serializable_ledger, format)?;

        // Update version history
        let mut version_history = self.load_version_history(ledger_id)?;
        let version_entry = VersionHistoryEntry {
            version: ledger.latest_version(),
            timestamp: Utc::now(),
            description,
            entry_count: ledger.entry_count(),
            root_hash: serializable_ledger.metadata.root_hash.clone(),
        };

        version_history.entries.push(version_entry);
        version_history.entries.sort_by_key(|e| e.version);

        self.save_version_history(&version_history)?;

        Ok(())
    }

    /// Delete a ledger from storage
    pub fn delete_ledger(&self, ledger_id: &Uuid) -> Result<()> {
        let formats = [
            StorageFormat::Json,
            StorageFormat::Binary,
            StorageFormat::CompressedJson,
            StorageFormat::CompressedBinary,
        ];

        // Remove ledger files in all formats
        for format in formats {
            let file_path = self.ledger_file_path(ledger_id, format);
            if file_path.exists() {
                fs::remove_file(&file_path).map_err(|e| SylvaError::StorageError {
                    message: format!("Failed to delete {:?} ledger file: {}", format, e),
                })?;
            }
        }

        // Remove version history
        let history_path = self.version_history_file_path(ledger_id);
        if history_path.exists() {
            fs::remove_file(&history_path).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to delete version history file: {}", e),
            })?;
        }

        // Remove compression report
        let compression_path = self.compression_report_file_path(ledger_id);
        if compression_path.exists() {
            fs::remove_file(&compression_path).map_err(|e| SylvaError::StorageError {
                message: format!("Failed to delete compression report file: {}", e),
            })?;
        }

        Ok(())
    }

    /// List all ledgers in storage
    pub fn list_ledgers(&self) -> Result<Vec<LedgerMetadata>> {
        let mut ledgers = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        let entries = fs::read_dir(&self.storage_dir).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read storage directory: {}", e),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| SylvaError::StorageError {
                message: format!("Failed to read directory entry: {}", e),
            })?;

            let file_name = entry.file_name().to_string_lossy().to_string();

            // Check if it's a ledger file (not a history file)
            if (file_name.ends_with(".json")
                || file_name.ends_with(".bin")
                || file_name.ends_with(".json.zst")
                || file_name.ends_with(".bin.zst"))
                && !file_name.contains(".history.")
            {
                let id_str = file_name.split('.').next().unwrap_or("");
                if let Ok(ledger_id) = Uuid::parse_str(id_str) {
                    // Only process each UUID once
                    if seen_ids.insert(ledger_id) {
                        if let Ok(ledger) = self.load_ledger(&ledger_id) {
                            ledgers.push(ledger.metadata);
                        }
                    }
                }
            }
        }

        // Sort by creation time
        ledgers.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(ledgers)
    }

    /// Get version history for a ledger
    pub fn get_version_history(&self, ledger_id: &Uuid) -> Result<VersionHistory> {
        self.load_version_history(ledger_id)
    }

    /// Create a snapshot of a ledger at a specific version
    pub fn create_snapshot(&self, ledger_id: &Uuid, version: u64) -> Result<TreeSnapshot> {
        let ledger = self.load_ledger(ledger_id)?;

        // Filter entries up to the specified version
        let entries: Vec<LedgerEntry> = ledger
            .ledger
            .get_entries()
            .iter()
            .filter(|e| e.version <= version)
            .cloned()
            .collect();

        if entries.is_empty() {
            return Err(SylvaError::StorageError {
                message: format!("No entries found for version {}", version),
            });
        }

        // Create tree and snapshot
        let tree = BinaryMerkleTree::from_entries(entries.clone())?;
        let snapshot = TreeSnapshot::new(version, entries, tree.root_hash());

        Ok(snapshot)
    }

    // Private helper methods

    fn save_serializable_ledger(
        &self,
        ledger: &SerializableLedger,
        format: StorageFormat,
    ) -> Result<()> {
        let file_path = self.ledger_file_path(&ledger.metadata.id, format);

        let (data, compression_stats) = match format {
            StorageFormat::Json => {
                let json_data =
                    serde_json::to_vec_pretty(ledger).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize ledger to JSON: {}", e),
                    })?;
                (json_data, None)
            }
            StorageFormat::Binary => {
                let binary_data =
                    bincode::serialize(ledger).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize ledger to binary: {}", e),
                    })?;
                (binary_data, None)
            }
            StorageFormat::CompressedJson => {
                let json_data =
                    serde_json::to_vec_pretty(ledger).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize ledger to JSON: {}", e),
                    })?;
                let compressed = self.compressor.compress(&json_data)?;
                let stats = compressed.stats.clone();
                let final_data =
                    bincode::serialize(&compressed).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize compressed data: {}", e),
                    })?;
                (final_data, Some(stats))
            }
            StorageFormat::CompressedBinary => {
                let binary_data =
                    bincode::serialize(ledger).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize ledger to binary: {}", e),
                    })?;
                let compressed = self.compressor.compress(&binary_data)?;
                let stats = compressed.stats.clone();
                let final_data =
                    bincode::serialize(&compressed).map_err(|e| SylvaError::StorageError {
                        message: format!("Failed to serialize compressed data: {}", e),
                    })?;
                (final_data, Some(stats))
            }
        };

        fs::write(&file_path, data).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to write ledger file: {}", e),
        })?;

        // Update metadata with compression stats and log if available
        if let Some(stats) = compression_stats {
            // Store compression stats in a separate metadata file for reporting
            self.save_compression_report(&ledger.metadata.id, &stats)?;

            if stats.is_beneficial() {
                println!("✓ {}", stats.display());
            } else {
                println!("⚠ Compression not beneficial: {}", stats.display());
            }
        }

        Ok(())
    }

    fn save_version_history(&self, history: &VersionHistory) -> Result<()> {
        let file_path = self.version_history_file_path(&history.ledger_id);

        let data = serde_json::to_vec_pretty(history).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to serialize version history: {}", e),
        })?;

        fs::write(&file_path, data).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to write version history file: {}", e),
        })?;

        Ok(())
    }

    fn load_version_history(&self, ledger_id: &Uuid) -> Result<VersionHistory> {
        let file_path = self.version_history_file_path(ledger_id);

        if !file_path.exists() {
            return Ok(VersionHistory {
                ledger_id: *ledger_id,
                entries: Vec::new(),
            });
        }

        let data = fs::read(&file_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read version history file: {}", e),
        })?;

        let history = serde_json::from_slice::<VersionHistory>(&data).map_err(|e| {
            SylvaError::StorageError {
                message: format!("Failed to deserialize version history: {}", e),
            }
        })?;

        Ok(history)
    }

    fn verify_ledger_integrity(&self, ledger: &SerializableLedger) -> Result<()> {
        // Verify temporal ordering
        let entries = ledger.ledger.get_entries();
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.version.cmp(&b.version))
        });

        for (i, entry) in entries.iter().enumerate() {
            if *entry != sorted_entries[i] {
                return Err(SylvaError::StorageError {
                    message: "Ledger entries are not in temporal order".to_string(),
                });
            }
        }

        // Verify root hash if available
        if let Some(expected_hash) = &ledger.metadata.root_hash {
            if let Some(snapshot) = &ledger.tree_snapshot {
                if let Some(actual_hash) = &snapshot.root_hash {
                    if expected_hash != &actual_hash.to_string() {
                        return Err(SylvaError::StorageError {
                            message: "Root hash mismatch - ledger integrity compromised"
                                .to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn ledger_file_path(&self, ledger_id: &Uuid, format: StorageFormat) -> PathBuf {
        let extension = match format {
            StorageFormat::Json => "json",
            StorageFormat::Binary => "bin",
            StorageFormat::CompressedJson => "json.zst",
            StorageFormat::CompressedBinary => "bin.zst",
        };

        self.storage_dir
            .join(format!("{}.{}", ledger_id, extension))
    }

    fn version_history_file_path(&self, ledger_id: &Uuid) -> PathBuf {
        self.storage_dir.join(format!("{}.history.json", ledger_id))
    }

    fn compression_report_file_path(&self, ledger_id: &Uuid) -> PathBuf {
        self.storage_dir
            .join(format!("{}.compression.json", ledger_id))
    }

    fn save_compression_report(&self, ledger_id: &Uuid, stats: &CompressionStats) -> Result<()> {
        let file_path = self.compression_report_file_path(ledger_id);

        let data = serde_json::to_vec_pretty(stats).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to serialize compression stats: {}", e),
        })?;

        fs::write(&file_path, data).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to write compression report: {}", e),
        })?;

        Ok(())
    }

    /// Load compression statistics for a ledger
    pub fn load_compression_report(&self, ledger_id: &Uuid) -> Result<Option<CompressionStats>> {
        let file_path = self.compression_report_file_path(ledger_id);

        if !file_path.exists() {
            return Ok(None);
        }

        let data = fs::read(&file_path).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to read compression report: {}", e),
        })?;

        let stats = serde_json::from_slice::<CompressionStats>(&data).map_err(|e| {
            SylvaError::StorageError {
                message: format!("Failed to deserialize compression stats: {}", e),
            }
        })?;

        Ok(Some(stats))
    }

    /// Get ledger metadata without loading the full ledger
    pub fn get_ledger_metadata(&self, ledger_id: &Uuid) -> Result<Option<LedgerMetadata>> {
        // Try to load the ledger and extract just the metadata
        match self.load_ledger(ledger_id) {
            Ok(serializable_ledger) => Ok(Some(serializable_ledger.metadata)),
            Err(SylvaError::StorageError { message }) if message.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Load a range of entries from a ledger without loading the entire ledger
    pub fn load_entries_range(
        &self,
        ledger_id: &Uuid,
        start_index: usize,
        end_index: usize,
    ) -> Result<Vec<LedgerEntry>> {
        // For now, load the full ledger and slice it
        // In a production implementation, this could use memory-mapped files
        // or a more sophisticated storage format for efficient range queries
        let serializable_ledger = self.load_ledger(ledger_id)?;
        let entries = serializable_ledger.ledger.get_entries();

        let start = start_index.min(entries.len());
        let end = end_index.min(entries.len());

        if start >= end {
            return Ok(Vec::new());
        }

        Ok(entries[start..end].to_vec())
    }

    /// Load entries within a specific time range
    pub fn load_entries_time_range(
        &self,
        ledger_id: &Uuid,
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>> {
        // For now, load entries and filter by time range
        // In a production implementation, this could use temporal indexing
        let serializable_ledger = self.load_ledger(ledger_id)?;
        let entries = serializable_ledger.ledger.get_entries();

        // Convert DateTime to timestamps for comparison
        let start_timestamp = time_range.start.timestamp() as u64;
        let end_timestamp = time_range.end.timestamp() as u64;

        let filtered_entries: Vec<LedgerEntry> = entries
            .iter()
            .skip(offset)
            .filter(|entry| entry.timestamp >= start_timestamp && entry.timestamp < end_timestamp)
            .take(limit)
            .cloned()
            .collect();

        Ok(filtered_entries)
    }

    /// Generate a comprehensive compression report for all ledgers
    pub fn generate_compression_report(&self) -> Result<CompressionReport> {
        let ledgers = self.list_ledgers()?;
        let mut total_original_size = 0;
        let mut total_compressed_size = 0;
        let mut compressed_ledgers = 0;
        let mut beneficial_compressions = 0;
        let mut compression_stats = Vec::new();

        for ledger_metadata in &ledgers {
            if let Ok(Some(stats)) = self.load_compression_report(&ledger_metadata.id) {
                total_original_size += stats.original_size;
                total_compressed_size += stats.compressed_size;
                compressed_ledgers += 1;

                if stats.is_beneficial() {
                    beneficial_compressions += 1;
                }

                compression_stats.push((ledger_metadata.clone(), stats));
            } else {
                // For uncompressed ledgers, estimate the file size
                let formats = [
                    StorageFormat::Json,
                    StorageFormat::Binary,
                    StorageFormat::CompressedJson,
                    StorageFormat::CompressedBinary,
                ];

                for format in formats {
                    let file_path = self.ledger_file_path(&ledger_metadata.id, format);
                    if file_path.exists() {
                        if let Ok(metadata) = fs::metadata(&file_path) {
                            total_original_size += metadata.len() as usize;
                            total_compressed_size += metadata.len() as usize;
                        }
                        break;
                    }
                }
            }
        }

        let overall_ratio = if total_original_size > 0 {
            total_compressed_size as f64 / total_original_size as f64
        } else {
            1.0
        };

        let overall_savings = if total_original_size > 0 {
            ((total_original_size - total_compressed_size) as f64 / total_original_size as f64)
                * 100.0
        } else {
            0.0
        };

        Ok(CompressionReport {
            total_ledgers: ledgers.len(),
            compressed_ledgers,
            beneficial_compressions,
            total_original_size,
            total_compressed_size,
            overall_compression_ratio: overall_ratio,
            overall_space_savings: overall_savings,
            ledger_stats: compression_stats,
        })
    }
}

impl std::fmt::Display for StorageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageFormat::Json => write!(f, "json"),
            StorageFormat::Binary => write!(f, "binary"),
            StorageFormat::CompressedJson => write!(f, "compressed-json"),
            StorageFormat::CompressedBinary => write!(f, "compressed-binary"),
        }
    }
}

impl std::str::FromStr for StorageFormat {
    type Err = SylvaError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(StorageFormat::Json),
            "binary" | "bin" => Ok(StorageFormat::Binary),
            "compressed-json" | "comp-json" | "jsonz" => Ok(StorageFormat::CompressedJson),
            "compressed-binary" | "comp-binary" | "binz" => Ok(StorageFormat::CompressedBinary),
            _ => Err(SylvaError::StorageError {
                message: format!("Unknown storage format: {}. Supported: json, binary, compressed-json, compressed-binary", s),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn create_test_workspace() -> (TempDir, Workspace) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        (temp_dir, workspace)
    }

    fn create_test_ledger() -> Ledger {
        let mut ledger = Ledger::new();
        ledger.add_entry(b"test data 1".to_vec()).unwrap();
        ledger.add_entry(b"test data 2".to_vec()).unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "test".to_string());
        ledger
            .add_entry_with_metadata(b"test data 3".to_vec(), metadata)
            .unwrap();

        ledger
    }

    #[test]
    fn test_storage_format_display() {
        assert_eq!(StorageFormat::Json.to_string(), "json");
        assert_eq!(StorageFormat::Binary.to_string(), "binary");
    }

    #[test]
    fn test_storage_format_from_str() {
        assert_eq!(
            "json".parse::<StorageFormat>().unwrap(),
            StorageFormat::Json
        );
        assert_eq!(
            "binary".parse::<StorageFormat>().unwrap(),
            StorageFormat::Binary
        );
        assert_eq!(
            "bin".parse::<StorageFormat>().unwrap(),
            StorageFormat::Binary
        );
        assert!("invalid".parse::<StorageFormat>().is_err());
    }

    #[test]
    fn test_ledger_storage_creation() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();

        assert_eq!(storage.default_format(), StorageFormat::Json);
        assert!(storage.storage_dir.exists());
    }

    #[test]
    fn test_save_and_load_ledger_json() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save ledger
        let ledger_id = storage.save_ledger(&ledger, "test ledger").unwrap();

        // Load ledger
        let loaded = storage.load_ledger(&ledger_id).unwrap();

        assert_eq!(loaded.metadata.id, ledger_id);
        assert_eq!(loaded.metadata.format, StorageFormat::Json);
        assert_eq!(loaded.metadata.entry_count, 3);
        assert_eq!(loaded.ledger.entry_count(), 3);
        assert!(loaded.tree_snapshot.is_some());
    }

    #[test]
    fn test_save_and_load_ledger_binary() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save ledger in binary format
        let ledger_id = storage
            .save_ledger_with_format(&ledger, "test ledger", StorageFormat::Binary)
            .unwrap();

        // Load ledger
        let loaded = storage.load_ledger(&ledger_id).unwrap();

        assert_eq!(loaded.metadata.id, ledger_id);
        assert_eq!(loaded.metadata.format, StorageFormat::Binary);
        assert_eq!(loaded.metadata.entry_count, 3);
        assert_eq!(loaded.ledger.entry_count(), 3);
    }

    #[test]
    fn test_ledger_serialization_round_trip() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let original_ledger = create_test_ledger();

        // Test JSON round trip
        let json_id = storage
            .save_ledger_with_format(&original_ledger, "json test", StorageFormat::Json)
            .unwrap();
        let json_loaded = storage.load_ledger(&json_id).unwrap();

        assert_eq!(
            json_loaded.ledger.entry_count(),
            original_ledger.entry_count()
        );
        assert_eq!(
            json_loaded.ledger.latest_version(),
            original_ledger.latest_version()
        );

        // Test binary round trip
        let binary_id = storage
            .save_ledger_with_format(&original_ledger, "binary test", StorageFormat::Binary)
            .unwrap();
        let binary_loaded = storage.load_ledger(&binary_id).unwrap();

        assert_eq!(
            binary_loaded.ledger.entry_count(),
            original_ledger.entry_count()
        );
        assert_eq!(
            binary_loaded.ledger.latest_version(),
            original_ledger.latest_version()
        );
    }

    #[test]
    fn test_version_history_tracking() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let mut ledger = create_test_ledger();

        // Save initial ledger
        let ledger_id = storage.save_ledger(&ledger, "versioned ledger").unwrap();

        // Update ledger
        ledger.add_entry(b"new data".to_vec()).unwrap();
        storage
            .update_ledger(&ledger_id, &ledger, Some("Added new entry".to_string()))
            .unwrap();

        // Check version history
        let history = storage.get_version_history(&ledger_id).unwrap();
        assert_eq!(history.entries.len(), 2);
        assert_eq!(history.entries[0].version, 2); // Initial version
        assert_eq!(history.entries[1].version, 3); // After update
    }

    #[test]
    fn test_list_ledgers() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();

        // Storage should start empty
        let initial_ledgers = storage.list_ledgers().unwrap();
        assert_eq!(initial_ledgers.len(), 0);

        // Save multiple ledgers
        let ledger1 = create_test_ledger();
        let ledger2 = create_test_ledger();

        storage.save_ledger(&ledger1, "ledger 1").unwrap();
        storage.save_ledger(&ledger2, "ledger 2").unwrap();

        // List ledgers
        let ledgers = storage.list_ledgers().unwrap();
        assert_eq!(ledgers.len(), 2);

        // Check descriptions
        let descriptions: Vec<_> = ledgers
            .iter()
            .filter_map(|l| l.description.as_ref())
            .collect();
        assert!(descriptions.contains(&&"ledger 1".to_string()));
        assert!(descriptions.contains(&&"ledger 2".to_string()));
    }

    #[test]
    fn test_ledger_deletion() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save and delete ledger
        let ledger_id = storage.save_ledger(&ledger, "to be deleted").unwrap();
        storage.delete_ledger(&ledger_id).unwrap();

        // Try to load - should fail
        assert!(storage.load_ledger(&ledger_id).is_err());

        // List should be empty
        let ledgers = storage.list_ledgers().unwrap();
        assert!(ledgers.is_empty());
    }

    #[test]
    fn test_create_snapshot() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save ledger
        let ledger_id = storage.save_ledger(&ledger, "snapshot test").unwrap();

        // Create snapshot at version 1
        let snapshot = storage.create_snapshot(&ledger_id, 1).unwrap();

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.entry_count(), 2); // Entries with version 0 and 1
        assert!(snapshot.root_hash.is_some());
    }

    #[test]
    fn test_temporal_ordering_preserved() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save and load
        let ledger_id = storage.save_ledger(&ledger, "temporal test").unwrap();
        let loaded = storage.load_ledger(&ledger_id).unwrap();

        // Verify temporal ordering
        let entries = loaded.ledger.entries_sorted_by_timestamp();
        for window in entries.windows(2) {
            assert!(window[0].timestamp <= window[1].timestamp);
        }
    }

    #[test]
    fn test_integrity_verification() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save ledger
        let ledger_id = storage.save_ledger(&ledger, "integrity test").unwrap();

        // Load and verify - should pass
        let loaded = storage.load_ledger(&ledger_id).unwrap();
        assert!(storage.verify_ledger_integrity(&loaded).is_ok());
    }

    #[test]
    fn test_empty_ledger_serialization() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let empty_ledger = Ledger::new();

        // Save empty ledger
        let ledger_id = storage.save_ledger(&empty_ledger, "empty ledger").unwrap();

        // Load and verify
        let loaded = storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded.ledger.entry_count(), 0);
        assert!(loaded.ledger.is_empty());
        assert!(loaded.tree_snapshot.is_none());
    }

    #[test]
    fn test_backward_compatibility() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Save in old format (JSON)
        let ledger_id = storage
            .save_ledger_with_format(&ledger, "legacy ledger", StorageFormat::Json)
            .unwrap();

        // Should be able to load regardless of current default format
        let loaded = storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded.ledger.entry_count(), ledger.entry_count());
        assert_eq!(loaded.metadata.format, StorageFormat::Json);
    }

    #[test]
    fn test_compressed_storage_formats() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let ledger = create_test_ledger();

        // Test compressed JSON format
        let json_id = storage
            .save_ledger_with_format(&ledger, "compressed json", StorageFormat::CompressedJson)
            .unwrap();

        let loaded_json = storage.load_ledger(&json_id).unwrap();
        assert_eq!(loaded_json.ledger.entry_count(), ledger.entry_count());
        assert_eq!(loaded_json.metadata.format, StorageFormat::CompressedJson);

        // Test compressed binary format
        let binary_id = storage
            .save_ledger_with_format(
                &ledger,
                "compressed binary",
                StorageFormat::CompressedBinary,
            )
            .unwrap();

        let loaded_binary = storage.load_ledger(&binary_id).unwrap();
        assert_eq!(loaded_binary.ledger.entry_count(), ledger.entry_count());
        assert_eq!(
            loaded_binary.metadata.format,
            StorageFormat::CompressedBinary
        );
    }

    #[test]
    fn test_compression_configuration() {
        use crate::storage::compression::{CompressionAlgorithm, CompressionConfig};

        let (_temp_dir, workspace) = create_test_workspace();
        let compression_config = CompressionConfig::new(CompressionAlgorithm::Zstd, 6).unwrap();
        let storage = LedgerStorage::new_with_compression(&workspace, compression_config).unwrap();

        assert_eq!(storage.default_format(), StorageFormat::CompressedJson);
        assert_eq!(storage.compression_config().level, 6);
    }

    #[test]
    fn test_compression_report_generation() {
        let (_temp_dir, workspace) = create_test_workspace();
        let storage = LedgerStorage::new(&workspace).unwrap();

        // Verify we start with an empty workspace
        assert_eq!(storage.list_ledgers().unwrap().len(), 0);

        let ledger1 = create_test_ledger();
        let ledger2 = create_test_ledger();

        // Save one compressed and one uncompressed
        storage
            .save_ledger_with_format(&ledger1, "compressed", StorageFormat::CompressedJson)
            .unwrap();
        storage
            .save_ledger_with_format(&ledger2, "uncompressed", StorageFormat::Json)
            .unwrap();

        // Verify we have exactly 2 ledgers
        assert_eq!(storage.list_ledgers().unwrap().len(), 2);

        // Generate compression report
        let report = storage.generate_compression_report().unwrap();
        assert_eq!(report.total_ledgers, 2);
        assert!(report.compressed_ledgers >= 1);
    }
}
