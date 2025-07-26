//! ledger serialization and persistence
//!
//! provides save/load operations for versioned ledgers with support for
//! both JSON and binary formats.

use crate::error::{Result, SylvaError};
use crate::ledger::{Ledger, LedgerEntry, LedgerStats};
use crate::tree::{binary::BinaryMerkleTree, Tree};
// use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// serialization format for ledger persistence
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// JSON format (human-readable, larger size)
    Json,
    /// binary format (efficient, smaller size)
    Binary,
}

/// versioned ledger snapshot for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    /// snapshot metadata
    pub metadata: SnapshotMetadata,
    /// all ledger entries
    pub entries: Vec<LedgerEntry>,
    /// merkle tree structure
    pub tree: Option<BinaryMerkleTree>,
    /// ledger statistics at time of snapshot
    pub stats: LedgerStats,
}

/// metadata for ledger snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// unique snapshot identifier
    pub id: Uuid,
    /// snapshot creation timestamp (unix timestamp)
    pub created_at: u64,
    /// ledger version at time of snapshot
    pub ledger_version: u64,
    /// total number of entries
    pub entry_count: usize,
    /// serialization format used
    pub format: String,
    /// optional description
    pub description: Option<String>,
    /// custom properties
    pub properties: HashMap<String, String>,
}

/// version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHistoryEntry {
    /// version number
    pub version: u64,
    /// timestamp when this version was created (unix timestamp)
    pub timestamp: u64,
    /// number of entries at this version
    pub entry_count: usize,
    /// snapshot file path if available
    pub snapshot_path: Option<PathBuf>,
    /// description of changes
    pub description: Option<String>,
}

/// manages ledger serialization operations
pub struct LedgerSerializer {
    /// base workspace directory
    #[allow(dead_code)]
    workspace_dir: PathBuf,
    /// ledgers storage directory
    ledgers_dir: PathBuf,
}

impl LedgerSerializer {
    /// create new ledger serializer for workspace
    pub fn new(workspace_dir: PathBuf) -> Result<Self> {
        let ledgers_dir = workspace_dir.join(".sylva").join("ledgers");
        std::fs::create_dir_all(&ledgers_dir)?;

        Ok(Self {
            workspace_dir,
            ledgers_dir,
        })
    }

    /// save ledger to persistent storage
    pub fn save_ledger(
        &self,
        ledger: &Ledger,
        format: SerializationFormat,
        description: Option<String>,
    ) -> Result<Uuid> {
        let snapshot_id = Uuid::new_v4();
        let stats = ledger.stats()?;

        // collect all entries
        let entry_ids = ledger.list_entries()?;
        let mut entries = Vec::new();
        for id in entry_ids {
            entries.push(ledger.get_entry(id)?);
        }

        // create merkle tree from entries
        let tree = if !entries.is_empty() {
            Some(BinaryMerkleTree::from_entries(&entries)?)
        } else {
            None
        };

        let metadata = SnapshotMetadata {
            id: snapshot_id,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ledger_version: stats.current_version,
            entry_count: entries.len(),
            format: format_to_string(format),
            description,
            properties: HashMap::new(),
        };

        let snapshot = LedgerSnapshot {
            metadata,
            entries,
            tree,
            stats,
        };

        // save snapshot to file
        let filename = format!(
            "ledger_v{:06}_{}.{}",
            snapshot.stats.current_version,
            snapshot_id,
            format_extension(format)
        );
        let file_path = self.ledgers_dir.join(&filename);

        match format {
            SerializationFormat::Json => {
                let json_data = serde_json::to_string_pretty(&snapshot)?;
                std::fs::write(&file_path, json_data)?;
            }
            SerializationFormat::Binary => {
                let binary_data = bincode::serialize(&snapshot).map_err(|e| {
                    SylvaError::internal(format!("Binary serialization failed: {}", e))
                })?;
                std::fs::write(&file_path, binary_data)?;
            }
        }

        // update version history
        self.update_version_history(&snapshot, &file_path)?;

        Ok(snapshot_id)
    }

    /// load ledger from persistent storage
    pub fn load_ledger(&self, snapshot_id: Uuid) -> Result<LedgerSnapshot> {
        // find snapshot file
        let snapshot_file = self.find_snapshot_file(snapshot_id)?;

        // determine format from extension
        let format = if snapshot_file.extension() == Some(std::ffi::OsStr::new("json")) {
            SerializationFormat::Json
        } else {
            SerializationFormat::Binary
        };

        // load and deserialize
        let file_data = std::fs::read(&snapshot_file)?;

        let snapshot = match format {
            SerializationFormat::Json => serde_json::from_slice::<LedgerSnapshot>(&file_data)?,
            SerializationFormat::Binary => bincode::deserialize::<LedgerSnapshot>(&file_data)
                .map_err(|e| {
                    SylvaError::internal(format!("Binary deserialization failed: {}", e))
                })?,
        };

        Ok(snapshot)
    }

    /// load latest ledger snapshot
    pub fn load_latest(&self) -> Result<Option<LedgerSnapshot>> {
        let history = self.load_version_history()?;

        if let Some(latest) = history.last() {
            if let Some(snapshot_path) = &latest.snapshot_path {
                let full_path = self.ledgers_dir.join(snapshot_path);

                // determine format and load
                let format = if full_path.extension() == Some(std::ffi::OsStr::new("json")) {
                    SerializationFormat::Json
                } else {
                    SerializationFormat::Binary
                };

                let file_data = std::fs::read(&full_path)?;

                let snapshot = match format {
                    SerializationFormat::Json => {
                        serde_json::from_slice::<LedgerSnapshot>(&file_data)?
                    }
                    SerializationFormat::Binary => {
                        bincode::deserialize::<LedgerSnapshot>(&file_data).map_err(|e| {
                            SylvaError::internal(format!("Binary deserialization failed: {}", e))
                        })?
                    }
                };

                return Ok(Some(snapshot));
            }
        }

        Ok(None)
    }

    /// list all available snapshots
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>> {
        let mut snapshots = Vec::new();

        let entries = std::fs::read_dir(&self.ledgers_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && (path.extension() == Some(std::ffi::OsStr::new("json"))
                    || path.extension() == Some(std::ffi::OsStr::new("bin")))
            {
                // try to load metadata only
                if let Ok(metadata) = self.load_snapshot_metadata(&path) {
                    snapshots.push(metadata);
                }
            }
        }

        // sort by creation time
        snapshots.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        Ok(snapshots)
    }

    /// get version history
    pub fn get_version_history(&self) -> Result<Vec<VersionHistoryEntry>> {
        self.load_version_history()
    }

    /// delete snapshot
    pub fn delete_snapshot(&self, snapshot_id: Uuid) -> Result<()> {
        let snapshot_file = self.find_snapshot_file(snapshot_id)?;
        std::fs::remove_file(&snapshot_file)?;

        // update version history
        let mut history = self.load_version_history()?;
        history.retain(|entry| {
            if let Some(path) = &entry.snapshot_path {
                path.to_str().unwrap() != snapshot_file.file_name().unwrap().to_str().unwrap()
            } else {
                true
            }
        });
        self.save_version_history(&history)?;

        Ok(())
    }

    /// get workspace storage stats
    pub fn storage_stats(&self) -> Result<StorageStats> {
        let mut total_size = 0;
        let mut file_count = 0;

        let entries = std::fs::read_dir(&self.ledgers_dir)?;
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                total_size += entry.metadata()?.len();
                file_count += 1;
            }
        }

        Ok(StorageStats {
            total_size,
            file_count,
            ledgers_dir: self.ledgers_dir.clone(),
        })
    }

    // private helper methods

    fn find_snapshot_file(&self, snapshot_id: Uuid) -> Result<PathBuf> {
        let entries = std::fs::read_dir(&self.ledgers_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.contains(&snapshot_id.to_string()) {
                    return Ok(path);
                }
            }
        }

        Err(SylvaError::not_found(format!("Snapshot {}", snapshot_id)))
    }

    fn load_snapshot_metadata(&self, path: &Path) -> Result<SnapshotMetadata> {
        let file_data = std::fs::read(path)?;

        // try JSON first
        if path.extension() == Some(std::ffi::OsStr::new("json")) {
            let snapshot: LedgerSnapshot = serde_json::from_slice(&file_data)?;
            Ok(snapshot.metadata)
        } else {
            let snapshot: LedgerSnapshot = bincode::deserialize(&file_data).map_err(|e| {
                SylvaError::internal(format!("Binary deserialization failed: {}", e))
            })?;
            Ok(snapshot.metadata)
        }
    }

    fn update_version_history(&self, snapshot: &LedgerSnapshot, file_path: &Path) -> Result<()> {
        let mut history = self.load_version_history().unwrap_or_default();

        let entry = VersionHistoryEntry {
            version: snapshot.metadata.ledger_version,
            timestamp: snapshot.metadata.created_at,
            entry_count: snapshot.metadata.entry_count,
            snapshot_path: file_path.file_name().map(|n| n.into()),
            description: snapshot.metadata.description.clone(),
        };

        history.push(entry);
        self.save_version_history(&history)?;

        Ok(())
    }

    fn load_version_history(&self) -> Result<Vec<VersionHistoryEntry>> {
        let history_path = self.ledgers_dir.join("version_history.json");

        if !history_path.exists() {
            return Ok(Vec::new());
        }

        let history_data = std::fs::read(&history_path)?;
        let history: Vec<VersionHistoryEntry> = serde_json::from_slice(&history_data)?;
        Ok(history)
    }

    fn save_version_history(&self, history: &[VersionHistoryEntry]) -> Result<()> {
        let history_path = self.ledgers_dir.join("version_history.json");
        let history_json = serde_json::to_string_pretty(history)?;
        std::fs::write(history_path, history_json)?;
        Ok(())
    }
}

/// storage statistics for workspace
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// total size of all ledger files
    pub total_size: u64,
    /// number of ledger files
    pub file_count: usize,
    /// ledgers directory path
    pub ledgers_dir: PathBuf,
}

// helper functions

fn format_to_string(format: SerializationFormat) -> String {
    match format {
        SerializationFormat::Json => "json".to_string(),
        SerializationFormat::Binary => "binary".to_string(),
    }
}

fn format_extension(format: SerializationFormat) -> &'static str {
    match format {
        SerializationFormat::Json => "json",
        SerializationFormat::Binary => "bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use tempfile::TempDir;

    fn create_test_ledger() -> Result<Ledger> {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage)?;

        // add some test entries
        ledger.add_entry(b"entry 1".to_vec(), Some("First entry".to_string()))?;
        ledger.add_entry(b"entry 2".to_vec(), Some("Second entry".to_string()))?;

        Ok(ledger)
    }

    #[test]
    fn test_ledger_serializer_creation() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();

        assert!(serializer.ledgers_dir.exists());
        assert!(serializer.ledgers_dir.is_dir());
    }

    #[test]
    fn test_save_and_load_json() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // save as JSON
        let snapshot_id = serializer
            .save_ledger(
                &ledger,
                SerializationFormat::Json,
                Some("Test snapshot".to_string()),
            )
            .unwrap();

        // load back
        let loaded_snapshot = serializer.load_ledger(snapshot_id).unwrap();

        assert_eq!(loaded_snapshot.entries.len(), 2);
        assert_eq!(loaded_snapshot.metadata.format, "json");
        assert_eq!(
            loaded_snapshot.metadata.description,
            Some("Test snapshot".to_string())
        );
    }

    #[test]
    fn test_save_and_load_binary() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // save as binary
        let snapshot_id = serializer
            .save_ledger(
                &ledger,
                SerializationFormat::Binary,
                Some("Binary test".to_string()),
            )
            .unwrap();

        // load back
        let loaded_snapshot = serializer.load_ledger(snapshot_id).unwrap();

        assert_eq!(loaded_snapshot.entries.len(), 2);
        assert_eq!(loaded_snapshot.metadata.format, "binary");
    }

    #[test]
    fn test_round_trip_serialization() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // get original stats
        let original_stats = ledger.stats().unwrap();

        // save and load JSON
        let json_id = serializer
            .save_ledger(&ledger, SerializationFormat::Json, None)
            .unwrap();
        let json_snapshot = serializer.load_ledger(json_id).unwrap();

        // save and load binary
        let bin_id = serializer
            .save_ledger(&ledger, SerializationFormat::Binary, None)
            .unwrap();
        let bin_snapshot = serializer.load_ledger(bin_id).unwrap();

        // verify integrity
        assert_eq!(json_snapshot.stats.entry_count, original_stats.entry_count);
        assert_eq!(bin_snapshot.stats.entry_count, original_stats.entry_count);
        assert_eq!(json_snapshot.entries.len(), bin_snapshot.entries.len());

        // verify entry data integrity
        for (json_entry, bin_entry) in json_snapshot
            .entries
            .iter()
            .zip(bin_snapshot.entries.iter())
        {
            assert_eq!(json_entry.data, bin_entry.data);
            assert_eq!(json_entry.version, bin_entry.version);
            assert_eq!(json_entry.data_hash, bin_entry.data_hash);
        }
    }

    #[test]
    fn test_list_snapshots() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // create multiple snapshots
        serializer
            .save_ledger(
                &ledger,
                SerializationFormat::Json,
                Some("First".to_string()),
            )
            .unwrap();
        serializer
            .save_ledger(
                &ledger,
                SerializationFormat::Binary,
                Some("Second".to_string()),
            )
            .unwrap();

        let snapshots = serializer.list_snapshots().unwrap();
        assert_eq!(snapshots.len(), 2);

        // should be sorted by creation time
        assert!(snapshots[0].created_at <= snapshots[1].created_at);
    }

    #[test]
    fn test_version_history() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // save multiple versions
        serializer
            .save_ledger(&ledger, SerializationFormat::Json, Some("V1".to_string()))
            .unwrap();
        serializer
            .save_ledger(&ledger, SerializationFormat::Json, Some("V2".to_string()))
            .unwrap();

        let history = serializer.get_version_history().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].description, Some("V1".to_string()));
        assert_eq!(history[1].description, Some("V2".to_string()));
    }

    #[test]
    fn test_load_latest() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        // should return None when no snapshots exist
        assert!(serializer.load_latest().unwrap().is_none());

        // save a snapshot
        serializer
            .save_ledger(
                &ledger,
                SerializationFormat::Json,
                Some("Latest".to_string()),
            )
            .unwrap();

        // should return the latest snapshot
        let latest = serializer.load_latest().unwrap().unwrap();
        assert_eq!(latest.metadata.description, Some("Latest".to_string()));
    }

    #[test]
    fn test_delete_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        let snapshot_id = serializer
            .save_ledger(&ledger, SerializationFormat::Json, None)
            .unwrap();

        // verify it exists
        assert!(serializer.load_ledger(snapshot_id).is_ok());

        // delete it
        serializer.delete_snapshot(snapshot_id).unwrap();

        // verify it's gone
        assert!(serializer.load_ledger(snapshot_id).is_err());
    }

    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let serializer = LedgerSerializer::new(temp_dir.path().to_path_buf()).unwrap();
        let ledger = create_test_ledger().unwrap();

        let initial_stats = serializer.storage_stats().unwrap();
        assert_eq!(initial_stats.file_count, 0);
        assert_eq!(initial_stats.total_size, 0);

        // save a ledger
        serializer
            .save_ledger(&ledger, SerializationFormat::Json, None)
            .unwrap();

        let after_stats = serializer.storage_stats().unwrap();
        assert!(after_stats.file_count >= 1);
        assert!(after_stats.total_size > 0);
    }
}
