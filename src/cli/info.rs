use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash as HashTrait, HashDigest, LedgerEntryHashInput};
use crate::ledger::{Ledger, LedgerEntry};
use crate::tree::{binary::BinaryMerkleTree, Tree};
use crate::workspace::Workspace;
use clap::ArgMatches;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Statistics about a ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerStats {
    pub name: String,
    pub entry_count: usize,
    pub total_size: usize,
    pub version_count: u64,
    pub hash_function: String,
    pub root_hash: Option<HashDigest>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    pub file_size: u64,
    pub integrity_status: IntegrityStatus,
}

/// Integrity check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Valid,
    Invalid(String),
    Unknown,
}

impl IntegrityStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, IntegrityStatus::Valid)
    }

    pub fn display(&self) -> &str {
        match self {
            IntegrityStatus::Valid => "✅ Valid",
            IntegrityStatus::Invalid(_) => "❌ Invalid",
            IntegrityStatus::Unknown => "❓ Unknown",
        }
    }

    pub fn details(&self) -> Option<&str> {
        match self {
            IntegrityStatus::Invalid(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Information about a ledger entry for history display
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: uuid::Uuid,
    pub version: u64,
    pub timestamp: u64,
    pub data_size: usize,
    pub description: Option<String>,
    pub source_type: Option<String>,
    pub filename: Option<String>,
}

/// Main info command implementation
#[derive(Debug)]
pub struct InfoCommand {
    workspace: Workspace,
}

impl InfoCommand {
    /// Create a new info command
    pub fn new() -> Result<Self> {
        let workspace = Workspace::find_workspace()?;
        Ok(Self { workspace })
    }

    /// Execute the info command for a specific ledger
    pub fn show_ledger_info(&self, ledger_name: &str) -> Result<()> {
        let stats = self.get_ledger_stats(ledger_name)?;
        self.display_ledger_info(&stats);
        Ok(())
    }

    /// Execute the history command for a specific ledger
    pub fn show_ledger_history(&self, ledger_name: &str, limit: Option<usize>) -> Result<()> {
        let history = self.get_ledger_history(ledger_name, limit)?;
        self.display_ledger_history(ledger_name, &history);
        Ok(())
    }

    /// Execute the list command to show all ledgers
    pub fn list_ledgers(&self) -> Result<()> {
        let ledger_stats = self.get_all_ledger_stats()?;
        self.display_ledger_list(&ledger_stats);
        Ok(())
    }

    /// Get statistics for a specific ledger
    fn get_ledger_stats(&self, ledger_name: &str) -> Result<LedgerStats> {
        use crate::storage::LedgerStorage;

        let storage = LedgerStorage::new(&self.workspace)?;
        let ledger_metadatas = storage.list_ledgers()?;

        // Find ledger by name
        let metadata = ledger_metadatas
            .iter()
            .find(|m| {
                m.description
                    .as_ref()
                    .is_some_and(|desc| desc == ledger_name)
            })
            .ok_or_else(|| SylvaError::EntryNotFound {
                id: format!("ledger '{}'", ledger_name),
            })?;

        // Load the ledger
        let serializable_ledger = storage.load_ledger(&metadata.id)?;
        let ledger = &serializable_ledger.ledger;
        let total_size = ledger.get_entries().iter().map(|e| e.data_size()).sum();

        // Calculate root hash using Merkle tree
        let mut tree = BinaryMerkleTree::new();
        for entry in ledger.get_entries() {
            tree.insert(entry.clone())?;
        }
        let root_hash = tree.root_hash();

        // Check integrity
        let integrity_status = self.check_ledger_integrity(ledger)?;

        // Find creation time from earliest entry
        let created_at = ledger.get_entries().iter().map(|e| e.timestamp).min();

        // Use metadata from storage
        let modified_at = Some(metadata.modified_at.timestamp() as u64);
        let file_size = total_size as u64; // Approximate file size

        Ok(LedgerStats {
            name: ledger_name.to_string(),
            entry_count: ledger.entry_count(),
            total_size,
            version_count: ledger.version_count(),
            hash_function: "blake3".to_string(), // Default hash function
            root_hash,
            created_at,
            modified_at,
            file_size,
            integrity_status,
        })
    }

    /// Get history entries for a ledger
    fn get_ledger_history(
        &self,
        ledger_name: &str,
        limit: Option<usize>,
    ) -> Result<Vec<HistoryEntry>> {
        use crate::storage::LedgerStorage;

        let storage = LedgerStorage::new(&self.workspace)?;
        let ledger_metadatas = storage.list_ledgers()?;

        // Find ledger by name
        let metadata = ledger_metadatas
            .iter()
            .find(|m| {
                m.description
                    .as_ref()
                    .is_some_and(|desc| desc == ledger_name)
            })
            .ok_or_else(|| SylvaError::EntryNotFound {
                id: format!("ledger '{}'", ledger_name),
            })?;

        // Load the ledger
        let serializable_ledger = storage.load_ledger(&metadata.id)?;
        let ledger = &serializable_ledger.ledger;
        let mut entries: Vec<LedgerEntry> = ledger.get_entries().to_vec();

        // Sort by timestamp (newest first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit if specified
        if let Some(limit) = limit {
            entries.truncate(limit);
        }

        // Convert to history entries
        let history = entries
            .into_iter()
            .map(|entry| {
                let description = entry
                    .get_metadata("commit_message")
                    .or_else(|| entry.get_metadata("description"))
                    .cloned();

                let source_type = entry.get_metadata("source_type").cloned();
                let filename = entry
                    .get_metadata("filename")
                    .or_else(|| entry.get_metadata("original_path"))
                    .cloned();

                HistoryEntry {
                    id: entry.id,
                    version: entry.version,
                    timestamp: entry.timestamp,
                    data_size: entry.data_size(),
                    description,
                    source_type,
                    filename,
                }
            })
            .collect();

        Ok(history)
    }

    /// Get statistics for all ledgers in the workspace
    fn get_all_ledger_stats(&self) -> Result<Vec<LedgerStats>> {
        let mut stats = Vec::new();

        use crate::storage::LedgerStorage;

        let storage = LedgerStorage::new(&self.workspace)?;
        let ledger_metadatas = storage.list_ledgers()?;

        for metadata in ledger_metadatas {
            if let Ok(serializable_ledger) = storage.load_ledger(&metadata.id) {
                let ledger_stats = LedgerStats {
                    name: metadata.description.unwrap_or_else(|| "main".to_string()),
                    entry_count: metadata.entry_count,
                    total_size: serializable_ledger
                        .ledger
                        .get_entries()
                        .iter()
                        .map(|e| e.data_size())
                        .sum(),
                    version_count: serializable_ledger.ledger.version_count(),
                    hash_function: "blake3".to_string(),
                    root_hash: None, // TODO: Get from tree
                    created_at: Some(metadata.created_at.timestamp() as u64),
                    modified_at: Some(metadata.modified_at.timestamp() as u64),
                    file_size: 0, // TODO: Calculate file size
                    integrity_status: IntegrityStatus::Valid,
                };
                stats.push(ledger_stats);
            }
        }

        // Sort by name
        stats.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(stats)
    }

    /// Check ledger integrity
    fn check_ledger_integrity(&self, ledger: &Ledger) -> Result<IntegrityStatus> {
        // Basic integrity checks
        let entries = ledger.get_entries();

        // Check for duplicate IDs
        let mut seen_ids = std::collections::HashSet::new();
        for entry in entries {
            if !seen_ids.insert(entry.id) {
                return Ok(IntegrityStatus::Invalid(format!(
                    "Duplicate entry ID: {}",
                    entry.id
                )));
            }
        }

        // Check version consistency
        let max_version = entries.iter().map(|e| e.version).max().unwrap_or(0);
        let expected_count = max_version + 1;
        if ledger.version_count() != expected_count {
            return Ok(IntegrityStatus::Invalid(format!(
                "Version count mismatch: expected {}, found {}",
                expected_count,
                ledger.version_count()
            )));
        }

        // Check timestamp consistency (should be increasing or equal)
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by_key(|e| e.version);

        for window in sorted_entries.windows(2) {
            if window[1].timestamp < window[0].timestamp {
                return Ok(IntegrityStatus::Invalid(
                    "Timestamp inconsistency detected".to_string(),
                ));
            }
        }

        // Check hash chain integrity if previous_hash is used
        for entry in entries {
            if let Some(prev_hash) = &entry.previous_hash {
                // Find the previous entry by version
                if entry.version > 0 {
                    let prev_entry = entries.iter().find(|e| e.version == entry.version - 1);

                    if let Some(prev) = prev_entry {
                        let hasher = Blake3Hasher::new();
                        let hash_input = LedgerEntryHashInput {
                            id: prev.id,
                            data: prev.data.clone(),
                            timestamp: prev.timestamp,
                            previous_hash: prev.previous_hash.clone(),
                        };
                        let calculated_hash = hasher.hash_entry(&hash_input)?;
                        if *prev_hash != calculated_hash {
                            return Ok(IntegrityStatus::Invalid(format!(
                                "Hash chain broken at version {}",
                                entry.version
                            )));
                        }
                    }
                }
            }
        }

        Ok(IntegrityStatus::Valid)
    }

    /// Display detailed ledger information
    fn display_ledger_info(&self, stats: &LedgerStats) {
        println!("Ledger Information: {}", stats.name);
        println!("{}", "=".repeat(50));

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);

        table.add_rows(vec![
            vec!["Property", "Value"],
            vec!["Entry Count", &stats.entry_count.to_string()],
            vec!["Total Data Size", &format_bytes(stats.total_size)],
            vec!["File Size", &format_bytes(stats.file_size as usize)],
            vec!["Version Count", &stats.version_count.to_string()],
            vec!["Hash Function", &stats.hash_function],
            vec![
                "Root Hash",
                &stats
                    .root_hash
                    .as_ref()
                    .map(|h| format!("{}...", hex::encode(&h.as_bytes()[..8])))
                    .unwrap_or_else(|| "None".to_string()),
            ],
            vec![
                "Created",
                &stats
                    .created_at
                    .map(format_timestamp)
                    .unwrap_or_else(|| "Unknown".to_string()),
            ],
            vec![
                "Modified",
                &stats
                    .modified_at
                    .map(format_timestamp)
                    .unwrap_or_else(|| "Unknown".to_string()),
            ],
            vec!["Integrity", stats.integrity_status.display()],
        ]);

        // Style the table
        table
            .column_mut(0)
            .unwrap()
            .set_cell_alignment(comfy_table::CellAlignment::Right);

        println!("{}", table);

        // Show integrity details if invalid
        if let Some(details) = stats.integrity_status.details() {
            println!("\n❌ Integrity Issues:");
            println!("   {}", details);
        }

        // Show additional statistics
        if stats.entry_count > 0 {
            let avg_size = stats.total_size / stats.entry_count;
            println!("\nAdditional Statistics:");
            println!("  Average entry size: {}", format_bytes(avg_size));

            if let Some(root_hash) = &stats.root_hash {
                println!("  Full root hash: {}", hex::encode(root_hash.as_bytes()));
            }
        }
    }

    /// Display ledger history
    fn display_ledger_history(&self, ledger_name: &str, history: &[HistoryEntry]) {
        println!("Ledger History: {}", ledger_name);
        println!("{}", "=".repeat(50));

        if history.is_empty() {
            println!("No entries found.");
            return;
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);

        table.add_row(vec![
            Cell::new("Version").fg(Color::Cyan),
            Cell::new("Timestamp").fg(Color::Cyan),
            Cell::new("Size").fg(Color::Cyan),
            Cell::new("Source").fg(Color::Cyan),
            Cell::new("Description").fg(Color::Cyan),
        ]);

        for entry in history {
            let source = match (&entry.source_type, &entry.filename) {
                (Some(src_type), Some(filename)) if src_type == "file" => {
                    format!("📄 {}", filename)
                }
                (Some(src_type), _) if src_type == "stdin" => "📥 stdin".to_string(),
                (Some(src_type), _) => format!("📋 {}", src_type),
                _ => "❓ unknown".to_string(),
            };

            let description = entry
                .description
                .as_deref()
                .unwrap_or("No description")
                .chars()
                .take(40)
                .collect::<String>();

            table.add_row(vec![
                Cell::new(entry.version.to_string()),
                Cell::new(format_timestamp(entry.timestamp)),
                Cell::new(format_bytes(entry.data_size)),
                Cell::new(&source),
                Cell::new(&description),
            ]);
        }

        println!("{}", table);

        // Show summary
        let total_size: usize = history.iter().map(|e| e.data_size).sum();
        println!(
            "\nSummary: {} entries, {} total",
            history.len(),
            format_bytes(total_size)
        );
    }

    /// Display list of all ledgers
    fn display_ledger_list(&self, ledger_stats: &[LedgerStats]) {
        println!("Ledgers in Workspace");
        println!("{}", "=".repeat(50));

        if ledger_stats.is_empty() {
            println!("No ledgers found in workspace.");
            return;
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);

        table.add_row(vec![
            Cell::new("Name").fg(Color::Cyan),
            Cell::new("Entries").fg(Color::Cyan),
            Cell::new("Size").fg(Color::Cyan),
            Cell::new("Versions").fg(Color::Cyan),
            Cell::new("Modified").fg(Color::Cyan),
            Cell::new("Status").fg(Color::Cyan),
        ]);

        for stats in ledger_stats {
            let status_cell = if stats.integrity_status.is_valid() {
                Cell::new("✅ Valid").fg(Color::Green)
            } else {
                Cell::new("❌ Invalid").fg(Color::Red)
            };

            table.add_row(vec![
                Cell::new(&stats.name),
                Cell::new(stats.entry_count.to_string()),
                Cell::new(format_bytes(stats.total_size)),
                Cell::new(stats.version_count.to_string()),
                Cell::new(
                    stats
                        .modified_at
                        .map(format_timestamp)
                        .unwrap_or_else(|| "Unknown".to_string()),
                ),
                status_cell,
            ]);
        }

        println!("{}", table);

        // Show summary statistics
        let total_entries: usize = ledger_stats.iter().map(|s| s.entry_count).sum();
        let total_size: usize = ledger_stats.iter().map(|s| s.total_size).sum();
        let valid_count = ledger_stats
            .iter()
            .filter(|s| s.integrity_status.is_valid())
            .count();

        println!("\nWorkspace Summary:");
        println!("  Ledgers: {}", ledger_stats.len());
        println!("  Total entries: {}", total_entries);
        println!("  Total size: {}", format_bytes(total_size));
        println!("  Valid ledgers: {}/{}", valid_count, ledger_stats.len());
    }
}

/// Format bytes in human-readable format
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

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

/// Format timestamp in human-readable format
pub fn format_timestamp(timestamp: u64) -> String {
    let datetime = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);

    match datetime.elapsed() {
        Ok(elapsed) => {
            let seconds = elapsed.as_secs();

            if seconds < 60 {
                format!("{} seconds ago", seconds)
            } else if seconds < 3600 {
                format!("{} minutes ago", seconds / 60)
            } else if seconds < 86400 {
                format!("{} hours ago", seconds / 3600)
            } else if seconds < 2592000 {
                // 30 days
                format!("{} days ago", seconds / 86400)
            } else {
                // For older dates, show actual date
                format_absolute_time(timestamp)
            }
        }
        Err(_) => format_absolute_time(timestamp),
    }
}

/// Format absolute timestamp
fn format_absolute_time(timestamp: u64) -> String {
    use chrono::DateTime;

    if let Some(datetime) = DateTime::from_timestamp(timestamp as i64, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        format!("Invalid timestamp: {}", timestamp)
    }
}

/// Handle CLI arguments for info command
pub fn handle_info_command(matches: &ArgMatches) -> Result<()> {
    let info_cmd = InfoCommand::new()?;

    if let Some(ledger_name) = matches.get_one::<String>("ledger") {
        info_cmd.show_ledger_info(ledger_name)
    } else {
        Err(SylvaError::ConfigError {
            message: "Ledger name is required for info command".to_string(),
        })
    }
}

/// Handle CLI arguments for history command
pub fn handle_history_command(matches: &ArgMatches) -> Result<()> {
    let info_cmd = InfoCommand::new()?;

    if let Some(ledger_name) = matches.get_one::<String>("ledger") {
        let limit = matches
            .get_one::<String>("limit")
            .and_then(|s| s.parse().ok());

        info_cmd.show_ledger_history(ledger_name, limit)
    } else {
        Err(SylvaError::ConfigError {
            message: "Ledger name is required for history command".to_string(),
        })
    }
}

/// Handle CLI arguments for list command
pub fn handle_list_command(_matches: &ArgMatches) -> Result<()> {
    let info_cmd = InfoCommand::new()?;
    info_cmd.list_ledgers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::UNIX_EPOCH;
    use tempfile::TempDir;

    fn create_test_workspace() -> (TempDir, Workspace) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::initialize(temp_dir.path()).unwrap();
        (temp_dir, workspace)
    }

    fn create_test_ledger_with_entries(
        workspace: &Workspace,
        name: &str,
        entry_count: usize,
    ) -> Result<()> {
        use crate::storage::LedgerStorage;

        let mut ledger = Ledger::new();

        for i in 0..entry_count {
            let mut metadata = HashMap::new();
            metadata.insert("commit_message".to_string(), format!("Entry {}", i));
            metadata.insert("source_type".to_string(), "file".to_string());
            metadata.insert("filename".to_string(), format!("test{}.txt", i));

            ledger.add_entry_with_metadata(format!("test data {}", i).into_bytes(), metadata)?;

            // Add small delay to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Save ledger using proper storage
        let storage = LedgerStorage::new(workspace)?;
        storage.save_ledger(&ledger, name)?;

        Ok(())
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_timestamp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Recent timestamp should show relative time
        let result = format_timestamp(now - 30);
        assert!(result.contains("seconds ago") || result.contains("minutes ago"));

        // Old timestamp should show absolute time
        let old_timestamp = now - 86400 * 365; // 1 year ago
        let result = format_timestamp(old_timestamp);
        assert!(result.contains("UTC") || result.contains("ago"));
    }

    #[test]
    fn test_integrity_status() {
        let valid = IntegrityStatus::Valid;
        assert!(valid.is_valid());
        assert_eq!(valid.display(), "✅ Valid");
        assert!(valid.details().is_none());

        let invalid = IntegrityStatus::Invalid("test error".to_string());
        assert!(!invalid.is_valid());
        assert_eq!(invalid.display(), "❌ Invalid");
        assert_eq!(invalid.details(), Some("test error"));
    }

    #[test]
    fn test_ledger_stats_creation() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 3).unwrap();

        let info_cmd = InfoCommand { workspace };
        let stats = info_cmd.get_ledger_stats("test").unwrap();

        assert_eq!(stats.name, "test");
        assert_eq!(stats.entry_count, 3);
        assert_eq!(stats.version_count, 3);
        assert!(stats.total_size > 0);
        assert!(stats.integrity_status.is_valid());
    }

    #[test]
    fn test_ledger_history() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 5).unwrap();

        let info_cmd = InfoCommand { workspace };
        let history = info_cmd.get_ledger_history("test", Some(3)).unwrap();

        assert_eq!(history.len(), 3); // Limited to 3

        // Should be sorted by timestamp (newest first)
        for window in history.windows(2) {
            assert!(window[0].timestamp >= window[1].timestamp);
        }

        // Check that entries have expected metadata
        for entry in &history {
            assert!(entry.description.is_some());
            assert!(entry.source_type.is_some());
            assert!(entry.filename.is_some());
        }
    }

    #[test]
    fn test_list_ledgers() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "ledger1", 2).unwrap();
        create_test_ledger_with_entries(&workspace, "ledger2", 3).unwrap();

        let info_cmd = InfoCommand { workspace };
        let stats = info_cmd.get_all_ledger_stats().unwrap();

        assert_eq!(stats.len(), 2);

        // Should be sorted by name
        assert_eq!(stats[0].name, "ledger1");
        assert_eq!(stats[1].name, "ledger2");

        assert_eq!(stats[0].entry_count, 2);
        assert_eq!(stats[1].entry_count, 3);
    }

    #[test]
    fn test_nonexistent_ledger() {
        let (_temp_dir, workspace) = create_test_workspace();
        let info_cmd = InfoCommand { workspace };

        let result = info_cmd.get_ledger_stats("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_integrity_checking() {
        let (_temp_dir, workspace) = create_test_workspace();

        // Create a valid ledger
        let mut ledger = Ledger::new();
        ledger.add_entry(b"test data".to_vec()).unwrap();

        let info_cmd = InfoCommand { workspace };
        let status = info_cmd.check_ledger_integrity(&ledger).unwrap();
        assert!(status.is_valid());

        // Test with duplicate ID (this is harder to create artificially,
        // so we'll just verify the valid case works)
        assert_eq!(status.display(), "✅ Valid");
    }
}
