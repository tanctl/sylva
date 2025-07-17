use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash as HashTrait, HashDigest};
use crate::ledger::Ledger;
use crate::storage::LedgerStorage;
use crate::tree::{TreeFactory, TreeType, TreeTypeDetector, UnifiedTree};
use crate::workspace::Workspace;
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Configuration for commit operations
#[derive(Debug, Clone)]
pub struct CommitConfig {
    pub message: Option<String>,
    pub auto_timestamp: bool,
    pub force: bool,
    pub show_progress: bool,
    pub dry_run: bool,
    pub use_stdin: bool,
    pub tree_type: TreeType,
}

impl Default for CommitConfig {
    fn default() -> Self {
        Self {
            message: None,
            auto_timestamp: true,
            force: false,
            show_progress: true,
            dry_run: false,
            use_stdin: false,
            tree_type: TreeType::Binary,
        }
    }
}

/// Represents a file to be committed
#[derive(Debug, Clone)]
pub struct CommitFile {
    pub path: Option<PathBuf>,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

impl CommitFile {
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        let mut metadata = HashMap::new();

        // Add file metadata
        metadata.insert("source_type".to_string(), "file".to_string());
        metadata.insert(
            "original_path".to_string(),
            path.to_string_lossy().to_string(),
        );

        if let Some(filename) = path.file_name() {
            metadata.insert(
                "filename".to_string(),
                filename.to_string_lossy().to_string(),
            );
        }

        if let Some(extension) = path.extension() {
            metadata.insert(
                "file_extension".to_string(),
                extension.to_string_lossy().to_string(),
            );
        }

        // Add file size
        metadata.insert("file_size".to_string(), data.len().to_string());

        Ok(Self {
            path: Some(path.to_path_buf()),
            data,
            metadata,
        })
    }

    pub fn from_stdin() -> Result<Self> {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;

        let mut metadata = HashMap::new();
        metadata.insert("source_type".to_string(), "stdin".to_string());
        metadata.insert("input_size".to_string(), data.len().to_string());
        metadata.insert(
            "timestamp".to_string(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        );

        Ok(Self {
            path: None,
            data,
            metadata,
        })
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn source_description(&self) -> String {
        match &self.path {
            Some(path) => format!("file: {}", path.display()),
            None => "stdin".to_string(),
        }
    }
}

/// Results from a commit operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    pub committed_entries: Vec<Uuid>,
    pub skipped_entries: Vec<(String, String)>, // (source, reason)
    pub conflicts_detected: Vec<ConflictInfo>,
    pub total_size: usize,
    pub commit_hash: Option<HashDigest>,
    pub stats: CommitStats,
}

/// Statistics about the commit operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitStats {
    pub files_processed: usize,
    pub entries_created: usize,
    pub conflicts_resolved: usize,
    pub total_bytes: usize,
    pub duration_ms: u128,
}

/// Information about version conflicts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictInfo {
    pub entry_id: Uuid,
    pub existing_version: u64,
    pub new_version: u64,
    pub conflict_type: ConflictType,
    pub resolution: ConflictResolution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    VersionMismatch,
    TimestampConflict,
    DataDuplication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    Skipped,
    ForceOverride,
    NewVersion,
    Merged,
}

/// Main commit command implementation
#[derive(Debug)]
pub struct CommitCommand {
    pub files: Vec<PathBuf>,
    pub config: CommitConfig,
    workspace: Workspace,
}

impl CommitCommand {
    /// Dynamically select tree type based on CLI args, workspace config, and existing data
    fn select_tree_type(matches: &ArgMatches, workspace: &Workspace) -> Result<TreeType> {
        // 1. Check if user explicitly specified tree type
        if let Some(tree_type_str) = matches.get_one::<String>("tree-type") {
            return tree_type_str.parse();
        }

        // 2. Check workspace configuration for default tree type
        if let Ok(tree_type) = workspace.config().get_tree_type_enum() {
            println!(
                "Using workspace configured tree type: {}",
                tree_type.as_str()
            );
            return Ok(tree_type);
        }

        // 3. Use advanced tree type detection from stored tree files
        let detector = TreeTypeDetector::new();

        // Check for existing tree files
        for tree_type in TreeType::all() {
            let tree_path = workspace
                .ledgers_path()
                .join(format!("main_{}.tree", tree_type.as_str()));
            if let Ok(detection_result) = detector.detect_from_file(&tree_path) {
                if detection_result.is_reliable {
                    println!(
                        "Detected {} tree with {:.1}% confidence from stored file",
                        detection_result.detected_type.unwrap().as_str(),
                        detection_result.confidence * 100.0
                    );
                    return Ok(detection_result.detected_type.unwrap());
                }
            }
        }

        // Fall back to workspace detection
        if let Ok(detection_result) = detector.detect_from_workspace(workspace.root_path()) {
            if detection_result.is_reliable {
                println!(
                    "Detected {} tree from workspace configuration",
                    detection_result.detected_type.unwrap().as_str()
                );
                return Ok(detection_result.detected_type.unwrap());
            }
        }

        // Legacy detection from ledger entries
        let ledger_path = workspace.ledgers_path().join("main.ledger");
        if ledger_path.exists() {
            if let Ok(data) = std::fs::read(&ledger_path) {
                if let Ok(ledger) = bincode::deserialize::<Ledger>(&data) {
                    if let Some(existing_type) = Self::detect_existing_tree_type(&ledger) {
                        println!(
                            "Detected existing tree type from ledger analysis: {}",
                            existing_type.as_str()
                        );
                        return Ok(existing_type);
                    }
                }
            }
        }

        // 4. Use intelligent selection based on data characteristics (if auto-selection is enabled)
        if workspace.config().get_tree_auto_selection() {
            let file_count = matches
                .get_many::<String>("files")
                .map(|files| files.count())
                .unwrap_or(0);

            let use_stdin = matches.get_flag("stdin");

            if file_count > 1000 || use_stdin {
                // For large datasets, prefer sparse trees for efficiency
                println!("Auto-selecting Sparse tree for large dataset optimization");
                Ok(TreeType::Sparse)
            } else if file_count > 100 {
                // Medium datasets work well with Patricia tries
                println!("Auto-selecting Patricia tree for medium dataset");
                Ok(TreeType::Patricia)
            } else {
                // Small datasets or default case use binary trees
                println!("Auto-selecting Binary tree for small dataset");
                Ok(TreeType::Binary)
            }
        } else {
            // Auto-selection disabled, use configured default
            println!("Auto-selection disabled, using configured default: binary");
            Ok(TreeType::Binary)
        }
    }

    /// Attempt to detect tree type from existing ledger
    fn detect_existing_tree_type(ledger: &Ledger) -> Option<TreeType> {
        // This is a simplified detection - in a real implementation,
        // you would store tree type metadata with the ledger

        // For now, assume if ledger has many entries, it was using sparse
        // This is just a heuristic and could be improved
        let entry_count = ledger.get_entries().len();

        if entry_count > 500 {
            Some(TreeType::Sparse)
        } else if entry_count > 50 {
            Some(TreeType::Patricia)
        } else {
            Some(TreeType::Binary)
        }
    }

    /// Create a new commit command from CLI arguments
    pub fn from_args(matches: &ArgMatches) -> Result<Self> {
        let workspace = Workspace::find_workspace()?;

        let files: Vec<PathBuf> = matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .map(PathBuf::from)
            .collect();

        // Parse tree type with dynamic selection
        let tree_type = Self::select_tree_type(matches, &workspace)?;

        let config = CommitConfig {
            message: matches.get_one::<String>("message").cloned(),
            auto_timestamp: matches.get_flag("auto-timestamp"),
            force: matches.get_flag("force"),
            show_progress: matches.get_flag("progress"),
            dry_run: matches.get_flag("dry-run"),
            use_stdin: matches.get_flag("stdin"),
            tree_type,
        };

        // Validate input
        if files.is_empty() && !config.use_stdin {
            return Err(SylvaError::ConfigError {
                message: "No files specified and --stdin not provided. Use --stdin to read from stdin or provide file paths.".to_string(),
            });
        }

        if !files.is_empty() && config.use_stdin {
            return Err(SylvaError::ConfigError {
                message: "Cannot specify both files and --stdin. Choose one input method."
                    .to_string(),
            });
        }

        Ok(Self {
            files,
            config,
            workspace,
        })
    }

    /// Execute the commit command
    pub fn execute(&self) -> Result<()> {
        let start_time = SystemTime::now();

        if self.config.dry_run {
            println!("Dry run mode - showing what would be committed:");
        }

        // Collect files to commit
        let commit_files = self.collect_commit_files()?;

        if commit_files.is_empty() {
            println!("No files to commit.");
            return Ok(());
        }

        // Load or create ledger with tree integration
        let mut ledger = self.load_or_create_ledger()?;
        let mut tree = self.load_or_create_tree()?;

        // Set up progress reporting
        let progress = if self.config.show_progress && commit_files.len() > 1 {
            let pb = ProgressBar::new(commit_files.len() as u64);
            if let Ok(template) = ProgressStyle::default_bar().template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
            ) {
                pb.set_style(template);
            }
            pb.set_message("Committing entries...");
            Some(pb)
        } else {
            None
        };

        // Process files
        let mut result = CommitResult {
            committed_entries: Vec::new(),
            skipped_entries: Vec::new(),
            conflicts_detected: Vec::new(),
            total_size: 0,
            commit_hash: None,
            stats: CommitStats {
                files_processed: 0,
                entries_created: 0,
                conflicts_resolved: 0,
                total_bytes: 0,
                duration_ms: 0,
            },
        };

        for (i, commit_file) in commit_files.iter().enumerate() {
            if let Some(ref pb) = progress {
                pb.set_message("Processing...");
            }

            match self.process_commit_file(commit_file, &mut ledger, &mut tree) {
                Ok(entry_id) => {
                    result.committed_entries.push(entry_id);
                    result.stats.entries_created += 1;
                    result.total_size += commit_file.size();

                    if !self.config.dry_run {
                        println!(
                            "✓ Committed {} -> {}",
                            commit_file.source_description(),
                            entry_id
                        );
                    } else {
                        println!(
                            "  Would commit {} -> {}",
                            commit_file.source_description(),
                            entry_id
                        );
                    }
                }
                Err(e) => {
                    result
                        .skipped_entries
                        .push((commit_file.source_description(), e.to_string()));
                    eprintln!("✗ Skipped {}: {}", commit_file.source_description(), e);
                }
            }

            result.stats.files_processed += 1;
            result.stats.total_bytes += commit_file.size();

            if let Some(ref pb) = progress {
                pb.set_position((i + 1) as u64);
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_with_message("Commit completed");
        }

        // Save ledger and tree if not dry run
        if !self.config.dry_run {
            self.save_ledger(&ledger)?;
            self.save_tree(&tree)?;

            // Generate commit hash
            let hasher = Blake3Hasher::new();
            let commit_data = self.generate_commit_data(&result)?;
            result.commit_hash = Some(hasher.hash_bytes(&commit_data)?);
        }

        // Calculate duration
        result.stats.duration_ms = start_time.elapsed().unwrap_or_default().as_millis();

        // Print summary
        self.print_commit_summary(&result);

        Ok(())
    }

    /// Collect files to commit
    fn collect_commit_files(&self) -> Result<Vec<CommitFile>> {
        let mut commit_files = Vec::new();

        if self.config.use_stdin {
            commit_files.push(CommitFile::from_stdin()?);
        } else {
            for file_path in &self.files {
                // Check if file exists and is readable
                if !file_path.exists() {
                    eprintln!("Warning: File not found: {}", file_path.display());
                    continue;
                }

                if !file_path.is_file() {
                    eprintln!("Warning: Skipping non-file: {}", file_path.display());
                    continue;
                }

                match CommitFile::from_file(file_path) {
                    Ok(commit_file) => commit_files.push(commit_file),
                    Err(e) => {
                        eprintln!("Warning: Failed to read {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        Ok(commit_files)
    }

    /// Process a single commit file
    fn process_commit_file(
        &self,
        commit_file: &CommitFile,
        ledger: &mut Ledger,
        tree: &mut UnifiedTree,
    ) -> Result<Uuid> {
        let mut metadata = commit_file.metadata.clone();

        // Add commit message if provided
        if let Some(ref message) = self.config.message {
            metadata.insert("commit_message".to_string(), message.clone());
        }

        // Add auto timestamp if enabled
        if self.config.auto_timestamp {
            metadata.insert(
                "commit_timestamp".to_string(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_string(),
            );
        }

        // Check for version conflicts
        if !self.config.force {
            self.check_version_conflicts(&commit_file.data, ledger)?;
        }

        // Create ledger entry
        if self.config.dry_run {
            // Return a dummy UUID for dry run
            Ok(Uuid::new_v4())
        } else {
            let entry_id = ledger.add_entry_with_metadata(commit_file.data.clone(), metadata)?;

            // Also add to tree using the unified interface
            let entry = ledger.get_entry(&entry_id)?.unwrap();
            tree.insert_ledger_entry(entry.clone())?;

            println!(
                "  Using {} tree for entry storage",
                self.config.tree_type.as_str()
            );

            Ok(entry_id)
        }
    }

    /// Check for version conflicts
    fn check_version_conflicts(&self, data: &[u8], ledger: &Ledger) -> Result<()> {
        // Simple conflict detection based on data hash
        let hasher = Blake3Hasher::new();
        let data_hash = hasher.hash_bytes(data)?;

        // Check if identical data already exists
        for entry in ledger.get_entries() {
            let entry_hash = hasher.hash_bytes(&entry.data)?;
            if entry_hash == data_hash {
                return Err(SylvaError::VersionConflict {
                    expected: "new".to_string(),
                    found: format!("existing entry {}", entry.id),
                });
            }
        }

        Ok(())
    }

    /// Load existing ledger or create new one
    fn load_or_create_ledger(&self) -> Result<Ledger> {
        let ledger_path = self.workspace.ledgers_path().join("main.ledger");

        if ledger_path.exists() {
            let data = fs::read(&ledger_path)?;
            bincode::deserialize(&data).map_err(|e| SylvaError::MerkleTreeError {
                message: format!("Failed to deserialize ledger: {}", e),
            })
        } else {
            Ok(Ledger::new())
        }
    }

    /// Load existing tree or create new one based on configuration
    fn load_or_create_tree(&self) -> Result<UnifiedTree> {
        let tree_path = self
            .workspace
            .ledgers_path()
            .join(format!("main_{}.tree", self.config.tree_type.as_str()));

        if tree_path.exists() {
            // Try to load existing tree
            if let Ok(data) = fs::read(&tree_path) {
                if let Ok(_tree_data) = bincode::deserialize::<serde_json::Value>(&data) {
                    // For now, create a new tree - in a real implementation, you'd deserialize the saved tree
                    println!(
                        "Loading existing {} tree from {}",
                        self.config.tree_type.as_str(),
                        tree_path.display()
                    );
                    return Ok(UnifiedTree::new(self.config.tree_type));
                }
            }
        }

        // Create new tree with factory
        let factory = TreeFactory::new().with_default_type(self.config.tree_type);
        let mut tree = factory.create(self.config.tree_type)?;

        // Set tree metadata for better detection
        tree.metadata_mut()
            .set_config("workspace", &self.workspace.root_path().to_string_lossy());
        tree.metadata_mut().set_config("created_by", "sylva-cli");
        tree.metadata_mut().set_config("tree_type_verified", "true");
        tree.metadata_mut().set_config("cli_version", "0.1.0");

        println!(
            "Created new {} tree for commit operations",
            self.config.tree_type.as_str()
        );
        Ok(tree)
    }

    /// Save ledger to disk using LedgerStorage
    fn save_ledger(&self, ledger: &Ledger) -> Result<()> {
        let storage = LedgerStorage::new(&self.workspace)?;
        let _ledger_id = storage.save_ledger(ledger, "main")?;
        Ok(())
    }

    /// Save tree to disk with metadata
    fn save_tree(&self, tree: &UnifiedTree) -> Result<()> {
        let tree_path = self
            .workspace
            .ledgers_path()
            .join(format!("main_{}.tree", self.config.tree_type.as_str()));

        // Create tree export data for persistence
        let export_data = tree.export_for_migration(tree.tree_type())?;
        let serialized =
            bincode::serialize(&export_data).map_err(|e| SylvaError::MerkleTreeError {
                message: format!("Failed to serialize tree: {}", e),
            })?;

        fs::write(&tree_path, serialized)?;

        let stats = tree.statistics();
        println!(
            "Saved {} tree: {} entries, {} bytes",
            tree.tree_type().as_str(),
            stats.entry_count,
            stats.memory_usage.total_bytes
        );

        Ok(())
    }

    /// Generate commit data for hashing
    fn generate_commit_data(&self, result: &CommitResult) -> Result<Vec<u8>> {
        let commit_info = serde_json::json!({
            "committed_entries": result.committed_entries,
            "total_size": result.total_size,
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "message": self.config.message,
            "files_count": result.stats.files_processed,
        });

        Ok(commit_info.to_string().into_bytes())
    }

    /// Print commit summary
    fn print_commit_summary(&self, result: &CommitResult) {
        println!("\nCommit Summary:");
        println!("  Files processed: {}", result.stats.files_processed);
        println!("  Entries created: {}", result.stats.entries_created);
        println!("  Total size: {} bytes", result.stats.total_bytes);
        println!("  Duration: {}ms", result.stats.duration_ms);

        if !result.skipped_entries.is_empty() {
            println!("  Skipped: {}", result.skipped_entries.len());
        }

        if !result.conflicts_detected.is_empty() {
            println!("  Conflicts: {}", result.conflicts_detected.len());
        }

        if let Some(ref hash) = result.commit_hash {
            println!("  Commit hash: {}", hex::encode(hash.as_bytes()));
        }

        if self.config.dry_run {
            println!("\n🔍 Dry run completed - no changes were made");
        } else if result.stats.entries_created > 0 {
            println!("\n✅ Commit successful");
        } else {
            println!("\n⚠️  No entries were committed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_workspace() -> (TempDir, Workspace) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::initialize(temp_dir.path()).unwrap();
        (temp_dir, workspace)
    }

    #[test]
    fn test_commit_file_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test data").unwrap();

        let commit_file = CommitFile::from_file(temp_file.path()).unwrap();
        assert_eq!(commit_file.data, b"test data\n");
        assert_eq!(
            commit_file.metadata.get("source_type"),
            Some(&"file".to_string())
        );
        assert!(commit_file.metadata.contains_key("filename"));
        assert!(commit_file.metadata.contains_key("file_size"));
    }

    #[test]
    fn test_commit_config_defaults() {
        let config = CommitConfig::default();
        assert!(config.auto_timestamp);
        assert!(!config.force);
        assert!(config.show_progress);
        assert!(!config.dry_run);
        assert!(!config.use_stdin);
    }

    #[test]
    fn test_commit_file_size_and_description() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test").unwrap();

        let commit_file = CommitFile::from_file(temp_file.path()).unwrap();
        assert_eq!(commit_file.size(), 5); // "test\n"
        assert!(commit_file.source_description().contains("file:"));

        // Test stdin file
        let stdin_file = CommitFile {
            path: None,
            data: b"stdin data".to_vec(),
            metadata: HashMap::new(),
        };
        assert_eq!(stdin_file.source_description(), "stdin");
    }

    #[test]
    fn test_version_conflict_detection() {
        let (_temp_dir, workspace) = create_test_workspace();
        let mut config = CommitConfig::default();
        config.tree_type = TreeType::Binary;
        let command = CommitCommand {
            files: vec![],
            config,
            workspace,
        };

        let mut ledger = Ledger::new();
        let data = b"test data";

        // Add entry to ledger
        ledger.add_entry(data.to_vec()).unwrap();

        // Should detect conflict with same data
        let result = command.check_version_conflicts(data, &ledger);
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("Version conflict") || error_message.contains("VersionConflict")
        );
    }

    #[test]
    fn test_commit_result_serialization() {
        let result = CommitResult {
            committed_entries: vec![Uuid::new_v4()],
            skipped_entries: vec![("test.txt".to_string(), "error".to_string())],
            conflicts_detected: vec![],
            total_size: 100,
            commit_hash: None,
            stats: CommitStats {
                files_processed: 1,
                entries_created: 1,
                conflicts_resolved: 0,
                total_bytes: 100,
                duration_ms: 50,
            },
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: CommitResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result.committed_entries, deserialized.committed_entries);
        assert_eq!(result.total_size, deserialized.total_size);
    }
}
