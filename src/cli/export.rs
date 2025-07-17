use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, Hash as HashTrait};
use crate::ledger::{Ledger, LedgerEntry};
use crate::tree::{binary::BinaryMerkleTree, Tree};
use crate::workspace::Workspace;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Export format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Binary,
    Hex,
}

impl ExportFormat {
    /// Parse format from string
    pub fn parse_format(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ExportFormat::Json),
            "binary" | "bin" => Ok(ExportFormat::Binary),
            "hex" => Ok(ExportFormat::Hex),
            _ => Err(SylvaError::ConfigError {
                message: format!(
                    "Unsupported export format: {}. Supported formats: json, binary, hex",
                    s
                ),
            }),
        }
    }

    /// Get file extension for format
    pub fn file_extension(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Binary => "bin",
            ExportFormat::Hex => "hex",
        }
    }

    /// Get MIME type for format
    pub fn mime_type(&self) -> &'static str {
        match self {
            ExportFormat::Json => "application/json",
            ExportFormat::Binary => "application/octet-stream",
            ExportFormat::Hex => "text/plain",
        }
    }
}

/// Configuration for export operations
#[derive(Debug, Clone)]
pub struct ExportConfig {
    pub format: ExportFormat,
    pub output_path: Option<PathBuf>,
    pub pretty_print: bool,
    pub include_metadata: bool,
    pub validate_output: bool,
    pub chunk_size: usize,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: ExportFormat::Json,
            output_path: None,
            pretty_print: true,
            include_metadata: true,
            validate_output: true,
            chunk_size: 1024 * 1024, // 1MB chunks for streaming
        }
    }
}

/// Serializable tree structure for JSON export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportableTree {
    pub metadata: TreeMetadata,
    pub root: Option<ExportableNode>,
    pub entries: Vec<ExportableEntry>,
    pub statistics: TreeStatistics,
}

/// Tree metadata for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeMetadata {
    pub ledger_name: String,
    pub version: String,
    pub export_timestamp: u64,
    pub export_format: String,
    pub hash_function: String,
    pub total_entries: usize,
    pub tree_height: usize,
}

/// Exportable tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportableNode {
    pub hash: String,
    pub is_leaf: bool,
    pub level: usize,
    pub index: usize,
    pub left_child: Option<Box<ExportableNode>>,
    pub right_child: Option<Box<ExportableNode>>,
    pub entry_data: Option<ExportableEntry>,
}

/// Exportable ledger entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportableEntry {
    pub id: String,
    pub version: u64,
    pub timestamp: u64,
    pub data_hash: String,
    pub data_size: usize,
    pub metadata: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>, // Base64 encoded for JSON
    pub previous_hash: Option<String>,
}

/// Tree statistics for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeStatistics {
    pub total_nodes: usize,
    pub leaf_nodes: usize,
    pub internal_nodes: usize,
    pub tree_depth: usize,
    pub total_data_size: usize,
    pub average_entry_size: f64,
    pub export_size_bytes: usize,
}

/// Binary export header
#[derive(Debug, Clone)]
pub struct BinaryExportHeader {
    pub magic: [u8; 4],     // "SYLV"
    pub version: u32,       // Export format version
    pub format_type: u8,    // 1 = binary
    pub compression: u8,    // 0 = none, 1 = zlib
    pub hash_algorithm: u8, // 1 = blake3
    pub entry_count: u64,
    pub tree_height: u32,
    pub timestamp: u64,
    pub data_offset: u64,   // Offset to tree data
    pub metadata_size: u32, // Size of metadata section
}

impl BinaryExportHeader {
    pub const MAGIC: [u8; 4] = *b"SYLV";
    pub const CURRENT_VERSION: u32 = 1;
    pub const SIZE: usize = 64; // Fixed header size

    pub fn new(entry_count: usize, tree_height: usize) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::CURRENT_VERSION,
            format_type: 1,
            compression: 0,
            hash_algorithm: 1,
            entry_count: entry_count as u64,
            tree_height: tree_height as u32,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            data_offset: Self::SIZE as u64,
            metadata_size: 0,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.magic); // 4 bytes
        bytes.extend_from_slice(&self.version.to_le_bytes()); // 4 bytes
        bytes.push(self.format_type); // 1 byte
        bytes.push(self.compression); // 1 byte
        bytes.push(self.hash_algorithm); // 1 byte
        bytes.push(0); // Reserved byte                          // 1 byte
        bytes.extend_from_slice(&self.entry_count.to_le_bytes()); // 8 bytes
        bytes.extend_from_slice(&self.tree_height.to_le_bytes()); // 4 bytes
        bytes.extend_from_slice(&[0u8; 4]); // Padding           // 4 bytes
        bytes.extend_from_slice(&self.timestamp.to_le_bytes()); // 8 bytes
        bytes.extend_from_slice(&self.data_offset.to_le_bytes()); // 8 bytes
        bytes.extend_from_slice(&self.metadata_size.to_le_bytes()); // 4 bytes
        bytes.extend_from_slice(&[0u8; 16]); // Reserved for future use // 16 bytes

        assert_eq!(bytes.len(), Self::SIZE);
        bytes
    }
}

/// Export command implementation
#[derive(Debug)]
pub struct ExportCommand {
    workspace: Workspace,
    config: ExportConfig,
}

impl ExportCommand {
    /// Create a new export command from CLI arguments
    pub fn from_args(matches: &ArgMatches) -> Result<Self> {
        let workspace = Workspace::find_workspace()?;

        let format = matches
            .get_one::<String>("format")
            .map(|s| ExportFormat::parse_format(s))
            .transpose()?
            .unwrap_or(ExportFormat::Json);

        let output_path = matches.get_one::<String>("output").map(PathBuf::from);

        let config = ExportConfig {
            format,
            output_path,
            pretty_print: !matches.get_flag("compact"),
            include_metadata: !matches.get_flag("no-metadata"),
            validate_output: !matches.get_flag("no-validate"),
            chunk_size: matches
                .get_one::<String>("chunk-size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024),
        };

        Ok(Self { workspace, config })
    }

    /// Execute the export command
    pub fn execute(&self, ledger_name: &str) -> Result<()> {
        println!(
            "Exporting ledger '{}' in {} format...",
            ledger_name,
            format!("{:?}", self.config.format).to_lowercase()
        );

        // Load ledger
        let ledger = self.load_ledger(ledger_name)?;

        // Build tree
        let tree = self.build_tree_from_ledger(&ledger)?;

        // Determine output path
        let output_path = self.get_output_path(ledger_name);

        // Export based on format
        match self.config.format {
            ExportFormat::Json => self.export_json(&tree, &ledger, &output_path)?,
            ExportFormat::Binary => self.export_binary(&tree, &ledger, &output_path)?,
            ExportFormat::Hex => self.export_hex(&tree, &ledger, &output_path)?,
        }

        // Validate output if requested
        if self.config.validate_output {
            self.validate_export(&output_path)?;
        }

        // Display summary
        self.display_export_summary(&output_path, &ledger)?;

        Ok(())
    }

    /// Load ledger from file
    fn load_ledger(&self, ledger_name: &str) -> Result<Ledger> {
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
        Ok(serializable_ledger.ledger)
    }

    /// Build Merkle tree from ledger
    fn build_tree_from_ledger(&self, ledger: &Ledger) -> Result<BinaryMerkleTree> {
        let mut tree = BinaryMerkleTree::new();

        for entry in ledger.get_entries() {
            tree.insert(entry.clone())?;
        }

        Ok(tree)
    }

    /// Get output path for export
    fn get_output_path(&self, ledger_name: &str) -> PathBuf {
        if let Some(ref path) = self.config.output_path {
            path.clone()
        } else {
            let filename = format!(
                "{}_export.{}",
                ledger_name,
                self.config.format.file_extension()
            );
            self.workspace.root_path().join(filename)
        }
    }

    /// Export tree to JSON format
    fn export_json(
        &self,
        tree: &BinaryMerkleTree,
        ledger: &Ledger,
        output_path: &Path,
    ) -> Result<()> {
        let exportable_tree = self.convert_to_exportable_tree(tree, ledger, "main")?;

        let file = File::create(output_path)?;
        let writer = BufWriter::new(file);

        if self.config.pretty_print {
            serde_json::to_writer_pretty(writer, &exportable_tree)?;
        } else {
            serde_json::to_writer(writer, &exportable_tree)?;
        }

        Ok(())
    }

    /// Export tree to binary format
    fn export_binary(
        &self,
        tree: &BinaryMerkleTree,
        ledger: &Ledger,
        output_path: &Path,
    ) -> Result<()> {
        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);

        // Write header
        let header = BinaryExportHeader::new(ledger.entry_count(), tree.height());
        writer.write_all(&header.to_bytes())?;

        // Write entries in binary format
        for entry in ledger.get_entries() {
            self.write_entry_binary(&mut writer, entry)?;
        }

        // Write tree structure
        if let Some(root_hash) = tree.root_hash() {
            writer.write_all(root_hash.as_bytes())?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Export tree to hex format
    fn export_hex(
        &self,
        tree: &BinaryMerkleTree,
        ledger: &Ledger,
        output_path: &Path,
    ) -> Result<()> {
        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);

        // Write header information
        writeln!(writer, "# Sylva Tree Export - Hex Format")?;
        writeln!(
            writer,
            "# Export timestamp: {}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        )?;
        writeln!(writer, "# Entries: {}", ledger.entry_count())?;
        writeln!(writer, "# Tree height: {}", tree.height())?;

        if let Some(root_hash) = tree.root_hash() {
            writeln!(writer, "# Root hash: {}", hex::encode(root_hash.as_bytes()))?;
        }

        writeln!(writer)?;

        // Write entries in hex format
        for (i, entry) in ledger.get_entries().iter().enumerate() {
            writeln!(writer, "## Entry {} (Version {})", i, entry.version)?;
            writeln!(writer, "ID: {}", entry.id)?;
            writeln!(writer, "Timestamp: {}", entry.timestamp)?;
            writeln!(writer, "Data: {}", hex::encode(&entry.data))?;

            let hasher = Blake3Hasher::new();
            let data_hash = hasher.hash_bytes(&entry.data)?;
            writeln!(writer, "Data Hash: {}", hex::encode(data_hash.as_bytes()))?;

            if let Some(ref prev_hash) = entry.previous_hash {
                writeln!(
                    writer,
                    "Previous Hash: {}",
                    hex::encode(prev_hash.as_bytes())
                )?;
            }

            if !entry.metadata.is_empty() {
                writeln!(writer, "Metadata:")?;
                for (key, value) in &entry.metadata {
                    writeln!(writer, "  {}: {}", key, value)?;
                }
            }

            writeln!(writer)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Write entry in binary format
    fn write_entry_binary(&self, writer: &mut BufWriter<File>, entry: &LedgerEntry) -> Result<()> {
        // Entry format: [id_len][id][timestamp][version][data_len][data][metadata_len][metadata]

        let id_bytes = entry.id.to_string().into_bytes();
        writer.write_all(&(id_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&id_bytes)?;

        writer.write_all(&entry.timestamp.to_le_bytes())?;
        writer.write_all(&entry.version.to_le_bytes())?;

        writer.write_all(&(entry.data.len() as u64).to_le_bytes())?;
        writer.write_all(&entry.data)?;

        // Serialize metadata
        let metadata_bytes =
            bincode::serialize(&entry.metadata).map_err(|e| SylvaError::MerkleTreeError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;
        writer.write_all(&(metadata_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&metadata_bytes)?;

        // Write previous hash if present
        if let Some(ref prev_hash) = entry.previous_hash {
            writer.write_all(&[1u8])?; // Has previous hash
            writer.write_all(prev_hash.as_bytes())?;
        } else {
            writer.write_all(&[0u8])?; // No previous hash
        }

        Ok(())
    }

    /// Convert tree to exportable format
    fn convert_to_exportable_tree(
        &self,
        tree: &BinaryMerkleTree,
        ledger: &Ledger,
        ledger_name: &str,
    ) -> Result<ExportableTree> {
        let entries: Vec<ExportableEntry> = ledger
            .get_entries()
            .iter()
            .map(|entry| self.convert_to_exportable_entry(entry))
            .collect::<Result<Vec<_>>>()?;

        let total_data_size = entries.iter().map(|e| e.data_size).sum::<usize>();
        let average_entry_size = if entries.is_empty() {
            0.0
        } else {
            total_data_size as f64 / entries.len() as f64
        };

        let statistics = TreeStatistics {
            total_nodes: 0, // Would need tree traversal to calculate
            leaf_nodes: entries.len(),
            internal_nodes: 0, // Would need tree traversal to calculate
            tree_depth: tree.height(),
            total_data_size,
            average_entry_size,
            export_size_bytes: 0, // Will be calculated after export
        };

        let metadata = TreeMetadata {
            ledger_name: ledger_name.to_string(),
            version: "1.0".to_string(),
            export_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            export_format: format!("{:?}", self.config.format).to_lowercase(),
            hash_function: "blake3".to_string(),
            total_entries: entries.len(),
            tree_height: tree.height(),
        };

        Ok(ExportableTree {
            metadata,
            root: None, // Tree structure would require extensive traversal
            entries,
            statistics,
        })
    }

    /// Convert ledger entry to exportable format
    fn convert_to_exportable_entry(&self, entry: &LedgerEntry) -> Result<ExportableEntry> {
        let hasher = Blake3Hasher::new();
        let data_hash = hasher.hash_bytes(&entry.data)?;

        let data = if self.config.include_metadata {
            use base64::prelude::*;
            Some(BASE64_STANDARD.encode(&entry.data))
        } else {
            None
        };

        Ok(ExportableEntry {
            id: entry.id.to_string(),
            version: entry.version,
            timestamp: entry.timestamp,
            data_hash: hex::encode(data_hash.as_bytes()),
            data_size: entry.data.len(),
            metadata: entry.metadata.clone(),
            data,
            previous_hash: entry
                .previous_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes())),
        })
    }

    /// Validate exported file
    fn validate_export(&self, output_path: &Path) -> Result<()> {
        if !output_path.exists() {
            return Err(SylvaError::IoError {
                source: io::Error::new(io::ErrorKind::NotFound, "Export file not found"),
            });
        }

        let metadata = fs::metadata(output_path)?;
        if metadata.len() == 0 {
            return Err(SylvaError::MerkleTreeError {
                message: "Export file is empty".to_string(),
            });
        }

        // Format-specific validation
        match self.config.format {
            ExportFormat::Json => self.validate_json_export(output_path)?,
            ExportFormat::Binary => self.validate_binary_export(output_path)?,
            ExportFormat::Hex => self.validate_hex_export(output_path)?,
        }

        Ok(())
    }

    /// Validate JSON export
    fn validate_json_export(&self, output_path: &Path) -> Result<()> {
        let content = fs::read_to_string(output_path)?;
        let _: ExportableTree =
            serde_json::from_str(&content).map_err(|e| SylvaError::MerkleTreeError {
                message: format!("Invalid JSON export: {}", e),
            })?;
        Ok(())
    }

    /// Validate binary export
    fn validate_binary_export(&self, output_path: &Path) -> Result<()> {
        let data = fs::read(output_path)?;

        if data.len() < BinaryExportHeader::SIZE {
            return Err(SylvaError::MerkleTreeError {
                message: "Binary export file too small".to_string(),
            });
        }

        // Check magic number
        if data[0..4] != BinaryExportHeader::MAGIC {
            return Err(SylvaError::MerkleTreeError {
                message: "Invalid binary export magic number".to_string(),
            });
        }

        Ok(())
    }

    /// Validate hex export
    fn validate_hex_export(&self, output_path: &Path) -> Result<()> {
        let content = fs::read_to_string(output_path)?;

        if !content.starts_with("# Sylva Tree Export - Hex Format") {
            return Err(SylvaError::MerkleTreeError {
                message: "Invalid hex export header".to_string(),
            });
        }

        Ok(())
    }

    /// Display export summary
    fn display_export_summary(&self, output_path: &Path, ledger: &Ledger) -> Result<()> {
        let metadata = fs::metadata(output_path)?;
        let file_size = metadata.len();

        println!("Export completed successfully!");
        println!("  Output file: {}", output_path.display());
        println!("  Format: {:?}", self.config.format);
        println!("  File size: {}", self.format_bytes(file_size as usize));
        println!("  Entries exported: {}", ledger.entry_count());
        println!("  MIME type: {}", self.config.format.mime_type());

        if self.config.validate_output {
            println!("  Validation: ✅ Passed");
        }

        Ok(())
    }

    /// Format bytes in human-readable format
    fn format_bytes(&self, bytes: usize) -> String {
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
}

/// Handle CLI arguments for export command
pub fn handle_export_command(matches: &ArgMatches) -> Result<()> {
    let export_cmd = ExportCommand::from_args(matches)?;

    if let Some(ledger_name) = matches.get_one::<String>("ledger") {
        export_cmd.execute(ledger_name)
    } else {
        Err(SylvaError::ConfigError {
            message: "Ledger name is required for export command".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerEntry;
    use std::collections::HashMap;
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
            metadata.insert("source".to_string(), "test".to_string());
            metadata.insert("index".to_string(), i.to_string());

            ledger.add_entry_with_metadata(format!("test data {}", i).into_bytes(), metadata)?;
        }

        // Save ledger using proper storage
        let storage = LedgerStorage::new(workspace)?;
        storage.save_ledger(&ledger, name)?;

        Ok(())
    }

    #[test]
    fn test_export_format_parsing() {
        assert_eq!(
            ExportFormat::parse_format("json").unwrap(),
            ExportFormat::Json
        );
        assert_eq!(
            ExportFormat::parse_format("JSON").unwrap(),
            ExportFormat::Json
        );
        assert_eq!(
            ExportFormat::parse_format("binary").unwrap(),
            ExportFormat::Binary
        );
        assert_eq!(
            ExportFormat::parse_format("bin").unwrap(),
            ExportFormat::Binary
        );
        assert_eq!(
            ExportFormat::parse_format("hex").unwrap(),
            ExportFormat::Hex
        );

        assert!(ExportFormat::parse_format("invalid").is_err());
    }

    #[test]
    fn test_export_format_properties() {
        assert_eq!(ExportFormat::Json.file_extension(), "json");
        assert_eq!(ExportFormat::Binary.file_extension(), "bin");
        assert_eq!(ExportFormat::Hex.file_extension(), "hex");

        assert_eq!(ExportFormat::Json.mime_type(), "application/json");
        assert_eq!(ExportFormat::Binary.mime_type(), "application/octet-stream");
        assert_eq!(ExportFormat::Hex.mime_type(), "text/plain");
    }

    #[test]
    fn test_binary_export_header() {
        let header = BinaryExportHeader::new(100, 7);

        assert_eq!(header.magic, BinaryExportHeader::MAGIC);
        assert_eq!(header.version, BinaryExportHeader::CURRENT_VERSION);
        assert_eq!(header.entry_count, 100);
        assert_eq!(header.tree_height, 7);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), BinaryExportHeader::SIZE);
        assert_eq!(&bytes[0..4], &BinaryExportHeader::MAGIC);
    }

    #[test]
    fn test_json_export() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 3).unwrap();

        let config = ExportConfig {
            format: ExportFormat::Json,
            output_path: Some(workspace.root_path().join("test_export.json")),
            pretty_print: true,
            include_metadata: true,
            validate_output: true,
            chunk_size: 1024,
        };

        let export_cmd = ExportCommand { workspace, config };

        assert!(export_cmd.execute("test").is_ok());

        // Verify output file exists and is valid JSON
        let output_path = export_cmd.workspace.root_path().join("test_export.json");
        assert!(output_path.exists());

        let content = fs::read_to_string(&output_path).unwrap();
        let exported_tree: ExportableTree = serde_json::from_str(&content).unwrap();

        assert_eq!(exported_tree.entries.len(), 3);
        assert_eq!(exported_tree.metadata.total_entries, 3);
        assert_eq!(exported_tree.metadata.export_format, "json");
    }

    #[test]
    fn test_binary_export() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 2).unwrap();

        let config = ExportConfig {
            format: ExportFormat::Binary,
            output_path: Some(workspace.root_path().join("test_export.bin")),
            pretty_print: false,
            include_metadata: true,
            validate_output: true,
            chunk_size: 1024,
        };

        let export_cmd = ExportCommand { workspace, config };

        assert!(export_cmd.execute("test").is_ok());

        // Verify output file exists and has valid header
        let output_path = export_cmd.workspace.root_path().join("test_export.bin");
        assert!(output_path.exists());

        let data = fs::read(&output_path).unwrap();
        assert!(data.len() >= BinaryExportHeader::SIZE);
        assert_eq!(&data[0..4], &BinaryExportHeader::MAGIC);
    }

    #[test]
    fn test_hex_export() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 2).unwrap();

        let config = ExportConfig {
            format: ExportFormat::Hex,
            output_path: Some(workspace.root_path().join("test_export.hex")),
            pretty_print: false,
            include_metadata: true,
            validate_output: true,
            chunk_size: 1024,
        };

        let export_cmd = ExportCommand { workspace, config };

        assert!(export_cmd.execute("test").is_ok());

        // Verify output file exists and has valid header
        let output_path = export_cmd.workspace.root_path().join("test_export.hex");
        assert!(output_path.exists());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.starts_with("# Sylva Tree Export - Hex Format"));
        assert!(content.contains("## Entry 0"));
    }

    #[test]
    fn test_export_validation() {
        let (_temp_dir, workspace) = create_test_workspace();
        create_test_ledger_with_entries(&workspace, "test", 1).unwrap();

        let config = ExportConfig {
            format: ExportFormat::Json,
            output_path: Some(workspace.root_path().join("test_validation.json")),
            validate_output: true,
            ..Default::default()
        };

        let export_cmd = ExportCommand { workspace, config };

        // Export should succeed with validation
        assert!(export_cmd.execute("test").is_ok());

        // Manually verify validation works
        let output_path = export_cmd
            .workspace
            .root_path()
            .join("test_validation.json");
        assert!(export_cmd.validate_export(&output_path).is_ok());
    }

    #[test]
    fn test_exportable_entry_conversion() {
        let (_temp_dir, workspace) = create_test_workspace();
        let config = ExportConfig::default();
        let export_cmd = ExportCommand { workspace, config };

        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), "test_value".to_string());

        let entry = LedgerEntry::new(b"test data".to_vec(), 1).with_metadata(metadata.clone());

        let exportable = export_cmd.convert_to_exportable_entry(&entry).unwrap();

        assert_eq!(exportable.version, 1);
        assert_eq!(exportable.data_size, 9);
        assert_eq!(exportable.metadata, metadata);
        assert!(exportable.data.is_some());
        assert!(!exportable.data_hash.is_empty());
    }

    #[test]
    fn test_nonexistent_ledger() {
        let (_temp_dir, workspace) = create_test_workspace();
        let config = ExportConfig::default();
        let export_cmd = ExportCommand { workspace, config };

        let result = export_cmd.execute("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_format_bytes() {
        let (_temp_dir, workspace) = create_test_workspace();
        let config = ExportConfig::default();
        let export_cmd = ExportCommand { workspace, config };

        assert_eq!(export_cmd.format_bytes(0), "0 B");
        assert_eq!(export_cmd.format_bytes(512), "512 B");
        assert_eq!(export_cmd.format_bytes(1024), "1.0 KB");
        assert_eq!(export_cmd.format_bytes(1536), "1.5 KB");
        assert_eq!(export_cmd.format_bytes(1048576), "1.0 MB");
    }
}
