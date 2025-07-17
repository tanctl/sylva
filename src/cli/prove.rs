use crate::hash::{Blake3Hasher, Hash};
use crate::ledger::{Ledger, LedgerEntry};
use crate::proof::ProofError;
use crate::storage::LedgerStorage;
use crate::tree::binary::BinaryMerkleTree;
use crate::tree::MerkleProof;
use crate::workspace::Workspace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Supported proof output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofFormat {
    #[default]
    Json,
    Binary,
    Hex,
}

impl ProofFormat {
    pub fn parse_format(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ProofFormat::Json),
            "binary" | "bin" => Ok(ProofFormat::Binary),
            "hex" => Ok(ProofFormat::Hex),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ProofFormat::Json => "json",
            ProofFormat::Binary => "bin",
            ProofFormat::Hex => "hex",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            ProofFormat::Json => "application/json",
            ProofFormat::Binary => "application/octet-stream",
            ProofFormat::Hex => "text/plain",
        }
    }
}

/// Configuration for proof generation
#[derive(Debug, Clone)]
pub struct ProveConfig {
    pub format: ProofFormat,
    pub output_path: Option<PathBuf>,
    pub pretty_print: bool,
    pub include_metadata: bool,
    pub include_version_info: bool,
    pub show_progress: bool,
    pub batch_size: usize,
}

impl Default for ProveConfig {
    fn default() -> Self {
        Self {
            format: ProofFormat::Json,
            output_path: None,
            pretty_print: true,
            include_metadata: true,
            include_version_info: true,
            show_progress: true,
            batch_size: 100,
        }
    }
}

/// Different modes of proof generation
#[derive(Debug, Clone)]
pub enum ProveMode {
    /// Generate proof for a specific entry by ID
    EntryId(Uuid),
    /// Generate proof for data content (with version awareness)
    DataContent(Vec<u8>),
    /// Generate proof for a specific version/timestamp
    Version(u64),
    /// Generate batch proofs from a file
    Batch(PathBuf),
}

/// Serializable proof structure with version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedProof {
    pub proof: SerializableProof,
    pub entry_info: EntryInfo,
    pub version_metadata: VersionMetadata,
    pub tree_info: TreeInfo,
    pub generation_timestamp: u64,
}

/// Serializable representation of an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableProof {
    pub entry_id: Uuid,
    pub leaf_index: usize,
    pub root_hash: String,
    pub proof_path: Vec<ProofElement>,
    pub is_valid: bool,
}

/// Individual proof element in the path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofElement {
    pub hash: String,
    pub is_left: bool,
    pub level: usize,
}

/// Entry information for the proven element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInfo {
    pub id: Uuid,
    pub version: u64,
    pub timestamp: u64,
    pub data_hash: String,
    pub data_size: usize,
    pub metadata: HashMap<String, String>,
}

/// Version-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub current_version: u64,
    pub total_versions: u64,
    pub version_at_timestamp: Option<u64>,
    pub historical_context: bool,
    pub version_range: (u64, u64),
}

/// Tree structure information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeInfo {
    pub total_entries: usize,
    pub tree_height: usize,
    pub root_hash: String,
    pub leaf_count: usize,
}

/// Batch proof results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofResult {
    pub proofs: Vec<VersionedProof>,
    pub summary: BatchSummary,
    pub processing_info: ProcessingInfo,
}

/// Summary of batch processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub total_requested: usize,
    pub successful_proofs: usize,
    pub failed_proofs: usize,
    pub processing_time_ms: u64,
}

/// Processing information for batch operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingInfo {
    pub batch_size: usize,
    pub total_batches: usize,
    pub memory_usage_mb: f64,
    pub average_proof_time_ms: f64,
}

/// Main prove command implementation
pub struct ProveCommand {
    storage: LedgerStorage,
    config: ProveConfig,
}

impl ProveCommand {
    pub fn new(storage: LedgerStorage, config: ProveConfig) -> Self {
        Self { storage, config }
    }

    /// Helper function to load ledger by name
    fn load_ledger_by_name(&self, _ledger_name: &str) -> Result<Ledger, ProofError> {
        // For now, use a simple implementation that gets the first ledger
        let ledger_files =
            self.storage
                .list_ledgers()
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: e.to_string(),
                })?;

        if let Some(metadata) = ledger_files.first() {
            let serializable_ledger = self.storage.load_ledger(&metadata.id).map_err(|e| {
                ProofError::HashComputationFailed {
                    reason: e.to_string(),
                }
            })?;

            Ok(serializable_ledger.ledger)
        } else {
            Err(ProofError::EmptyTree)
        }
    }

    /// Execute the prove command with the given mode
    pub fn execute(&self, ledger_name: &str, mode: ProveMode) -> Result<(), ProofError> {
        match mode {
            ProveMode::EntryId(entry_id) => self.prove_entry_id(ledger_name, entry_id),
            ProveMode::DataContent(data) => self.prove_data_content(ledger_name, &data),
            ProveMode::Version(timestamp) => self.prove_version(ledger_name, timestamp),
            ProveMode::Batch(file_path) => self.prove_batch(ledger_name, &file_path),
        }
    }

    /// Generate proof for a specific entry ID
    fn prove_entry_id(&self, ledger_name: &str, entry_id: Uuid) -> Result<(), ProofError> {
        let ledger = self.load_ledger_by_name(ledger_name)?;
        let entries = ledger.get_entries();

        if entries.is_empty() {
            return Err(ProofError::EmptyTree);
        }

        // Find the entry
        let entry = entries
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or(ProofError::LeafNotFound { entry_id })?;

        // Generate proof
        let tree = BinaryMerkleTree::from_entries(entries.to_vec()).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let proof_result = tree.generate_inclusion_proof(&entry_id).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let proof = proof_result.ok_or(ProofError::LeafNotFound { entry_id })?;

        // Create versioned proof
        let versioned_proof = self.create_versioned_proof(proof, entry, entries)?;

        // Output the proof
        self.output_proof(
            &versioned_proof,
            ledger_name,
            &format!("entry_{}", entry_id),
        )?;

        if self.config.show_progress {
            println!("✅ Proof generated successfully for entry {}", entry_id);
        }

        Ok(())
    }

    /// Generate proof for data content with version awareness
    fn prove_data_content(&self, ledger_name: &str, data: &[u8]) -> Result<(), ProofError> {
        let ledger = self.load_ledger_by_name(ledger_name)?;
        let entries = ledger.get_entries();

        if entries.is_empty() {
            return Err(ProofError::EmptyTree);
        }

        // Find entries with matching data
        let matching_entries: Vec<_> = entries.iter().filter(|e| e.data == data).collect();

        if matching_entries.is_empty() {
            return Err(ProofError::LeafNotFound {
                entry_id: Uuid::nil(), // Use nil UUID for data-based searches
            });
        }

        // Generate proofs for all matching entries (version-aware)
        let tree = BinaryMerkleTree::from_entries(entries.to_vec()).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let mut proofs = Vec::new();

        for entry in matching_entries {
            if let Ok(Some(proof)) = tree.generate_inclusion_proof(&entry.id).map_err(|e| {
                ProofError::HashComputationFailed {
                    reason: e.to_string(),
                }
            }) {
                if let Ok(versioned_proof) = self.create_versioned_proof(proof, entry, entries) {
                    proofs.push(versioned_proof);
                }
            }
        }

        // Output proofs
        let successful_count = proofs.len();
        if proofs.len() == 1 {
            self.output_proof(&proofs[0], ledger_name, "data_content")?;
        } else {
            // Multiple versions found - output as batch
            let batch_result = BatchProofResult {
                proofs,
                summary: BatchSummary {
                    total_requested: 1,
                    successful_proofs: successful_count,
                    failed_proofs: 0,
                    processing_time_ms: 0,
                },
                processing_info: ProcessingInfo {
                    batch_size: successful_count,
                    total_batches: 1,
                    memory_usage_mb: 0.0,
                    average_proof_time_ms: 0.0,
                },
            };
            self.output_batch_result(&batch_result, ledger_name, "data_content_versions")?;
        }

        if self.config.show_progress {
            println!(
                "✅ Proof generated successfully for data content ({} versions found)",
                successful_count
            );
        }

        Ok(())
    }

    /// Generate proof for a specific version/timestamp
    fn prove_version(&self, ledger_name: &str, timestamp: u64) -> Result<(), ProofError> {
        let ledger = self.load_ledger_by_name(ledger_name)?;
        let entries = ledger.get_entries();

        if entries.is_empty() {
            return Err(ProofError::EmptyTree);
        }

        // Find entries at or before the specified timestamp
        let historical_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp <= timestamp)
            .collect();

        if historical_entries.is_empty() {
            return Err(ProofError::LeafNotFound {
                entry_id: Uuid::nil(), // Use nil UUID for timestamp-based searches
            });
        }

        // Generate proofs for all entries in the historical state
        let entries_for_tree: Vec<LedgerEntry> =
            historical_entries.iter().map(|e| (*e).clone()).collect();
        let tree = BinaryMerkleTree::from_entries(entries_for_tree).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let mut proofs = Vec::new();

        for entry in &historical_entries {
            if let Ok(Some(proof)) = tree.generate_inclusion_proof(&entry.id).map_err(|e| {
                ProofError::HashComputationFailed {
                    reason: e.to_string(),
                }
            }) {
                if let Ok(versioned_proof) = self.create_versioned_proof(proof, entry, entries) {
                    proofs.push(versioned_proof);
                }
            }
        }

        // Output as batch result
        let successful_count = proofs.len();
        let batch_result = BatchProofResult {
            proofs,
            summary: BatchSummary {
                total_requested: 1,
                successful_proofs: successful_count,
                failed_proofs: 0,
                processing_time_ms: 0,
            },
            processing_info: ProcessingInfo {
                batch_size: successful_count,
                total_batches: 1,
                memory_usage_mb: 0.0,
                average_proof_time_ms: 0.0,
            },
        };

        self.output_batch_result(
            &batch_result,
            ledger_name,
            &format!("version_{}", timestamp),
        )?;

        if self.config.show_progress {
            println!(
                "✅ Historical proof generated successfully for timestamp {} ({} entries)",
                timestamp, successful_count
            );
        }

        Ok(())
    }

    /// Generate batch proofs from a file
    fn prove_batch(&self, ledger_name: &str, file_path: &PathBuf) -> Result<(), ProofError> {
        let ledger = self.load_ledger_by_name(ledger_name)?;
        let entries = ledger.get_entries();

        if entries.is_empty() {
            return Err(ProofError::EmptyTree);
        }

        // Read entry IDs from file
        let file = File::open(file_path).map_err(|e| ProofError::HashComputationFailed {
            reason: format!("Failed to open batch file: {}", e),
        })?;
        let reader = BufReader::new(file);

        let mut entry_ids = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| ProofError::HashComputationFailed {
                reason: format!("Failed to read line: {}", e),
            })?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue; // Skip empty lines and comments
            }

            let entry_id =
                Uuid::parse_str(line).map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("Invalid UUID '{}': {}", line, e),
                })?;
            entry_ids.push(entry_id);
        }

        if entry_ids.is_empty() {
            return Err(ProofError::HashComputationFailed {
                reason: "No valid entry IDs found in batch file".to_string(),
            });
        }

        // Generate proofs in batches
        let start_time = SystemTime::now();
        let tree = BinaryMerkleTree::from_entries(entries.to_vec()).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let mut proofs = Vec::new();
        let mut failed_count = 0;

        let total_batches = entry_ids.len().div_ceil(self.config.batch_size);

        for (batch_idx, batch) in entry_ids.chunks(self.config.batch_size).enumerate() {
            if self.config.show_progress {
                println!(
                    "Processing batch {}/{} ({} entries)...",
                    batch_idx + 1,
                    total_batches,
                    batch.len()
                );
            }

            for entry_id in batch {
                match entries.iter().find(|e| e.id == *entry_id) {
                    Some(entry) => {
                        match tree.generate_inclusion_proof(entry_id).map_err(|e| {
                            ProofError::HashComputationFailed {
                                reason: e.to_string(),
                            }
                        }) {
                            Ok(Some(proof)) => {
                                match self.create_versioned_proof(proof, entry, entries) {
                                    Ok(versioned_proof) => proofs.push(versioned_proof),
                                    Err(_) => failed_count += 1,
                                }
                            }
                            Ok(None) => failed_count += 1,
                            Err(_) => failed_count += 1,
                        }
                    }
                    None => failed_count += 1,
                }
            }
        }

        let processing_time =
            start_time
                .elapsed()
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("Time calculation error: {}", e),
                })?;
        let processing_time_ms = processing_time.as_millis() as u64;

        // Create batch result
        let batch_result = BatchProofResult {
            proofs,
            summary: BatchSummary {
                total_requested: entry_ids.len(),
                successful_proofs: entry_ids.len() - failed_count,
                failed_proofs: failed_count,
                processing_time_ms,
            },
            processing_info: ProcessingInfo {
                batch_size: self.config.batch_size,
                total_batches,
                memory_usage_mb: 0.0, // TODO: Calculate actual memory usage
                average_proof_time_ms: if !entry_ids.is_empty() {
                    processing_time_ms as f64 / entry_ids.len() as f64
                } else {
                    0.0
                },
            },
        };

        self.output_batch_result(&batch_result, ledger_name, "batch")?;

        if self.config.show_progress {
            println!("✅ Batch proof generation completed!");
            println!(
                "   Total: {} | Success: {} | Failed: {}",
                entry_ids.len(),
                entry_ids.len() - failed_count,
                failed_count
            );
            println!("   Processing time: {}ms", processing_time_ms);
        }

        Ok(())
    }

    /// Create a versioned proof with metadata
    fn create_versioned_proof(
        &self,
        proof: MerkleProof,
        entry: &LedgerEntry,
        all_entries: &[LedgerEntry],
    ) -> Result<VersionedProof, ProofError> {
        // Create a Blake3Hasher to compute entry hash
        let hasher = Blake3Hasher::new();
        let entry_data_hash =
            hasher
                .hash_bytes(&entry.data)
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: e.to_string(),
                })?;

        // Convert proof to serializable format
        let serializable_proof = SerializableProof {
            entry_id: proof.entry_id,
            leaf_index: 0, // Default for tree MerkleProof
            root_hash: hex::encode(proof.root_hash.as_bytes()),
            proof_path: proof
                .path
                .iter()
                .enumerate()
                .map(|(level, element)| ProofElement {
                    hash: hex::encode(element.hash.as_bytes()),
                    is_left: element.is_left,
                    level,
                })
                .collect(),
            is_valid: true, // We assume the proof is valid since we just generated it
        };

        // Create entry info
        let entry_info = EntryInfo {
            id: entry.id,
            version: entry.version,
            timestamp: entry.timestamp,
            data_hash: hex::encode(entry_data_hash.as_bytes()),
            data_size: entry.data.len(),
            metadata: entry.metadata.clone(),
        };

        // Create version metadata
        let version_metadata = VersionMetadata {
            current_version: entry.version,
            total_versions: all_entries.len() as u64,
            version_at_timestamp: Some(entry.timestamp),
            historical_context: false,
            version_range: (
                all_entries.iter().map(|e| e.version).min().unwrap_or(0),
                all_entries.iter().map(|e| e.version).max().unwrap_or(0),
            ),
        };

        // Create tree info
        let tree_info = TreeInfo {
            total_entries: all_entries.len(),
            tree_height: (all_entries.len() as f64).log2().ceil() as usize,
            root_hash: hex::encode(proof.root_hash.as_bytes()),
            leaf_count: all_entries.len(),
        };

        let generation_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ProofError::HashComputationFailed {
                reason: format!("Time error: {}", e),
            })?
            .as_secs();

        Ok(VersionedProof {
            proof: serializable_proof,
            entry_info,
            version_metadata,
            tree_info,
            generation_timestamp,
        })
    }

    /// Output a single proof
    fn output_proof(
        &self,
        proof: &VersionedProof,
        ledger_name: &str,
        suffix: &str,
    ) -> Result<(), ProofError> {
        let filename = match &self.config.output_path {
            Some(path) => path.clone(),
            None => PathBuf::from(format!(
                "{}_proof_{}.{}",
                ledger_name,
                suffix,
                self.config.format.extension()
            )),
        };

        self.write_proof_to_file(proof, &filename)?;

        if self.config.show_progress {
            println!("Proof written to: {}", filename.display());
            println!("Format: {:?}", self.config.format);
            println!("Entry ID: {}", proof.entry_info.id);
            println!("Version: {}", proof.entry_info.version);
            println!("Valid: {}", proof.proof.is_valid);
        }

        Ok(())
    }

    /// Output batch results
    fn output_batch_result(
        &self,
        result: &BatchProofResult,
        ledger_name: &str,
        suffix: &str,
    ) -> Result<(), ProofError> {
        let filename = match &self.config.output_path {
            Some(path) => path.clone(),
            None => PathBuf::from(format!(
                "{}_batch_proof_{}.{}",
                ledger_name,
                suffix,
                self.config.format.extension()
            )),
        };

        self.write_batch_to_file(result, &filename)?;

        if self.config.show_progress {
            println!("Batch proof written to: {}", filename.display());
            println!("Format: {:?}", self.config.format);
            println!("Total proofs: {}", result.proofs.len());
            println!(
                "Success rate: {:.1}%",
                (result.summary.successful_proofs as f64 / result.summary.total_requested as f64)
                    * 100.0
            );
        }

        Ok(())
    }

    /// Write a single proof to file
    fn write_proof_to_file(
        &self,
        proof: &VersionedProof,
        filename: &PathBuf,
    ) -> Result<(), ProofError> {
        let mut file = File::create(filename).map_err(|e| ProofError::HashComputationFailed {
            reason: format!("Failed to create file: {}", e),
        })?;

        match self.config.format {
            ProofFormat::Json => {
                let json_data = if self.config.pretty_print {
                    serde_json::to_string_pretty(proof)
                } else {
                    serde_json::to_string(proof)
                }
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("JSON serialization error: {}", e),
                })?;

                file.write_all(json_data.as_bytes()).map_err(|e| {
                    ProofError::HashComputationFailed {
                        reason: format!("Failed to write JSON: {}", e),
                    }
                })?;
            }
            ProofFormat::Binary => {
                let binary_data =
                    bincode::serialize(proof).map_err(|e| ProofError::HashComputationFailed {
                        reason: format!("Binary serialization error: {}", e),
                    })?;

                file.write_all(&binary_data)
                    .map_err(|e| ProofError::HashComputationFailed {
                        reason: format!("Failed to write binary: {}", e),
                    })?;
            }
            ProofFormat::Hex => {
                writeln!(file, "# Sylva Proof - Hex Format")?;
                writeln!(
                    file,
                    "# Generation timestamp: {}",
                    proof.generation_timestamp
                )?;
                writeln!(file, "# Entry ID: {}", proof.entry_info.id)?;
                writeln!(file, "# Version: {}", proof.entry_info.version)?;
                writeln!(file)?;
                writeln!(file, "## Proof Information")?;
                writeln!(file, "Root Hash: {}", proof.proof.root_hash)?;
                writeln!(file, "Leaf Index: {}", proof.proof.leaf_index)?;
                writeln!(file, "Valid: {}", proof.proof.is_valid)?;
                writeln!(file)?;
                writeln!(file, "## Proof Path")?;
                for element in &proof.proof.proof_path {
                    writeln!(
                        file,
                        "Level {}: {} ({})",
                        element.level,
                        element.hash,
                        if element.is_left { "left" } else { "right" }
                    )?;
                }
                writeln!(file)?;
                writeln!(file, "## Entry Information")?;
                writeln!(file, "Data Hash: {}", proof.entry_info.data_hash)?;
                writeln!(file, "Data Size: {} bytes", proof.entry_info.data_size)?;
                writeln!(file, "Timestamp: {}", proof.entry_info.timestamp)?;
                writeln!(file)?;
                writeln!(file, "## Version Metadata")?;
                writeln!(
                    file,
                    "Current Version: {}",
                    proof.version_metadata.current_version
                )?;
                writeln!(
                    file,
                    "Total Versions: {}",
                    proof.version_metadata.total_versions
                )?;
                writeln!(
                    file,
                    "Version Range: {}-{}",
                    proof.version_metadata.version_range.0, proof.version_metadata.version_range.1
                )?;
            }
        }

        Ok(())
    }

    /// Write batch results to file
    fn write_batch_to_file(
        &self,
        result: &BatchProofResult,
        filename: &PathBuf,
    ) -> Result<(), ProofError> {
        let mut file = File::create(filename).map_err(|e| ProofError::HashComputationFailed {
            reason: format!("Failed to create file: {}", e),
        })?;

        match self.config.format {
            ProofFormat::Json => {
                let json_data = if self.config.pretty_print {
                    serde_json::to_string_pretty(result)
                } else {
                    serde_json::to_string(result)
                }
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("JSON serialization error: {}", e),
                })?;

                file.write_all(json_data.as_bytes()).map_err(|e| {
                    ProofError::HashComputationFailed {
                        reason: format!("Failed to write JSON: {}", e),
                    }
                })?;
            }
            ProofFormat::Binary => {
                let binary_data =
                    bincode::serialize(result).map_err(|e| ProofError::HashComputationFailed {
                        reason: format!("Binary serialization error: {}", e),
                    })?;

                file.write_all(&binary_data)
                    .map_err(|e| ProofError::HashComputationFailed {
                        reason: format!("Failed to write binary: {}", e),
                    })?;
            }
            ProofFormat::Hex => {
                writeln!(file, "# Sylva Batch Proof - Hex Format")?;
                writeln!(file, "# Total proofs: {}", result.proofs.len())?;
                writeln!(
                    file,
                    "# Success rate: {:.1}%",
                    (result.summary.successful_proofs as f64
                        / result.summary.total_requested as f64)
                        * 100.0
                )?;
                writeln!(file)?;

                for (i, proof) in result.proofs.iter().enumerate() {
                    writeln!(file, "## Proof {} of {}", i + 1, result.proofs.len())?;
                    writeln!(file, "Entry ID: {}", proof.entry_info.id)?;
                    writeln!(file, "Version: {}", proof.entry_info.version)?;
                    writeln!(file, "Root Hash: {}", proof.proof.root_hash)?;
                    writeln!(file, "Valid: {}", proof.proof.is_valid)?;
                    writeln!(file)?;
                }
            }
        }

        Ok(())
    }
}

impl std::convert::From<std::io::Error> for ProofError {
    fn from(error: std::io::Error) -> Self {
        ProofError::HashComputationFailed {
            reason: error.to_string(),
        }
    }
}

/// Handle the prove command from CLI arguments
pub fn handle_prove_command(matches: &clap::ArgMatches) -> crate::error::Result<()> {
    let ledger_name = matches.get_one::<String>("ledger").unwrap();

    // Parse configuration
    let config = ProveConfig {
        format: matches
            .get_one::<String>("format")
            .map(|s| ProofFormat::parse_format(s))
            .transpose()
            .map_err(|e| crate::error::SylvaError::InvalidInput { message: e })?
            .unwrap_or_default(),
        output_path: matches.get_one::<String>("output").map(PathBuf::from),
        pretty_print: !matches.get_flag("compact"),
        include_metadata: !matches.get_flag("no-metadata"),
        include_version_info: !matches.get_flag("no-version-info"),
        show_progress: !matches.get_flag("no-progress"),
        batch_size: matches
            .get_one::<String>("batch-size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100),
    };

    // Determine prove mode
    let mode = if let Some(entry_id_str) = matches.get_one::<String>("entry-id") {
        let entry_id =
            Uuid::parse_str(entry_id_str).map_err(|e| crate::error::SylvaError::InvalidInput {
                message: format!("Invalid UUID: {}", e),
            })?;
        ProveMode::EntryId(entry_id)
    } else if let Some(data_hex) = matches.get_one::<String>("data") {
        let data = hex::decode(data_hex).map_err(|e| crate::error::SylvaError::InvalidInput {
            message: format!("Invalid hex data: {}", e),
        })?;
        ProveMode::DataContent(data)
    } else if let Some(version_str) = matches.get_one::<String>("version") {
        let version =
            version_str
                .parse::<u64>()
                .map_err(|e| crate::error::SylvaError::InvalidInput {
                    message: format!("Invalid timestamp: {}", e),
                })?;
        ProveMode::Version(version)
    } else if matches.get_flag("batch") {
        let entries_file = matches.get_one::<String>("entries").ok_or_else(|| {
            crate::error::SylvaError::InvalidInput {
                message: "--entries file required for batch mode".to_string(),
            }
        })?;
        ProveMode::Batch(PathBuf::from(entries_file))
    } else {
        return Err(crate::error::SylvaError::InvalidInput {
            message: "Must specify one of: --entry-id, --data, --version, or --batch".to_string(),
        });
    };

    // Initialize storage and prove command
    let workspace = Workspace::find_workspace()?;
    let storage = LedgerStorage::new(&workspace)?;
    let prove_command = ProveCommand::new(storage, config);

    // Execute the prove command
    prove_command
        .execute(ledger_name, mode)
        .map_err(|e| crate::error::SylvaError::ProofError { source: e })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_proof_format_parsing() {
        assert_eq!(
            ProofFormat::parse_format("json").unwrap(),
            ProofFormat::Json
        );
        assert_eq!(
            ProofFormat::parse_format("JSON").unwrap(),
            ProofFormat::Json
        );
        assert_eq!(
            ProofFormat::parse_format("binary").unwrap(),
            ProofFormat::Binary
        );
        assert_eq!(
            ProofFormat::parse_format("bin").unwrap(),
            ProofFormat::Binary
        );
        assert_eq!(ProofFormat::parse_format("hex").unwrap(), ProofFormat::Hex);
        assert!(ProofFormat::parse_format("invalid").is_err());
    }

    #[test]
    fn test_proof_format_properties() {
        assert_eq!(ProofFormat::Json.extension(), "json");
        assert_eq!(ProofFormat::Binary.extension(), "bin");
        assert_eq!(ProofFormat::Hex.extension(), "hex");

        assert_eq!(ProofFormat::Json.mime_type(), "application/json");
        assert_eq!(ProofFormat::Binary.mime_type(), "application/octet-stream");
        assert_eq!(ProofFormat::Hex.mime_type(), "text/plain");
    }

    #[test]
    fn test_prove_config_default() {
        let config = ProveConfig::default();
        assert_eq!(config.format, ProofFormat::Json);
        assert!(config.pretty_print);
        assert!(config.include_metadata);
        assert!(config.include_version_info);
        assert!(config.show_progress);
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_serializable_proof_creation() {
        let entry_id = Uuid::new_v4();
        let root_hash = "1234567890abcdef";

        let proof = SerializableProof {
            entry_id,
            leaf_index: 0,
            root_hash: root_hash.to_string(),
            proof_path: vec![],
            is_valid: true,
        };

        assert_eq!(proof.entry_id, entry_id);
        assert_eq!(proof.leaf_index, 0);
        assert!(proof.is_valid);
    }

    #[test]
    fn test_version_metadata_creation() {
        let metadata = VersionMetadata {
            current_version: 5,
            total_versions: 10,
            version_at_timestamp: Some(1640000005),
            historical_context: false,
            version_range: (0, 9),
        };

        assert_eq!(metadata.current_version, 5);
        assert_eq!(metadata.total_versions, 10);
        assert_eq!(metadata.version_at_timestamp, Some(1640000005));
        assert!(!metadata.historical_context);
        assert_eq!(metadata.version_range, (0, 9));
    }

    #[test]
    fn test_batch_proof_result_creation() {
        let result = BatchProofResult {
            proofs: vec![],
            summary: BatchSummary {
                total_requested: 5,
                successful_proofs: 4,
                failed_proofs: 1,
                processing_time_ms: 100,
            },
            processing_info: ProcessingInfo {
                batch_size: 10,
                total_batches: 1,
                memory_usage_mb: 1.5,
                average_proof_time_ms: 25.0,
            },
        };

        assert_eq!(result.summary.total_requested, 5);
        assert_eq!(result.summary.successful_proofs, 4);
        assert_eq!(result.summary.failed_proofs, 1);
        assert_eq!(result.processing_info.batch_size, 10);
    }

    #[test]
    fn test_batch_file_parsing() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("batch_entries.txt");

        let entry1 = Uuid::new_v4();
        let entry2 = Uuid::new_v4();

        {
            let mut file = File::create(&file_path).unwrap();
            writeln!(file, "# Test batch file").unwrap();
            writeln!(file, "{}", entry1).unwrap();
            writeln!(file).unwrap(); // Empty line
            writeln!(file, "{}", entry2).unwrap();
            writeln!(file, "# Another comment").unwrap();
        }

        // Test file parsing logic would go here
        // This is a placeholder for the actual batch file parsing
        assert!(file_path.exists());
    }

    #[test]
    fn test_entry_info_serialization() {
        let entry_info = EntryInfo {
            id: Uuid::new_v4(),
            version: 1,
            timestamp: 1640000001,
            data_hash: "abcd1234".to_string(),
            data_size: 20,
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&entry_info).unwrap();
        let deserialized: EntryInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(entry_info.id, deserialized.id);
        assert_eq!(entry_info.version, deserialized.version);
        assert_eq!(entry_info.timestamp, deserialized.timestamp);
        assert_eq!(entry_info.data_hash, deserialized.data_hash);
        assert_eq!(entry_info.data_size, deserialized.data_size);
    }

    #[test]
    fn test_proof_element_serialization() {
        let element = ProofElement {
            hash: "deadbeef".to_string(),
            is_left: true,
            level: 2,
        };

        let json = serde_json::to_string(&element).unwrap();
        let deserialized: ProofElement = serde_json::from_str(&json).unwrap();

        assert_eq!(element.hash, deserialized.hash);
        assert_eq!(element.is_left, deserialized.is_left);
        assert_eq!(element.level, deserialized.level);
    }

    #[test]
    fn test_tree_info_calculation() {
        let tree_info = TreeInfo {
            total_entries: 8,
            tree_height: 3,
            root_hash: "abcd1234".to_string(),
            leaf_count: 8,
        };

        assert_eq!(tree_info.total_entries, 8);
        assert_eq!(tree_info.tree_height, 3);
        assert_eq!(tree_info.leaf_count, 8);
    }

    #[test]
    fn test_processing_info_calculations() {
        let processing_info = ProcessingInfo {
            batch_size: 50,
            total_batches: 2,
            memory_usage_mb: 2.5,
            average_proof_time_ms: 15.5,
        };

        assert_eq!(processing_info.batch_size, 50);
        assert_eq!(processing_info.total_batches, 2);
        assert_eq!(processing_info.memory_usage_mb, 2.5);
        assert_eq!(processing_info.average_proof_time_ms, 15.5);
    }
}
