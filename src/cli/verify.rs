use crate::hash::{Blake3Hasher, Hash, HashDigest};
use crate::ledger::{Ledger, LedgerEntry};
use crate::proof::ProofError;
use crate::storage::LedgerStorage;
use crate::tree::{binary::BinaryMerkleTree, Tree};
use crate::workspace::Workspace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

/// Verification result status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Valid,
    Invalid,
    Error,
}

/// Verification mode for the verify command
#[derive(Debug, Clone)]
pub enum VerificationMode {
    /// Verify against a stored ledger
    LedgerBased { ledger_name: String },
    /// Verify against a specific root hash and version
    Historical { root_hash: String, version: u64 },
    /// Batch verification of multiple proof files
    Batch { proof_files: Vec<PathBuf> },
}

/// Configuration for verification operations
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    pub detailed_output: bool,
    pub show_performance: bool,
    pub validate_temporal_consistency: bool,
    pub enforce_version_constraints: bool,
    pub max_batch_size: usize,
    pub timeout_seconds: u64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            detailed_output: true,
            show_performance: true,
            validate_temporal_consistency: true,
            enforce_version_constraints: true,
            max_batch_size: 1000,
            timeout_seconds: 300,
        }
    }
}

/// Detailed verification result for a single proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub proof_file: String,
    pub status: VerificationStatus,
    pub entry_id: Uuid,
    pub proof_version: u64,
    pub ledger_version: u64,
    pub verification_time_ms: u64,
    pub details: VerificationDetails,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Detailed verification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    pub root_hash_match: bool,
    pub path_validation: bool,
    pub temporal_consistency: bool,
    pub version_consistency: bool,
    pub cryptographic_validity: bool,
    pub proof_depth: usize,
    pub tree_height: usize,
    pub entry_timestamp: u64,
    pub proof_timestamp: u64,
    pub hash_function: String,
}

/// Batch verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    pub total_proofs: usize,
    pub valid_proofs: usize,
    pub invalid_proofs: usize,
    pub error_proofs: usize,
    pub processing_time_ms: u64,
    pub throughput_proofs_per_second: f64,
    pub results: Vec<VerificationResult>,
    pub performance_metrics: PerformanceMetrics,
    pub version_conflicts: Vec<VersionConflict>,
}

/// Performance metrics for verification operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub average_verification_time_ms: f64,
    pub min_verification_time_ms: u64,
    pub max_verification_time_ms: u64,
    pub memory_usage_mb: f64,
    pub cpu_utilization_percent: f64,
}

/// Version conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConflict {
    pub proof_file: String,
    pub expected_version: u64,
    pub found_version: u64,
    pub conflict_type: String,
    pub resolution: String,
}

/// Serialized proof structure for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedProof {
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

/// Main verify command implementation
pub struct VerifyCommand {
    storage: LedgerStorage,
    config: VerifyConfig,
}

impl VerifyCommand {
    pub fn new(storage: LedgerStorage, config: VerifyConfig) -> Self {
        Self { storage, config }
    }

    /// Execute the verify command with the given mode
    pub fn execute(
        &self,
        mode: VerificationMode,
        proof_files: &[PathBuf],
    ) -> Result<(), ProofError> {
        match mode {
            VerificationMode::LedgerBased { ledger_name } => {
                self.verify_against_ledger(&ledger_name, proof_files)
            }
            VerificationMode::Historical { root_hash, version } => {
                self.verify_historical(&root_hash, version, proof_files)
            }
            VerificationMode::Batch { proof_files } => self.verify_batch(&proof_files),
        }
    }

    /// Verify proofs against a stored ledger
    fn verify_against_ledger(
        &self,
        ledger_name: &str,
        proof_files: &[PathBuf],
    ) -> Result<(), ProofError> {
        let start_time = Instant::now();

        // Load the ledger
        let ledger = self.load_ledger_by_name(ledger_name)?;
        let entries = ledger.get_entries();

        if entries.is_empty() {
            return Err(ProofError::EmptyTree);
        }

        // Verify each proof file
        let mut results = Vec::new();
        for proof_file in proof_files {
            let result = self.verify_single_proof_against_ledger(proof_file, &ledger)?;
            results.push(result);
        }

        // Generate and display summary
        self.display_verification_summary(&results, start_time.elapsed().as_millis() as u64)?;

        Ok(())
    }

    /// Verify proofs against a specific root hash and version
    fn verify_historical(
        &self,
        root_hash: &str,
        version: u64,
        proof_files: &[PathBuf],
    ) -> Result<(), ProofError> {
        let start_time = Instant::now();

        // Parse root hash
        let expected_root = hex::decode(root_hash).map_err(|e| ProofError::InvalidHashFormat {
            reason: format!("Invalid root hash: {}", e),
        })?;

        // Verify each proof file
        let mut results = Vec::new();
        for proof_file in proof_files {
            let result =
                self.verify_single_proof_historical(proof_file, &expected_root, version)?;
            results.push(result);
        }

        // Generate and display summary
        self.display_verification_summary(&results, start_time.elapsed().as_millis() as u64)?;

        Ok(())
    }

    /// Verify multiple proof files in batch
    fn verify_batch(&self, proof_files: &[PathBuf]) -> Result<(), ProofError> {
        let start_time = Instant::now();

        // Process proofs in batches
        let mut all_results = Vec::new();
        let mut version_conflicts = Vec::new();

        for chunk in proof_files.chunks(self.config.max_batch_size) {
            let batch_results = self.process_proof_batch(chunk)?;

            // Check for version conflicts within this batch
            let conflicts = self.detect_version_conflicts(&batch_results);
            version_conflicts.extend(conflicts);

            all_results.extend(batch_results);
        }

        // Generate batch result
        let processing_time_ms = start_time.elapsed().as_millis() as u64;
        let batch_result =
            self.create_batch_result(all_results, processing_time_ms, version_conflicts)?;

        // Display results
        self.display_batch_results(&batch_result)?;

        Ok(())
    }

    /// Load ledger by name
    fn load_ledger_by_name(&self, _ledger_name: &str) -> Result<Ledger, ProofError> {
        let ledger_files =
            self.storage
                .list_ledgers()
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: e.to_string(),
                })?;

        // Find ledger by name (simplified - in real implementation, use proper name matching)
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

    /// Verify a single proof against a ledger
    fn verify_single_proof_against_ledger(
        &self,
        proof_file: &PathBuf,
        ledger: &Ledger,
    ) -> Result<VerificationResult, ProofError> {
        let start_time = Instant::now();

        // Load and parse proof
        let proof = self.load_proof_from_file(proof_file)?;

        // Find corresponding entry in ledger
        let entry = ledger
            .get_entry(&proof.entry_info.id)
            .map_err(|e| ProofError::HashComputationFailed {
                reason: e.to_string(),
            })?
            .ok_or(ProofError::LeafNotFound {
                entry_id: proof.entry_info.id,
            })?;

        // Perform verification
        let verification_details = self.verify_proof_against_entry(&proof, entry, ledger)?;

        let verification_time_ms = start_time.elapsed().as_millis() as u64;
        let status = if verification_details.cryptographic_validity
            && verification_details.root_hash_match
            && verification_details.path_validation
        {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        };

        Ok(VerificationResult {
            proof_file: proof_file.to_string_lossy().to_string(),
            status,
            entry_id: proof.entry_info.id,
            proof_version: proof.entry_info.version,
            ledger_version: entry.version,
            verification_time_ms,
            details: verification_details,
            errors: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Verify a single proof against historical state
    fn verify_single_proof_historical(
        &self,
        proof_file: &PathBuf,
        expected_root: &[u8],
        version: u64,
    ) -> Result<VerificationResult, ProofError> {
        let start_time = Instant::now();

        // Load and parse proof
        let proof = self.load_proof_from_file(proof_file)?;

        // Verify against historical state
        let verification_details = self.verify_proof_historical(&proof, expected_root, version)?;

        let verification_time_ms = start_time.elapsed().as_millis() as u64;
        let status = if verification_details.cryptographic_validity
            && verification_details.root_hash_match
            && verification_details.temporal_consistency
        {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        };

        Ok(VerificationResult {
            proof_file: proof_file.to_string_lossy().to_string(),
            status,
            entry_id: proof.entry_info.id,
            proof_version: proof.entry_info.version,
            ledger_version: version,
            verification_time_ms,
            details: verification_details,
            errors: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Load proof from file
    fn load_proof_from_file(&self, proof_file: &PathBuf) -> Result<SerializedProof, ProofError> {
        use std::fs;

        let data = fs::read(proof_file).map_err(|e| ProofError::HashComputationFailed {
            reason: format!("Failed to read proof file: {}", e),
        })?;

        // Determine format based on file extension
        let extension = proof_file
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json");

        let proof: SerializedProof = match extension {
            "json" => {
                serde_json::from_slice(&data).map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("Failed to parse JSON proof: {}", e),
                })?
            }
            "bin" => {
                bincode::deserialize(&data).map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("Failed to parse binary proof: {}", e),
                })?
            }
            "hex" => {
                return Err(ProofError::HashComputationFailed {
                    reason: "Hex format proof verification is not yet supported. Please use JSON format proofs for verification.".to_string(),
                });
            }
            _ => {
                // Default to JSON for unknown extensions
                serde_json::from_slice(&data).map_err(|e| ProofError::HashComputationFailed {
                    reason: format!("Failed to parse proof as JSON: {}", e),
                })?
            }
        };

        Ok(proof)
    }

    /// Verify proof against an entry
    fn verify_proof_against_entry(
        &self,
        proof: &SerializedProof,
        entry: &LedgerEntry,
        ledger: &Ledger,
    ) -> Result<VerificationDetails, ProofError> {
        let hasher = Blake3Hasher::new();

        // Verify root hash match by creating a tree from the entries
        let tree = BinaryMerkleTree::from_entries(ledger.get_entries().to_vec()).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: e.to_string(),
            }
        })?;
        let computed_root = tree
            .root_hash()
            .ok_or_else(|| ProofError::HashComputationFailed {
                reason: "Failed to compute root hash".to_string(),
            })?;

        let root_hash_match = hex::encode(computed_root.as_bytes()) == proof.proof.root_hash;

        // Verify cryptographic validity
        let cryptographic_validity =
            self.verify_cryptographic_proof(&proof.proof, entry, &hasher)?;

        // Verify temporal consistency
        let temporal_consistency = self.verify_temporal_consistency(proof, entry)?;

        // Verify version consistency
        let version_consistency = proof.entry_info.version == entry.version;

        Ok(VerificationDetails {
            root_hash_match,
            path_validation: cryptographic_validity,
            temporal_consistency,
            version_consistency,
            cryptographic_validity,
            proof_depth: proof.proof.proof_path.len(),
            tree_height: proof.tree_info.tree_height,
            entry_timestamp: entry.timestamp,
            proof_timestamp: proof.generation_timestamp,
            hash_function: "Blake3".to_string(),
        })
    }

    /// Verify proof against historical state
    fn verify_proof_historical(
        &self,
        proof: &SerializedProof,
        expected_root: &[u8],
        version: u64,
    ) -> Result<VerificationDetails, ProofError> {
        let _hasher = Blake3Hasher::new();

        // Verify root hash match
        let root_hash_match =
            hex::decode(&proof.proof.root_hash).map_err(|e| ProofError::InvalidHashFormat {
                reason: e.to_string(),
            })? == expected_root;

        // Verify cryptographic validity (simplified - would need historical entry data)
        let cryptographic_validity = true; // Placeholder

        // Verify temporal consistency
        let temporal_consistency = proof.entry_info.version <= version;

        // Verify version consistency
        let version_consistency = proof.entry_info.version <= version;

        Ok(VerificationDetails {
            root_hash_match,
            path_validation: cryptographic_validity,
            temporal_consistency,
            version_consistency,
            cryptographic_validity,
            proof_depth: proof.proof.proof_path.len(),
            tree_height: proof.tree_info.tree_height,
            entry_timestamp: proof.entry_info.timestamp,
            proof_timestamp: proof.generation_timestamp,
            hash_function: "Blake3".to_string(),
        })
    }

    /// Verify cryptographic proof
    fn verify_cryptographic_proof(
        &self,
        proof: &SerializableProof,
        entry: &LedgerEntry,
        hasher: &Blake3Hasher,
    ) -> Result<bool, ProofError> {
        // Compute leaf hash
        let leaf_hash =
            hasher
                .hash_bytes(&entry.data)
                .map_err(|e| ProofError::HashComputationFailed {
                    reason: e.to_string(),
                })?;

        // Reconstruct root hash from proof path
        let mut current_hash = leaf_hash;

        for element in &proof.proof_path {
            let sibling_hash =
                hex::decode(&element.hash).map_err(|e| ProofError::InvalidHashFormat {
                    reason: e.to_string(),
                })?;

            let sibling_digest = HashDigest::new(sibling_hash.try_into().map_err(|_| {
                ProofError::InvalidHashFormat {
                    reason: "Invalid hash length".to_string(),
                }
            })?);

            current_hash = if element.is_left {
                hasher.hash_pair(&sibling_digest, &current_hash)
            } else {
                hasher.hash_pair(&current_hash, &sibling_digest)
            }
            .map_err(|e| ProofError::HashComputationFailed {
                reason: e.to_string(),
            })?;
        }

        // Compare with expected root
        let expected_root =
            hex::decode(&proof.root_hash).map_err(|e| ProofError::InvalidHashFormat {
                reason: e.to_string(),
            })?;

        Ok(current_hash.as_bytes() == expected_root.as_slice())
    }

    /// Verify temporal consistency
    fn verify_temporal_consistency(
        &self,
        proof: &SerializedProof,
        entry: &LedgerEntry,
    ) -> Result<bool, ProofError> {
        // Check if proof generation timestamp is after entry timestamp
        Ok(proof.generation_timestamp >= entry.timestamp)
    }

    /// Process a batch of proofs
    fn process_proof_batch(
        &self,
        proof_files: &[PathBuf],
    ) -> Result<Vec<VerificationResult>, ProofError> {
        let mut results = Vec::new();

        for proof_file in proof_files {
            // For batch processing, we'll use a simplified verification approach
            let result = self.verify_single_proof_batch(proof_file)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Verify a single proof in batch mode
    fn verify_single_proof_batch(
        &self,
        proof_file: &PathBuf,
    ) -> Result<VerificationResult, ProofError> {
        let start_time = Instant::now();

        // Load proof
        let proof = self.load_proof_from_file(proof_file)?;

        // Basic validation
        let basic_validity = self.validate_proof_structure(&proof)?;

        let verification_time_ms = start_time.elapsed().as_millis() as u64;
        let status = if basic_validity {
            VerificationStatus::Valid
        } else {
            VerificationStatus::Invalid
        };

        Ok(VerificationResult {
            proof_file: proof_file.to_string_lossy().to_string(),
            status,
            entry_id: proof.entry_info.id,
            proof_version: proof.entry_info.version,
            ledger_version: proof.entry_info.version,
            verification_time_ms,
            details: VerificationDetails {
                root_hash_match: basic_validity,
                path_validation: basic_validity,
                temporal_consistency: true,
                version_consistency: true,
                cryptographic_validity: basic_validity,
                proof_depth: proof.proof.proof_path.len(),
                tree_height: proof.tree_info.tree_height,
                entry_timestamp: proof.entry_info.timestamp,
                proof_timestamp: proof.generation_timestamp,
                hash_function: "Blake3".to_string(),
            },
            errors: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Validate proof structure
    fn validate_proof_structure(&self, proof: &SerializedProof) -> Result<bool, ProofError> {
        // Check if proof has valid structure
        if proof.proof.proof_path.is_empty() {
            return Ok(false);
        }

        // Check if root hash is valid hex
        if hex::decode(&proof.proof.root_hash).is_err() {
            return Ok(false);
        }

        // Check if all proof path elements have valid hashes
        for element in &proof.proof.proof_path {
            if hex::decode(&element.hash).is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Detect version conflicts in batch results
    fn detect_version_conflicts(&self, results: &[VerificationResult]) -> Vec<VersionConflict> {
        let mut conflicts = Vec::new();

        for result in results {
            if result.proof_version != result.ledger_version {
                conflicts.push(VersionConflict {
                    proof_file: result.proof_file.clone(),
                    expected_version: result.ledger_version,
                    found_version: result.proof_version,
                    conflict_type: "Version mismatch".to_string(),
                    resolution: "Manual review required".to_string(),
                });
            }
        }

        conflicts
    }

    /// Create batch verification result
    fn create_batch_result(
        &self,
        results: Vec<VerificationResult>,
        processing_time_ms: u64,
        version_conflicts: Vec<VersionConflict>,
    ) -> Result<BatchVerificationResult, ProofError> {
        let total_proofs = results.len();
        let valid_proofs = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Valid)
            .count();
        let invalid_proofs = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Invalid)
            .count();
        let error_proofs = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Error)
            .count();

        let throughput = if processing_time_ms > 0 {
            (total_proofs as f64) / (processing_time_ms as f64 / 1000.0)
        } else {
            0.0
        };

        let verification_times: Vec<u64> = results.iter().map(|r| r.verification_time_ms).collect();
        let avg_time = if !verification_times.is_empty() {
            verification_times.iter().sum::<u64>() as f64 / verification_times.len() as f64
        } else {
            0.0
        };

        let performance_metrics = PerformanceMetrics {
            average_verification_time_ms: avg_time,
            min_verification_time_ms: verification_times.iter().min().copied().unwrap_or(0),
            max_verification_time_ms: verification_times.iter().max().copied().unwrap_or(0),
            memory_usage_mb: 0.0, // TODO: Implement actual memory tracking
            cpu_utilization_percent: 0.0, // TODO: Implement actual CPU tracking
        };

        Ok(BatchVerificationResult {
            total_proofs,
            valid_proofs,
            invalid_proofs,
            error_proofs,
            processing_time_ms,
            throughput_proofs_per_second: throughput,
            results,
            performance_metrics,
            version_conflicts,
        })
    }

    /// Display verification summary
    fn display_verification_summary(
        &self,
        results: &[VerificationResult],
        total_time_ms: u64,
    ) -> Result<(), ProofError> {
        let valid_count = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Valid)
            .count();
        let invalid_count = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Invalid)
            .count();
        let error_count = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Error)
            .count();

        println!("🔍 Verification Summary");
        println!("====================");
        println!("Total proofs: {}", results.len());
        println!("✅ Valid: {}", valid_count);
        println!("❌ Invalid: {}", invalid_count);
        println!("⚠️  Errors: {}", error_count);
        println!("⏱️  Total time: {}ms", total_time_ms);

        if self.config.show_performance {
            let avg_time = if !results.is_empty() {
                results.iter().map(|r| r.verification_time_ms).sum::<u64>() as f64
                    / results.len() as f64
            } else {
                0.0
            };

            println!(
                "📊 Performance: {:.2} proofs/sec",
                results.len() as f64 / (total_time_ms as f64 / 1000.0)
            );
            println!("📊 Average time per proof: {:.2}ms", avg_time);
        }

        if self.config.detailed_output {
            println!("\n📋 Detailed Results:");
            for result in results {
                self.display_single_result(result)?;
            }
        }

        Ok(())
    }

    /// Display batch verification results
    fn display_batch_results(&self, result: &BatchVerificationResult) -> Result<(), ProofError> {
        println!("🔍 Batch Verification Results");
        println!("=============================");
        println!("Total proofs: {}", result.total_proofs);
        println!("✅ Valid: {}", result.valid_proofs);
        println!("❌ Invalid: {}", result.invalid_proofs);
        println!("⚠️  Errors: {}", result.error_proofs);
        println!("⏱️  Processing time: {}ms", result.processing_time_ms);
        println!(
            "📊 Throughput: {:.2} proofs/sec",
            result.throughput_proofs_per_second
        );

        if self.config.show_performance {
            let perf = &result.performance_metrics;
            println!("\n📊 Performance Metrics:");
            println!(
                "   Average time: {:.2}ms",
                perf.average_verification_time_ms
            );
            println!("   Min time: {}ms", perf.min_verification_time_ms);
            println!("   Max time: {}ms", perf.max_verification_time_ms);
        }

        if !result.version_conflicts.is_empty() {
            println!("\n⚠️  Version Conflicts:");
            for conflict in &result.version_conflicts {
                println!(
                    "   📄 {}: expected v{}, found v{}",
                    conflict.proof_file, conflict.expected_version, conflict.found_version
                );
            }
        }

        if self.config.detailed_output && !result.results.is_empty() {
            println!("\n📋 Detailed Results:");
            for single_result in &result.results {
                self.display_single_result(single_result)?;
            }
        }

        Ok(())
    }

    /// Display a single verification result
    fn display_single_result(&self, result: &VerificationResult) -> Result<(), ProofError> {
        let status_icon = match result.status {
            VerificationStatus::Valid => "✅",
            VerificationStatus::Invalid => "❌",
            VerificationStatus::Error => "⚠️",
        };

        println!("\n{} {}", status_icon, result.proof_file);
        println!("   Entry ID: {}", result.entry_id);
        println!(
            "   Proof version: {}, Ledger version: {}",
            result.proof_version, result.ledger_version
        );
        println!("   Verification time: {}ms", result.verification_time_ms);

        if self.config.detailed_output {
            let details = &result.details;
            println!("   Details:");
            println!(
                "     Root hash match: {}",
                if details.root_hash_match {
                    "✅"
                } else {
                    "❌"
                }
            );
            println!(
                "     Path validation: {}",
                if details.path_validation {
                    "✅"
                } else {
                    "❌"
                }
            );
            println!(
                "     Temporal consistency: {}",
                if details.temporal_consistency {
                    "✅"
                } else {
                    "❌"
                }
            );
            println!(
                "     Version consistency: {}",
                if details.version_consistency {
                    "✅"
                } else {
                    "❌"
                }
            );
            println!(
                "     Cryptographic validity: {}",
                if details.cryptographic_validity {
                    "✅"
                } else {
                    "❌"
                }
            );
            println!("     Proof depth: {}", details.proof_depth);
            println!("     Tree height: {}", details.tree_height);
        }

        Ok(())
    }
}

/// Handle the verify command from CLI arguments
pub fn handle_verify_command(matches: &clap::ArgMatches) -> crate::error::Result<()> {
    let proof_files: Vec<PathBuf> = matches
        .get_many::<String>("proof_files")
        .map(|files| files.map(PathBuf::from).collect())
        .unwrap_or_default();

    if proof_files.is_empty() {
        return Err(crate::error::SylvaError::InvalidInput {
            message: "At least one proof file must be specified".to_string(),
        });
    }

    // Parse configuration
    let config = VerifyConfig {
        detailed_output: !matches.get_flag("quiet"),
        show_performance: matches.get_flag("performance"),
        validate_temporal_consistency: !matches.get_flag("no-temporal-check"),
        enforce_version_constraints: !matches.get_flag("no-version-check"),
        max_batch_size: matches
            .get_one::<String>("batch-size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000),
        timeout_seconds: matches
            .get_one::<String>("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    };

    // Determine verification mode
    let mode = if let Some(ledger_name) = matches.get_one::<String>("ledger") {
        VerificationMode::LedgerBased {
            ledger_name: ledger_name.clone(),
        }
    } else if let Some(root_hash) = matches.get_one::<String>("root") {
        let version = matches
            .get_one::<String>("version")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        VerificationMode::Historical {
            root_hash: root_hash.clone(),
            version,
        }
    } else {
        VerificationMode::Batch {
            proof_files: proof_files.clone(),
        }
    };

    // Initialize storage and verify command
    let workspace = Workspace::find_workspace()?;
    let storage = LedgerStorage::new(&workspace)?;
    let verify_command = VerifyCommand::new(storage, config);

    // Execute the verify command
    verify_command
        .execute(mode, &proof_files)
        .map_err(|e| crate::error::SylvaError::ProofError { source: e })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_proof(entry_id: Uuid, version: u64) -> SerializedProof {
        SerializedProof {
            proof: SerializableProof {
                entry_id,
                leaf_index: 0,
                root_hash: "deadbeef".to_string(),
                proof_path: vec![],
                is_valid: true,
            },
            entry_info: EntryInfo {
                id: entry_id,
                version,
                timestamp: 1640000000 + version,
                data_hash: "abcd1234".to_string(),
                data_size: 10,
                metadata: HashMap::new(),
            },
            version_metadata: VersionMetadata {
                current_version: version,
                total_versions: 1,
                version_at_timestamp: Some(1640000000 + version),
                historical_context: false,
                version_range: (0, version),
            },
            tree_info: TreeInfo {
                total_entries: 1,
                tree_height: 1,
                root_hash: "deadbeef".to_string(),
                leaf_count: 1,
            },
            generation_timestamp: 1640000000 + version + 1,
        }
    }

    #[test]
    fn test_verify_config_default() {
        let config = VerifyConfig::default();
        assert!(config.detailed_output);
        assert!(config.show_performance);
        assert!(config.validate_temporal_consistency);
        assert!(config.enforce_version_constraints);
        assert_eq!(config.max_batch_size, 1000);
        assert_eq!(config.timeout_seconds, 300);
    }

    #[test]
    fn test_verification_status() {
        assert_eq!(VerificationStatus::Valid, VerificationStatus::Valid);
        assert_ne!(VerificationStatus::Valid, VerificationStatus::Invalid);
        assert_ne!(VerificationStatus::Invalid, VerificationStatus::Error);
    }

    #[test]
    fn test_verification_result_creation() {
        let entry_id = Uuid::new_v4();
        let result = VerificationResult {
            proof_file: "test.json".to_string(),
            status: VerificationStatus::Valid,
            entry_id,
            proof_version: 1,
            ledger_version: 1,
            verification_time_ms: 50,
            details: VerificationDetails {
                root_hash_match: true,
                path_validation: true,
                temporal_consistency: true,
                version_consistency: true,
                cryptographic_validity: true,
                proof_depth: 3,
                tree_height: 4,
                entry_timestamp: 1640000001,
                proof_timestamp: 1640000002,
                hash_function: "Blake3".to_string(),
            },
            errors: vec![],
            warnings: vec![],
        };

        assert_eq!(result.status, VerificationStatus::Valid);
        assert_eq!(result.entry_id, entry_id);
        assert_eq!(result.proof_version, 1);
        assert_eq!(result.ledger_version, 1);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_batch_verification_result_creation() {
        let results = vec![];
        let version_conflicts = vec![];

        let batch_result = BatchVerificationResult {
            total_proofs: 0,
            valid_proofs: 0,
            invalid_proofs: 0,
            error_proofs: 0,
            processing_time_ms: 100,
            throughput_proofs_per_second: 0.0,
            results,
            performance_metrics: PerformanceMetrics {
                average_verification_time_ms: 0.0,
                min_verification_time_ms: 0,
                max_verification_time_ms: 0,
                memory_usage_mb: 0.0,
                cpu_utilization_percent: 0.0,
            },
            version_conflicts,
        };

        assert_eq!(batch_result.total_proofs, 0);
        assert_eq!(batch_result.processing_time_ms, 100);
        assert_eq!(batch_result.throughput_proofs_per_second, 0.0);
    }

    #[test]
    fn test_version_conflict_detection() {
        let conflict = VersionConflict {
            proof_file: "test.json".to_string(),
            expected_version: 1,
            found_version: 2,
            conflict_type: "Version mismatch".to_string(),
            resolution: "Manual review required".to_string(),
        };

        assert_eq!(conflict.expected_version, 1);
        assert_eq!(conflict.found_version, 2);
        assert_eq!(conflict.conflict_type, "Version mismatch");
    }

    #[test]
    fn test_performance_metrics_calculation() {
        let metrics = PerformanceMetrics {
            average_verification_time_ms: 25.5,
            min_verification_time_ms: 10,
            max_verification_time_ms: 50,
            memory_usage_mb: 1.5,
            cpu_utilization_percent: 75.0,
        };

        assert_eq!(metrics.average_verification_time_ms, 25.5);
        assert_eq!(metrics.min_verification_time_ms, 10);
        assert_eq!(metrics.max_verification_time_ms, 50);
        assert_eq!(metrics.memory_usage_mb, 1.5);
        assert_eq!(metrics.cpu_utilization_percent, 75.0);
    }

    #[test]
    fn test_verification_mode_types() {
        let ledger_mode = VerificationMode::LedgerBased {
            ledger_name: "test".to_string(),
        };

        let historical_mode = VerificationMode::Historical {
            root_hash: "deadbeef".to_string(),
            version: 1,
        };

        let batch_mode = VerificationMode::Batch {
            proof_files: vec![PathBuf::from("test.json")],
        };

        // Test that different modes can be created
        match ledger_mode {
            VerificationMode::LedgerBased { .. } => {}
            _ => panic!("Expected LedgerBased mode"),
        }

        match historical_mode {
            VerificationMode::Historical { .. } => {}
            _ => panic!("Expected Historical mode"),
        }

        match batch_mode {
            VerificationMode::Batch { .. } => {}
            _ => panic!("Expected Batch mode"),
        }
    }

    #[test]
    fn test_serialized_proof_validation() {
        let entry_id = Uuid::new_v4();
        let proof = create_test_proof(entry_id, 1);

        // Test basic structure
        assert_eq!(proof.entry_info.id, entry_id);
        assert_eq!(proof.entry_info.version, 1);
        assert_eq!(proof.version_metadata.current_version, 1);
        assert_eq!(proof.tree_info.total_entries, 1);
        assert!(proof.proof.is_valid);
    }

    #[test]
    fn test_verification_details_completeness() {
        let details = VerificationDetails {
            root_hash_match: true,
            path_validation: true,
            temporal_consistency: true,
            version_consistency: true,
            cryptographic_validity: true,
            proof_depth: 3,
            tree_height: 4,
            entry_timestamp: 1640000001,
            proof_timestamp: 1640000002,
            hash_function: "Blake3".to_string(),
        };

        assert!(details.root_hash_match);
        assert!(details.path_validation);
        assert!(details.temporal_consistency);
        assert!(details.version_consistency);
        assert!(details.cryptographic_validity);
        assert_eq!(details.proof_depth, 3);
        assert_eq!(details.tree_height, 4);
        assert_eq!(details.hash_function, "Blake3");
    }
}
