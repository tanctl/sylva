use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tempfile::tempdir;
use uuid::Uuid;

use sylva::cli::verify::*;
use sylva::ledger::Ledger;

fn create_test_ledger() -> Ledger {
    let mut ledger = Ledger::new();
    let _ = ledger.add_entry(b"test data 1".to_vec());
    let _ = ledger.add_entry(b"test data 2".to_vec());
    let _ = ledger.add_entry(b"test data 3".to_vec());
    ledger
}

fn create_test_proof_file(dir: &std::path::Path, entry_id: Uuid, version: u64) -> PathBuf {
    let proof_file = dir.join(format!("proof_{}.json", entry_id));
    let proof = SerializedProof {
        proof: SerializableProof {
            entry_id,
            leaf_index: 0,
            root_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            proof_path: vec![
                ProofElement {
                    hash: "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                        .to_string(),
                    is_left: true,
                    level: 0,
                },
                ProofElement {
                    hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
                        .to_string(),
                    is_left: false,
                    level: 1,
                },
            ],
            is_valid: true,
        },
        entry_info: EntryInfo {
            id: entry_id,
            version,
            timestamp: 1640000000 + version,
            data_hash: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                .to_string(),
            data_size: 20,
            metadata: HashMap::new(),
        },
        version_metadata: VersionMetadata {
            current_version: version,
            total_versions: 3,
            version_at_timestamp: Some(1640000000 + version),
            historical_context: false,
            version_range: (0, 3),
        },
        tree_info: TreeInfo {
            total_entries: 3,
            tree_height: 2,
            root_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            leaf_count: 3,
        },
        generation_timestamp: 1640000000 + version + 1,
    };

    let mut file = File::create(&proof_file).unwrap();
    let json = serde_json::to_string_pretty(&proof).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    proof_file
}

fn create_invalid_proof_file(dir: &std::path::Path) -> PathBuf {
    let proof_file = dir.join("invalid_proof.json");
    let invalid_proof = SerializedProof {
        proof: SerializableProof {
            entry_id: Uuid::new_v4(),
            leaf_index: 0,
            root_hash: "invalid_hex".to_string(), // Invalid hex
            proof_path: vec![],
            is_valid: false,
        },
        entry_info: EntryInfo {
            id: Uuid::new_v4(),
            version: 1,
            timestamp: 1640000001,
            data_hash: "invalid_hash".to_string(),
            data_size: 10,
            metadata: HashMap::new(),
        },
        version_metadata: VersionMetadata {
            current_version: 1,
            total_versions: 1,
            version_at_timestamp: Some(1640000001),
            historical_context: false,
            version_range: (0, 1),
        },
        tree_info: TreeInfo {
            total_entries: 1,
            tree_height: 1,
            root_hash: "invalid_hex".to_string(),
            leaf_count: 1,
        },
        generation_timestamp: 1640000002,
    };

    let mut file = File::create(&proof_file).unwrap();
    let json = serde_json::to_string_pretty(&invalid_proof).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    proof_file
}

#[test]
fn test_verify_config_creation() {
    let config = VerifyConfig::default();
    assert!(config.detailed_output);
    assert!(config.show_performance);
    assert!(config.validate_temporal_consistency);
    assert!(config.enforce_version_constraints);
    assert_eq!(config.max_batch_size, 1000);
    assert_eq!(config.timeout_seconds, 300);
}

#[test]
fn test_verify_config_custom() {
    let config = VerifyConfig {
        detailed_output: false,
        show_performance: false,
        validate_temporal_consistency: false,
        enforce_version_constraints: false,
        max_batch_size: 500,
        timeout_seconds: 600,
    };

    assert!(!config.detailed_output);
    assert!(!config.show_performance);
    assert!(!config.validate_temporal_consistency);
    assert!(!config.enforce_version_constraints);
    assert_eq!(config.max_batch_size, 500);
    assert_eq!(config.timeout_seconds, 600);
}

#[test]
fn test_verification_status_enum() {
    let status_valid = VerificationStatus::Valid;
    let status_invalid = VerificationStatus::Invalid;
    let status_error = VerificationStatus::Error;

    assert_eq!(status_valid, VerificationStatus::Valid);
    assert_ne!(status_valid, status_invalid);
    assert_ne!(status_invalid, status_error);
}

#[test]
fn test_verification_mode_creation() {
    let ledger_mode = VerificationMode::LedgerBased {
        ledger_name: "test_ledger".to_string(),
    };

    let historical_mode = VerificationMode::Historical {
        root_hash: "deadbeef".to_string(),
        version: 12345,
    };

    let batch_mode = VerificationMode::Batch {
        proof_files: vec![PathBuf::from("proof1.json"), PathBuf::from("proof2.json")],
    };

    match ledger_mode {
        VerificationMode::LedgerBased { ledger_name } => {
            assert_eq!(ledger_name, "test_ledger");
        }
        _ => panic!("Expected LedgerBased mode"),
    }

    match historical_mode {
        VerificationMode::Historical { root_hash, version } => {
            assert_eq!(root_hash, "deadbeef");
            assert_eq!(version, 12345);
        }
        _ => panic!("Expected Historical mode"),
    }

    match batch_mode {
        VerificationMode::Batch { proof_files } => {
            assert_eq!(proof_files.len(), 2);
        }
        _ => panic!("Expected Batch mode"),
    }
}

#[test]
fn test_verification_result_creation() {
    let entry_id = Uuid::new_v4();
    let result = VerificationResult {
        proof_file: "test_proof.json".to_string(),
        status: VerificationStatus::Valid,
        entry_id,
        proof_version: 1,
        ledger_version: 1,
        verification_time_ms: 42,
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

    assert_eq!(result.proof_file, "test_proof.json");
    assert_eq!(result.status, VerificationStatus::Valid);
    assert_eq!(result.entry_id, entry_id);
    assert_eq!(result.proof_version, 1);
    assert_eq!(result.ledger_version, 1);
    assert_eq!(result.verification_time_ms, 42);
    assert!(result.details.root_hash_match);
    assert!(result.details.path_validation);
    assert!(result.details.temporal_consistency);
    assert!(result.details.version_consistency);
    assert!(result.details.cryptographic_validity);
    assert_eq!(result.details.proof_depth, 3);
    assert_eq!(result.details.tree_height, 4);
    assert_eq!(result.details.hash_function, "Blake3");
    assert!(result.errors.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn test_batch_verification_result_creation() {
    let entry_id = Uuid::new_v4();
    let result = VerificationResult {
        proof_file: "test_proof.json".to_string(),
        status: VerificationStatus::Valid,
        entry_id,
        proof_version: 1,
        ledger_version: 1,
        verification_time_ms: 42,
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

    let batch_result = BatchVerificationResult {
        total_proofs: 1,
        valid_proofs: 1,
        invalid_proofs: 0,
        error_proofs: 0,
        processing_time_ms: 100,
        throughput_proofs_per_second: 10.0,
        results: vec![result],
        performance_metrics: PerformanceMetrics {
            average_verification_time_ms: 42.0,
            min_verification_time_ms: 42,
            max_verification_time_ms: 42,
            memory_usage_mb: 1.5,
            cpu_utilization_percent: 25.0,
        },
        version_conflicts: vec![],
    };

    assert_eq!(batch_result.total_proofs, 1);
    assert_eq!(batch_result.valid_proofs, 1);
    assert_eq!(batch_result.invalid_proofs, 0);
    assert_eq!(batch_result.error_proofs, 0);
    assert_eq!(batch_result.processing_time_ms, 100);
    assert_eq!(batch_result.throughput_proofs_per_second, 10.0);
    assert_eq!(batch_result.results.len(), 1);
    assert_eq!(
        batch_result
            .performance_metrics
            .average_verification_time_ms,
        42.0
    );
    assert_eq!(
        batch_result.performance_metrics.min_verification_time_ms,
        42
    );
    assert_eq!(
        batch_result.performance_metrics.max_verification_time_ms,
        42
    );
    assert_eq!(batch_result.performance_metrics.memory_usage_mb, 1.5);
    assert_eq!(
        batch_result.performance_metrics.cpu_utilization_percent,
        25.0
    );
    assert!(batch_result.version_conflicts.is_empty());
}

#[test]
fn test_version_conflict_detection() {
    let conflict = VersionConflict {
        proof_file: "conflicted_proof.json".to_string(),
        expected_version: 1,
        found_version: 2,
        conflict_type: "Version mismatch".to_string(),
        resolution: "Manual review required".to_string(),
    };

    assert_eq!(conflict.proof_file, "conflicted_proof.json");
    assert_eq!(conflict.expected_version, 1);
    assert_eq!(conflict.found_version, 2);
    assert_eq!(conflict.conflict_type, "Version mismatch");
    assert_eq!(conflict.resolution, "Manual review required");
}

#[test]
fn test_performance_metrics_calculation() {
    let metrics = PerformanceMetrics {
        average_verification_time_ms: 35.7,
        min_verification_time_ms: 10,
        max_verification_time_ms: 95,
        memory_usage_mb: 2.3,
        cpu_utilization_percent: 67.5,
    };

    assert_eq!(metrics.average_verification_time_ms, 35.7);
    assert_eq!(metrics.min_verification_time_ms, 10);
    assert_eq!(metrics.max_verification_time_ms, 95);
    assert_eq!(metrics.memory_usage_mb, 2.3);
    assert_eq!(metrics.cpu_utilization_percent, 67.5);
}

#[test]
fn test_serialized_proof_structure() {
    let entry_id = Uuid::new_v4();
    let proof = SerializedProof {
        proof: SerializableProof {
            entry_id,
            leaf_index: 0,
            root_hash: "deadbeef".to_string(),
            proof_path: vec![
                ProofElement {
                    hash: "abcd1234".to_string(),
                    is_left: true,
                    level: 0,
                },
                ProofElement {
                    hash: "5678efgh".to_string(),
                    is_left: false,
                    level: 1,
                },
            ],
            is_valid: true,
        },
        entry_info: EntryInfo {
            id: entry_id,
            version: 1,
            timestamp: 1640000001,
            data_hash: "fedcba09".to_string(),
            data_size: 20,
            metadata: HashMap::new(),
        },
        version_metadata: VersionMetadata {
            current_version: 1,
            total_versions: 1,
            version_at_timestamp: Some(1640000001),
            historical_context: false,
            version_range: (0, 1),
        },
        tree_info: TreeInfo {
            total_entries: 1,
            tree_height: 2,
            root_hash: "deadbeef".to_string(),
            leaf_count: 1,
        },
        generation_timestamp: 1640000002,
    };

    assert_eq!(proof.proof.entry_id, entry_id);
    assert_eq!(proof.proof.leaf_index, 0);
    assert_eq!(proof.proof.root_hash, "deadbeef");
    assert_eq!(proof.proof.proof_path.len(), 2);
    assert!(proof.proof.is_valid);

    assert_eq!(proof.entry_info.id, entry_id);
    assert_eq!(proof.entry_info.version, 1);
    assert_eq!(proof.entry_info.timestamp, 1640000001);
    assert_eq!(proof.entry_info.data_hash, "fedcba09");
    assert_eq!(proof.entry_info.data_size, 20);

    assert_eq!(proof.version_metadata.current_version, 1);
    assert_eq!(proof.version_metadata.total_versions, 1);
    assert_eq!(
        proof.version_metadata.version_at_timestamp,
        Some(1640000001)
    );
    assert!(!proof.version_metadata.historical_context);
    assert_eq!(proof.version_metadata.version_range, (0, 1));

    assert_eq!(proof.tree_info.total_entries, 1);
    assert_eq!(proof.tree_info.tree_height, 2);
    assert_eq!(proof.tree_info.root_hash, "deadbeef");
    assert_eq!(proof.tree_info.leaf_count, 1);

    assert_eq!(proof.generation_timestamp, 1640000002);
}

#[test]
fn test_proof_element_structure() {
    let element = ProofElement {
        hash: "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd".to_string(),
        is_left: true,
        level: 2,
    };

    assert_eq!(
        element.hash,
        "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
    );
    assert!(element.is_left);
    assert_eq!(element.level, 2);
}

#[test]
fn test_entry_info_structure() {
    let entry_id = Uuid::new_v4();
    let mut metadata = HashMap::new();
    metadata.insert("author".to_string(), "test".to_string());
    metadata.insert("type".to_string(), "verification".to_string());

    let entry_info = EntryInfo {
        id: entry_id,
        version: 3,
        timestamp: 1640000003,
        data_hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab".to_string(),
        data_size: 150,
        metadata,
    };

    assert_eq!(entry_info.id, entry_id);
    assert_eq!(entry_info.version, 3);
    assert_eq!(entry_info.timestamp, 1640000003);
    assert_eq!(
        entry_info.data_hash,
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
    assert_eq!(entry_info.data_size, 150);
    assert_eq!(entry_info.metadata.len(), 2);
    assert_eq!(entry_info.metadata.get("author"), Some(&"test".to_string()));
    assert_eq!(
        entry_info.metadata.get("type"),
        Some(&"verification".to_string())
    );
}

#[test]
fn test_version_metadata_structure() {
    let metadata = VersionMetadata {
        current_version: 5,
        total_versions: 10,
        version_at_timestamp: Some(1640000005),
        historical_context: true,
        version_range: (1, 10),
    };

    assert_eq!(metadata.current_version, 5);
    assert_eq!(metadata.total_versions, 10);
    assert_eq!(metadata.version_at_timestamp, Some(1640000005));
    assert!(metadata.historical_context);
    assert_eq!(metadata.version_range, (1, 10));
}

#[test]
fn test_tree_info_structure() {
    let tree_info = TreeInfo {
        total_entries: 128,
        tree_height: 7,
        root_hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12".to_string(),
        leaf_count: 128,
    };

    assert_eq!(tree_info.total_entries, 128);
    assert_eq!(tree_info.tree_height, 7);
    assert_eq!(
        tree_info.root_hash,
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
    );
    assert_eq!(tree_info.leaf_count, 128);
}

#[test]
fn test_verification_details_structure() {
    let details = VerificationDetails {
        root_hash_match: true,
        path_validation: true,
        temporal_consistency: true,
        version_consistency: true,
        cryptographic_validity: true,
        proof_depth: 5,
        tree_height: 6,
        entry_timestamp: 1640000001,
        proof_timestamp: 1640000002,
        hash_function: "Blake3".to_string(),
    };

    assert!(details.root_hash_match);
    assert!(details.path_validation);
    assert!(details.temporal_consistency);
    assert!(details.version_consistency);
    assert!(details.cryptographic_validity);
    assert_eq!(details.proof_depth, 5);
    assert_eq!(details.tree_height, 6);
    assert_eq!(details.entry_timestamp, 1640000001);
    assert_eq!(details.proof_timestamp, 1640000002);
    assert_eq!(details.hash_function, "Blake3");
}

#[test]
fn test_proof_file_creation_and_loading() {
    let temp_dir = tempdir().unwrap();
    let entry_id = Uuid::new_v4();

    let proof_file = create_test_proof_file(temp_dir.path(), entry_id, 1);

    // Verify the file was created
    assert!(proof_file.exists());

    // Load and verify the proof
    let file = File::open(&proof_file).unwrap();
    let proof: SerializedProof = serde_json::from_reader(file).unwrap();

    assert_eq!(proof.entry_info.id, entry_id);
    assert_eq!(proof.entry_info.version, 1);
    assert_eq!(proof.proof.proof_path.len(), 2);
    assert!(proof.proof.is_valid);
}

#[test]
fn test_invalid_proof_file_creation() {
    let temp_dir = tempdir().unwrap();
    let proof_file = create_invalid_proof_file(temp_dir.path());

    // Verify the file was created
    assert!(proof_file.exists());

    // Load the proof
    let file = File::open(&proof_file).unwrap();
    let proof: SerializedProof = serde_json::from_reader(file).unwrap();

    // Verify it's marked as invalid
    assert!(!proof.proof.is_valid);
    assert_eq!(proof.proof.root_hash, "invalid_hex");
    assert_eq!(proof.entry_info.data_hash, "invalid_hash");
}

#[test]
fn test_multiple_proof_files_creation() {
    let temp_dir = tempdir().unwrap();
    let entry_id1 = Uuid::new_v4();
    let entry_id2 = Uuid::new_v4();
    let entry_id3 = Uuid::new_v4();

    let proof_file1 = create_test_proof_file(temp_dir.path(), entry_id1, 1);
    let proof_file2 = create_test_proof_file(temp_dir.path(), entry_id2, 2);
    let proof_file3 = create_test_proof_file(temp_dir.path(), entry_id3, 3);

    // Verify all files were created
    assert!(proof_file1.exists());
    assert!(proof_file2.exists());
    assert!(proof_file3.exists());

    // Load and verify each proof
    let file1 = File::open(&proof_file1).unwrap();
    let proof1: SerializedProof = serde_json::from_reader(file1).unwrap();
    assert_eq!(proof1.entry_info.id, entry_id1);
    assert_eq!(proof1.entry_info.version, 1);

    let file2 = File::open(&proof_file2).unwrap();
    let proof2: SerializedProof = serde_json::from_reader(file2).unwrap();
    assert_eq!(proof2.entry_info.id, entry_id2);
    assert_eq!(proof2.entry_info.version, 2);

    let file3 = File::open(&proof_file3).unwrap();
    let proof3: SerializedProof = serde_json::from_reader(file3).unwrap();
    assert_eq!(proof3.entry_info.id, entry_id3);
    assert_eq!(proof3.entry_info.version, 3);
}

#[test]
fn test_ledger_creation_for_testing() {
    let ledger = create_test_ledger();

    assert_eq!(ledger.entry_count(), 3);
    assert!(!ledger.is_empty());

    let entries = ledger.get_entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].data, b"test data 1");
    assert_eq!(entries[1].data, b"test data 2");
    assert_eq!(entries[2].data, b"test data 3");

    assert_eq!(entries[0].version, 0);
    assert_eq!(entries[1].version, 1);
    assert_eq!(entries[2].version, 2);
}

#[test]
fn test_proof_serialization_roundtrip() {
    let entry_id = Uuid::new_v4();
    let original_proof = SerializedProof {
        proof: SerializableProof {
            entry_id,
            leaf_index: 0,
            root_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            proof_path: vec![ProofElement {
                hash: "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                    .to_string(),
                is_left: true,
                level: 0,
            }],
            is_valid: true,
        },
        entry_info: EntryInfo {
            id: entry_id,
            version: 1,
            timestamp: 1640000001,
            data_hash: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                .to_string(),
            data_size: 20,
            metadata: HashMap::new(),
        },
        version_metadata: VersionMetadata {
            current_version: 1,
            total_versions: 1,
            version_at_timestamp: Some(1640000001),
            historical_context: false,
            version_range: (0, 1),
        },
        tree_info: TreeInfo {
            total_entries: 1,
            tree_height: 1,
            root_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            leaf_count: 1,
        },
        generation_timestamp: 1640000002,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&original_proof).unwrap();

    // Deserialize back
    let deserialized_proof: SerializedProof = serde_json::from_str(&json).unwrap();

    // Verify all fields match
    assert_eq!(
        deserialized_proof.proof.entry_id,
        original_proof.proof.entry_id
    );
    assert_eq!(
        deserialized_proof.proof.leaf_index,
        original_proof.proof.leaf_index
    );
    assert_eq!(
        deserialized_proof.proof.root_hash,
        original_proof.proof.root_hash
    );
    assert_eq!(
        deserialized_proof.proof.proof_path.len(),
        original_proof.proof.proof_path.len()
    );
    assert_eq!(
        deserialized_proof.proof.is_valid,
        original_proof.proof.is_valid
    );

    assert_eq!(
        deserialized_proof.entry_info.id,
        original_proof.entry_info.id
    );
    assert_eq!(
        deserialized_proof.entry_info.version,
        original_proof.entry_info.version
    );
    assert_eq!(
        deserialized_proof.entry_info.timestamp,
        original_proof.entry_info.timestamp
    );
    assert_eq!(
        deserialized_proof.entry_info.data_hash,
        original_proof.entry_info.data_hash
    );
    assert_eq!(
        deserialized_proof.entry_info.data_size,
        original_proof.entry_info.data_size
    );

    assert_eq!(
        deserialized_proof.version_metadata.current_version,
        original_proof.version_metadata.current_version
    );
    assert_eq!(
        deserialized_proof.version_metadata.total_versions,
        original_proof.version_metadata.total_versions
    );
    assert_eq!(
        deserialized_proof.version_metadata.version_at_timestamp,
        original_proof.version_metadata.version_at_timestamp
    );
    assert_eq!(
        deserialized_proof.version_metadata.historical_context,
        original_proof.version_metadata.historical_context
    );
    assert_eq!(
        deserialized_proof.version_metadata.version_range,
        original_proof.version_metadata.version_range
    );

    assert_eq!(
        deserialized_proof.tree_info.total_entries,
        original_proof.tree_info.total_entries
    );
    assert_eq!(
        deserialized_proof.tree_info.tree_height,
        original_proof.tree_info.tree_height
    );
    assert_eq!(
        deserialized_proof.tree_info.root_hash,
        original_proof.tree_info.root_hash
    );
    assert_eq!(
        deserialized_proof.tree_info.leaf_count,
        original_proof.tree_info.leaf_count
    );

    assert_eq!(
        deserialized_proof.generation_timestamp,
        original_proof.generation_timestamp
    );
}
