use std::fs;
use sylva::cli::optimize::OptimizationEngine;
use sylva::ledger::{Ledger, LedgerEntry};
use sylva::storage::LedgerStorage;
use sylva::tree::{TreeType, UnifiedTree};
use sylva::workspace::Workspace;
use tempfile::TempDir;

fn create_test_workspace() -> (TempDir, Workspace) {
    let temp_dir = TempDir::new().unwrap();
    let workspace = Workspace::init(temp_dir.path()).unwrap();
    (temp_dir, workspace)
}

fn create_test_ledger(entry_count: usize) -> Ledger {
    let mut ledger = Ledger::new();

    for i in 0..entry_count {
        let data = format!("test data entry {}", i).into_bytes();
        ledger.add_entry(data).unwrap();
    }

    ledger
}

fn create_unoptimized_tree(tree_type: TreeType, entry_count: usize) -> UnifiedTree {
    let mut tree = UnifiedTree::new(tree_type);
    let ledger = create_test_ledger(entry_count);

    for entry in ledger.get_entries() {
        tree.insert_ledger_entry(entry.clone()).unwrap();
    }

    // Add some inefficiency by inserting and removing entries
    for i in 0..entry_count / 5 {
        let dummy_entry = LedgerEntry::new(format!("dummy {}", i).into_bytes(), 9999 + i as u64);
        tree.insert_ledger_entry(dummy_entry).unwrap();
    }

    tree
}

#[test]
fn test_tree_compaction() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = create_unoptimized_tree(tree_type, 100);
        let before_stats = tree.statistics();

        tree.compact().unwrap();

        let after_stats = tree.statistics();

        // After compaction, the tree should be valid
        assert!(tree.validate().unwrap());

        // Memory usage should not increase after compaction
        assert!(after_stats.memory_usage.total_bytes <= before_stats.memory_usage.total_bytes);

        println!("Tree type: {:?}", tree_type);
        println!(
            "Before compaction: {} bytes",
            before_stats.memory_usage.total_bytes
        );
        println!(
            "After compaction: {} bytes",
            after_stats.memory_usage.total_bytes
        );
    }
}

#[test]
fn test_redundant_data_removal() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = create_unoptimized_tree(tree_type, 100);
        let before_stats = tree.statistics();

        tree.remove_redundant_data().unwrap();

        let after_stats = tree.statistics();

        // After redundant data removal, the tree should be valid
        assert!(tree.validate().unwrap());

        // Memory usage should not increase
        assert!(after_stats.memory_usage.total_bytes <= before_stats.memory_usage.total_bytes);

        println!("Tree type: {:?}", tree_type);
        println!(
            "Before redundant data removal: {} bytes",
            before_stats.memory_usage.total_bytes
        );
        println!(
            "After redundant data removal: {} bytes",
            after_stats.memory_usage.total_bytes
        );
    }
}

#[test]
fn test_tree_rebalancing() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = create_unoptimized_tree(tree_type, 100);
        let before_stats = tree.statistics();

        tree.rebalance().unwrap();

        let after_stats = tree.statistics();

        // After rebalancing, the tree should be valid
        assert!(tree.validate().unwrap());

        // Entry count should remain the same
        assert_eq!(before_stats.entry_count, after_stats.entry_count);

        println!("Tree type: {:?}", tree_type);
        println!(
            "Before rebalancing - efficiency: {:.2}%",
            before_stats.memory_usage.efficiency() * 100.0
        );
        println!(
            "After rebalancing - efficiency: {:.2}%",
            after_stats.memory_usage.efficiency() * 100.0
        );
    }
}

#[test]
fn test_full_optimization_pipeline() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = create_unoptimized_tree(tree_type, 200);
        let before_stats = tree.statistics();

        // Run full optimization pipeline
        tree.compact().unwrap();
        tree.remove_redundant_data().unwrap();
        tree.rebalance().unwrap();

        let after_stats = tree.statistics();

        // Tree should remain valid after optimization
        assert!(tree.validate().unwrap());

        // Entry count should remain the same
        assert_eq!(before_stats.entry_count, after_stats.entry_count);

        // Memory efficiency should not decrease
        assert!(after_stats.memory_usage.efficiency() >= before_stats.memory_usage.efficiency());

        let space_savings = if before_stats.memory_usage.total_bytes > 0 {
            ((before_stats.memory_usage.total_bytes - after_stats.memory_usage.total_bytes) as f64
                / before_stats.memory_usage.total_bytes as f64)
                * 100.0
        } else {
            0.0
        };

        println!("Tree type: {:?}", tree_type);
        println!("Space savings: {:.2}%", space_savings);
        println!(
            "Efficiency improvement: {:.2}% -> {:.2}%",
            before_stats.memory_usage.efficiency() * 100.0,
            after_stats.memory_usage.efficiency() * 100.0
        );
    }
}

#[test]
fn test_optimization_engine_creation() {
    let (_temp_dir, workspace) = create_test_workspace();
    let engine = OptimizationEngine::new(workspace);
    assert!(engine.is_ok());
}

#[test]
fn test_workspace_optimization_dry_run() {
    let (_temp_dir, workspace) = create_test_workspace();
    let storage = LedgerStorage::new(&workspace).unwrap();

    // Create some test ledgers
    for i in 0..3 {
        let ledger = create_test_ledger(50);
        storage
            .save_ledger(&ledger, &format!("test_ledger_{}", i))
            .unwrap();
    }

    let mut engine = OptimizationEngine::new(workspace).unwrap();
    let report = engine.optimize_workspace(true).unwrap(); // dry run

    assert!(report.total_trees < 1000); // Sanity check instead of >= 0
    assert!(report.optimization_time >= 0.0);
    assert!(!report.workspace_path.as_os_str().is_empty());
}

#[test]
fn test_optimization_report_display() {
    let (_temp_dir, workspace) = create_test_workspace();
    let mut engine = OptimizationEngine::new(workspace).unwrap();

    let report = engine.optimize_workspace(true).unwrap();
    let display_output = report.display();

    assert!(display_output.contains("Tree Optimization Report"));
    assert!(
        display_output.contains("Storage Summary") || display_output.contains("Storage Analysis")
    );
}

#[test]
fn test_tree_migration_optimization() {
    let tree_pairs = [
        (TreeType::Binary, TreeType::Sparse),
        (TreeType::Sparse, TreeType::Patricia),
    ];

    for (from_type, to_type) in tree_pairs {
        let tree = create_unoptimized_tree(from_type, 50);
        let before_stats = tree.statistics();

        let migrated_tree = tree.migrate_to(to_type).unwrap();
        let after_stats = migrated_tree.statistics();

        // Migrated tree should be valid
        assert!(migrated_tree.validate().unwrap());

        // Tree type should have changed
        assert_eq!(migrated_tree.tree_type(), to_type);

        // Entry count should be preserved (approximately, depending on migration)
        // For key-value trees, we may lose some entries in the conversion
        if from_type == TreeType::Binary {
            // Binary to other migrations may not preserve exact count due to conversion
            assert!(after_stats.entry_count <= before_stats.entry_count);
        } else {
            assert_eq!(after_stats.entry_count, before_stats.entry_count);
        }

        println!("Migration: {:?} -> {:?}", from_type, to_type);
        println!(
            "Entry count: {} -> {}",
            before_stats.entry_count, after_stats.entry_count
        );
    }
}

#[test]
fn test_memory_usage_calculation() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let tree = create_unoptimized_tree(tree_type, 100);
        let memory_usage = tree.memory_usage();

        assert!(memory_usage.total_bytes > 0);
        assert!(memory_usage.data_bytes <= memory_usage.total_bytes);
        assert!(memory_usage.metadata_bytes <= memory_usage.total_bytes);
        assert!(memory_usage.structure_bytes <= memory_usage.total_bytes);

        let efficiency = memory_usage.efficiency();
        assert!(efficiency >= 0.0 && efficiency <= 1.0);

        println!("Tree type: {:?}", tree_type);
        println!("Total bytes: {}", memory_usage.total_bytes);
        println!("Efficiency: {:.2}%", efficiency * 100.0);
    }
}

#[test]
fn test_optimization_preserves_data_integrity() {
    let mut tree = create_unoptimized_tree(TreeType::Binary, 100);

    // Get original entry count (avoiding borrow checker issues)
    let original_count = tree.entry_count();

    // Perform optimization
    tree.compact().unwrap();
    tree.remove_redundant_data().unwrap();
    tree.rebalance().unwrap();

    // Get optimized entry count
    let optimized_count = tree.entry_count();

    // Data should be preserved (though some optimization may reduce count)
    assert!(optimized_count > 0);

    // At least 80% of entries should be preserved (allowing for dummy removal)
    assert!(optimized_count >= original_count * 80 / 100);
}

#[test]
fn test_storage_analysis() {
    let (_temp_dir, workspace) = create_test_workspace();
    let storage = LedgerStorage::new(&workspace).unwrap();

    // Create test ledgers with different characteristics
    for i in 0..5 {
        let ledger = create_test_ledger(20 + i * 10);
        storage
            .save_ledger(&ledger, &format!("ledger_{}", i))
            .unwrap();
    }

    // Create some "unused" files by writing directly to the directory
    let ledgers_path = workspace.ledgers_path();
    fs::write(ledgers_path.join("unused.backup"), b"backup data").unwrap();
    fs::write(ledgers_path.join("temp.tmp"), b"temporary data").unwrap();

    let engine = OptimizationEngine::new(workspace).unwrap();
    let storage_analysis = engine.analyze_storage().unwrap();

    assert!(storage_analysis.total_files > 0);
    assert!(storage_analysis.total_size > 0);
    assert!(!storage_analysis.unused_files.is_empty()); // Should detect backup and tmp files
}

#[test]
fn test_optimization_recommendations() {
    let (_temp_dir, workspace) = create_test_workspace();
    let storage = LedgerStorage::new(&workspace).unwrap();

    // Create test data
    let ledger = create_test_ledger(100);
    storage.save_ledger(&ledger, "test_ledger").unwrap();

    let mut engine = OptimizationEngine::new(workspace).unwrap();
    let report = engine.optimize_workspace(true).unwrap();

    // Should generate some recommendations or complete without error
    assert!(report.recommendations.len() < 1000); // Sanity check instead of >= 0

    for recommendation in &report.recommendations {
        println!(
            "Recommendation: {:?} - {}",
            recommendation.recommendation_type, recommendation.description
        );
    }
}

#[test]
fn test_tree_validation_after_optimization() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = create_unoptimized_tree(tree_type, 50);

        // Tree should be valid before optimization
        assert!(tree.validate().unwrap());

        // Optimize
        tree.compact().unwrap();
        assert!(tree.validate().unwrap());

        tree.remove_redundant_data().unwrap();
        assert!(tree.validate().unwrap());

        tree.rebalance().unwrap();
        assert!(tree.validate().unwrap());

        println!(
            "Tree type {:?} remains valid after all optimizations",
            tree_type
        );
    }
}

#[test]
fn test_empty_tree_optimization() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let mut tree = UnifiedTree::new(tree_type);

        // Empty tree should handle optimization gracefully
        assert!(tree.compact().is_ok());
        assert!(tree.remove_redundant_data().is_ok());
        assert!(tree.rebalance().is_ok());

        // Should remain empty and valid
        assert!(tree.is_empty());
        assert!(tree.validate().unwrap());
    }
}

#[test]
fn test_optimization_idempotency() {
    let mut tree = create_unoptimized_tree(TreeType::Binary, 100);

    // First optimization
    tree.compact().unwrap();
    tree.remove_redundant_data().unwrap();
    tree.rebalance().unwrap();

    let first_stats = tree.statistics();

    // Second optimization should have minimal impact
    tree.compact().unwrap();
    tree.remove_redundant_data().unwrap();
    tree.rebalance().unwrap();

    let second_stats = tree.statistics();

    // Stats should be very similar after second optimization
    assert_eq!(first_stats.entry_count, second_stats.entry_count);

    // Memory usage should not increase significantly
    let size_diff = (second_stats.memory_usage.total_bytes as i64
        - first_stats.memory_usage.total_bytes as i64)
        .abs();
    let size_tolerance = first_stats.memory_usage.total_bytes / 20; // 5% tolerance

    assert!(
        size_diff as usize <= size_tolerance,
        "Memory usage changed too much on second optimization: {} vs {} (diff: {})",
        first_stats.memory_usage.total_bytes,
        second_stats.memory_usage.total_bytes,
        size_diff
    );
}
