use sylva::error::Result;
use sylva::ledger::LedgerEntry;
use sylva::tree::{TreeFactory, TreeType, UnifiedTree};

#[test]
fn test_unified_tree_creation() -> Result<()> {
    // Test all tree types can be created
    for tree_type in TreeType::all() {
        let tree = UnifiedTree::new(*tree_type);
        assert_eq!(tree.tree_type(), *tree_type);
        assert!(tree.is_empty());
        assert_eq!(tree.entry_count(), 0);
    }
    Ok(())
}

#[test]
fn test_tree_factory() -> Result<()> {
    let factory = TreeFactory::new();

    // Test default creation
    let default_tree = factory.create_default()?;
    assert_eq!(default_tree.tree_type(), TreeType::Binary);

    // Test specific type creation
    for tree_type in TreeType::all() {
        let tree = factory.create(*tree_type)?;
        assert_eq!(tree.tree_type(), *tree_type);
    }

    Ok(())
}

#[test]
fn test_tree_with_ledger_entries() -> Result<()> {
    let mut tree = UnifiedTree::new(TreeType::Binary);

    // Create test entries
    let entries = vec![
        LedgerEntry::new(b"data1".to_vec(), 1),
        LedgerEntry::new(b"data2".to_vec(), 2),
        LedgerEntry::new(b"data3".to_vec(), 3),
    ];

    // Insert entries
    tree.insert_ledger_entries(entries)?;

    assert_eq!(tree.entry_count(), 3);
    assert!(!tree.is_empty());

    // Test statistics
    let stats = tree.statistics();
    assert_eq!(stats.tree_type, TreeType::Binary);
    assert_eq!(stats.entry_count, 3);

    Ok(())
}

#[test]
fn test_tree_migration() -> Result<()> {
    // Create binary tree with data
    let mut source_tree = UnifiedTree::new(TreeType::Binary);
    let entries = vec![
        LedgerEntry::new(b"test1".to_vec(), 1),
        LedgerEntry::new(b"test2".to_vec(), 2),
    ];
    source_tree.insert_ledger_entries(entries)?;

    // Test migration to sparse tree
    let migrated_tree = source_tree.migrate_to(TreeType::Sparse)?;
    assert_eq!(migrated_tree.tree_type(), TreeType::Sparse);
    assert_eq!(migrated_tree.entry_count(), 2);

    Ok(())
}

#[test]
fn test_tree_validation() -> Result<()> {
    let mut tree = UnifiedTree::new(TreeType::Binary);

    // Empty tree should be valid
    assert!(tree.validate()?);

    // Tree with data should be valid
    let entry = LedgerEntry::new(b"test".to_vec(), 1);
    tree.insert_ledger_entry(entry)?;
    assert!(tree.validate()?);

    Ok(())
}

#[test]
fn test_tree_metadata() -> Result<()> {
    let mut tree = UnifiedTree::new(TreeType::Binary);

    // Check initial metadata
    let metadata = tree.metadata();
    assert_eq!(metadata.tree_type, TreeType::Binary);
    assert_eq!(metadata.entry_count, 0);

    // Add configuration
    tree.metadata_mut().set_config("test_key", "test_value");
    assert_eq!(
        tree.metadata().get_config("test_key"),
        Some(&"test_value".to_string())
    );

    Ok(())
}

#[test]
fn test_key_value_operations() -> Result<()> {
    let mut sparse_tree = UnifiedTree::new(TreeType::Sparse);

    // Test key-value insertion
    sparse_tree.insert_key_value(b"key1", b"value1".to_vec())?;
    sparse_tree.insert_key_value(b"key2", b"value2".to_vec())?;

    assert_eq!(sparse_tree.entry_count(), 2);

    // Test key-value retrieval
    assert_eq!(sparse_tree.get_by_key(b"key1")?, Some(b"value1".to_vec()));
    assert_eq!(sparse_tree.get_by_key(b"key2")?, Some(b"value2".to_vec()));
    assert_eq!(sparse_tree.get_by_key(b"nonexistent")?, None);

    // Binary tree shouldn't support key-value operations
    let mut binary_tree = UnifiedTree::new(TreeType::Binary);
    assert!(binary_tree
        .insert_key_value(b"key", b"value".to_vec())
        .is_err());
    assert!(binary_tree.get_by_key(b"key").is_err());

    Ok(())
}

#[test]
fn test_tree_export_import() -> Result<()> {
    let mut source_tree = UnifiedTree::new(TreeType::Binary);
    let entries = vec![LedgerEntry::new(b"export_test".to_vec(), 1)];
    source_tree.insert_ledger_entries(entries)?;

    // Export data
    let export_data = source_tree.export_for_migration(TreeType::Binary)?;
    assert_eq!(export_data.source_tree_type, TreeType::Binary);
    assert_eq!(export_data.target_tree_type, TreeType::Binary);
    assert!(!export_data.ledger_entries.is_empty());

    // Import into new tree
    let mut target_tree = UnifiedTree::new(TreeType::Binary);
    target_tree.import_from_migration(export_data)?;

    assert_eq!(target_tree.entry_count(), 1);

    Ok(())
}

#[test]
fn test_migration_compatibility() -> Result<()> {
    let factory = TreeFactory::new();

    // Test compatible migrations
    assert!(factory.can_migrate(TreeType::Binary, TreeType::Binary));
    assert!(factory.can_migrate(TreeType::Binary, TreeType::Sparse));
    assert!(factory.can_migrate(TreeType::Sparse, TreeType::Patricia));
    assert!(factory.can_migrate(TreeType::Patricia, TreeType::Sparse));

    // Test migration paths
    let path = factory.migration_path(TreeType::Binary, TreeType::Binary);
    assert_eq!(path, vec![TreeType::Binary]);

    let path = factory.migration_path(TreeType::Binary, TreeType::Sparse);
    assert_eq!(path, vec![TreeType::Binary, TreeType::Sparse]);

    Ok(())
}

#[test]
fn test_tree_memory_usage() -> Result<()> {
    let mut tree = UnifiedTree::new(TreeType::Binary);

    // Get initial memory usage
    let initial_stats = tree.statistics();
    let initial_memory = initial_stats.memory_usage.total_bytes;

    // Add some data
    let entries = vec![
        LedgerEntry::new(b"memory_test_1".to_vec(), 1),
        LedgerEntry::new(b"memory_test_2".to_vec(), 2),
    ];
    tree.insert_ledger_entries(entries)?;

    // Memory usage should increase
    let updated_stats = tree.statistics();
    let updated_memory = updated_stats.memory_usage.total_bytes;

    assert!(updated_memory >= initial_memory);
    assert!(updated_stats.memory_usage.efficiency() > 0.0);
    assert!(updated_stats.memory_usage.efficiency() <= 1.0);

    Ok(())
}
