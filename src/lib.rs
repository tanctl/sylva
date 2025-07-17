pub mod cache;
pub mod cli;
pub mod config;
pub mod error;
pub mod hash;
pub mod ledger;
pub mod proof;
pub mod storage;
pub mod streaming;
pub mod tree;
pub mod workspace;

pub use error::SylvaError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let mut ledger = ledger::Ledger::new();
        let data = b"test data".to_vec();
        let id = ledger.add_entry(data).unwrap();
        assert!(ledger.get_entry(&id).unwrap().is_some());
    }

    #[test]
    fn test_hash_calculation() {
        use hash::{Blake3Hasher, Hash};
        let hasher = Blake3Hasher::new();
        let data = b"test data";
        let hash = hasher.hash_bytes(data).unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_merkle_tree() {
        use tree::{binary::BinaryMerkleTree, Tree};
        let mut tree = BinaryMerkleTree::new();
        let entry = ledger::LedgerEntry::new(b"test data".to_vec(), 1);
        assert!(tree.insert(entry).is_ok());
    }

    #[test]
    fn test_proof_creation() {
        let proof = proof::Proof::new("test-id".to_string());
        assert_eq!(proof.entry_id, "test-id");
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_storage() {
        use storage::LedgerStorage;
        use tempfile::TempDir;
        use workspace::Workspace;

        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = LedgerStorage::new(&workspace).unwrap();

        let mut ledger = ledger::Ledger::new();
        ledger.add_entry(b"test data".to_vec()).unwrap();

        let ledger_id = storage.save_ledger(&ledger, "test ledger").unwrap();
        let loaded = storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded.ledger.entry_count(), 1);
    }

    #[test]
    fn test_config_creation() {
        let config = config::Config::new();
        assert_eq!(config.get_default_hash(), "blake3");
        assert_eq!(config.get_cache_size(), 1000);
        assert_eq!(config.get_compression_level(), 3);
        assert_eq!(config.get_ledger_format(), "json");
    }
}
