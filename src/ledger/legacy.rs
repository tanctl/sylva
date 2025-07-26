//! core ledger implementation for Sylva

use crate::error::{Result, SylvaError};
use crate::hash::{Blake3Hasher, EntryHashContext, Hash, HashOutput};
use crate::proof::{Proof, ProofGenerator};
use crate::storage::{Storage, StorageFactory};
use crate::tree::MerkleTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

/// versioned ledger with merkle tree proof generation
pub struct Ledger {
    storage: Box<dyn Storage>,
    entry_index: HashMap<Uuid, EntryMetadata>,
    current_version: u64,
    proof_generator: ProofGenerator,
    hasher: Blake3Hasher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// single entry in the ledger
pub struct LedgerEntry {
    /// unique entry identifier
    pub id: Uuid,
    /// entry version number
    pub version: u64,
    /// raw entry data
    pub data: Vec<u8>,
    /// entry metadata
    pub metadata: EntryMetadata,
    /// hash of the entry data
    pub data_hash: HashOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// metadata for ledger entries
pub struct EntryMetadata {
    /// when entry was created (unix timestamp)
    pub timestamp: u64,
    /// optional user message
    pub message: Option<String>,
    /// tags for categorizing entries
    pub tags: Vec<String>,
    /// mime type or content type
    pub content_type: Option<String>,
    /// size of entry data in bytes
    pub size: u64,
    /// id of previous version if any
    pub previous_id: Option<Uuid>,
    /// extra key-value properties
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// statistics about the ledger
pub struct LedgerStats {
    /// total number of entries
    pub entry_count: usize,
    /// total size of all entries in bytes
    pub total_size: u64,
    /// current ledger version
    pub current_version: u64,
    /// number of entry chains
    pub entry_chains: usize,
}

impl Ledger {
    /// create new ledger with filesystem storage
    pub fn new(base_path: PathBuf) -> Result<Self> {
        let storage = StorageFactory::filesystem(base_path)?;
        Self::with_storage(storage)
    }

    /// create new ledger with custom storage backend
    pub fn with_storage(storage: Box<dyn Storage>) -> Result<Self> {
        let mut ledger = Self {
            storage,
            entry_index: HashMap::new(),
            current_version: 0,
            proof_generator: ProofGenerator::default(),
            hasher: Blake3Hasher::new(),
        };

        ledger.load_entries()?;

        Ok(ledger)
    }

    /// load existing ledger from filesystem
    pub fn load(base_path: PathBuf) -> Result<Self> {
        Self::new(base_path)
    }

    /// add new entry to the ledger
    pub fn add_entry(&mut self, data: Vec<u8>, message: Option<String>) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.current_version += 1;

        let entry_context = EntryHashContext {
            entry_id: id,
            version: self.current_version,
            timestamp,
            previous_id: None,
            content_type: None,
            metadata: HashMap::new(),
        };

        let data_hash = self.hasher.hash_entry(&data, &entry_context)?;

        let metadata = EntryMetadata {
            timestamp,
            message,
            tags: Vec::new(),
            content_type: None,
            size: data.len() as u64,
            previous_id: None,
            properties: HashMap::new(),
        };

        let entry = LedgerEntry {
            id,
            version: self.current_version,
            data,
            metadata: metadata.clone(),
            data_hash,
        };

        let key = format!("entry:{}", id);
        let entry_data = serde_json::to_vec(&entry)?;
        self.storage.store(&key, &entry_data)?;

        self.entry_index.insert(id, metadata);

        self.save_version_info()?;

        Ok(id)
    }

    /// get entry by id
    pub fn get_entry(&self, id: Uuid) -> Result<LedgerEntry> {
        let key = format!("entry:{}", id);
        let entry_data = self
            .storage
            .retrieve(&key)
            .map_err(|_| SylvaError::entry_not_found(id))?;

        let entry: LedgerEntry = serde_json::from_slice(&entry_data)?;
        Ok(entry)
    }

    /// check if entry exists
    pub fn entry_exists(&self, id: Uuid) -> Result<bool> {
        Ok(self.entry_index.contains_key(&id))
    }

    /// list all entry ids
    pub fn list_entries(&self) -> Result<Vec<Uuid>> {
        Ok(self.entry_index.keys().cloned().collect())
    }

    /// get entry metadata without loading full data
    pub fn get_entry_metadata(&self, id: Uuid) -> Result<&EntryMetadata> {
        self.entry_index
            .get(&id)
            .ok_or_else(|| SylvaError::entry_not_found(id))
    }

    /// update existing entry (creates new version)
    pub fn update_entry(
        &mut self,
        id: Uuid,
        new_data: Vec<u8>,
        message: Option<String>,
    ) -> Result<Uuid> {
        let existing_entry = self.get_entry(id)?;

        let new_id = Uuid::new_v4();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.current_version += 1;

        let new_entry_version = existing_entry.version + 1;

        let entry_context = EntryHashContext {
            entry_id: new_id,
            version: new_entry_version,
            timestamp,
            previous_id: Some(id),
            content_type: existing_entry.metadata.content_type.clone(),
            metadata: existing_entry.metadata.properties.clone(),
        };

        let data_hash = self.hasher.hash_entry(&new_data, &entry_context)?;

        let metadata = EntryMetadata {
            timestamp,
            message,
            tags: existing_entry.metadata.tags.clone(),
            content_type: existing_entry.metadata.content_type.clone(),
            size: new_data.len() as u64,
            previous_id: Some(id),
            properties: existing_entry.metadata.properties.clone(),
        };

        let entry = LedgerEntry {
            id: new_id,
            version: new_entry_version,
            data: new_data,
            metadata: metadata.clone(),
            data_hash,
        };

        let key = format!("entry:{}", new_id);
        let entry_data = serde_json::to_vec(&entry)?;
        self.storage.store(&key, &entry_data)?;

        self.entry_index.insert(new_id, metadata);
        self.save_version_info()?;

        Ok(new_id)
    }

    /// generate cryptographic proof for an entry
    pub fn generate_proof(&self, id: Uuid) -> Result<Proof> {
        let entry = self.get_entry(id)?;

        let leaves = vec![&entry.data[..]];
        let tree = MerkleTree::new(&leaves)?;
        let merkle_proof = tree.generate_proof(0, &leaves)?;

        let proof = self.proof_generator.generate_existence_proof(
            id,
            entry.version,
            &entry.data,
            merkle_proof,
        )?;

        Ok(proof)
    }

    /// verify proof against entry data
    pub fn verify_proof(&self, proof: &Proof, data: &[u8]) -> Result<bool> {
        if !self.entry_exists(proof.entry_id)? {
            return Ok(false);
        }
        proof.verify(data)
    }

    /// get ledger statistics
    pub fn stats(&self) -> Result<LedgerStats> {
        let storage_stats = self.storage.stats()?;

        let mut chains = std::collections::HashSet::new();
        for metadata in self.entry_index.values() {
            if metadata.previous_id.is_none() {
                chains.insert("root");
            }
        }

        Ok(LedgerStats {
            entry_count: self.entry_index.len(),
            total_size: storage_stats.total_size,
            current_version: self.current_version,
            entry_chains: chains.len(),
        })
    }

    /// validate ledger integrity
    pub fn validate(&self) -> Result<()> {
        for id in self.entry_index.keys() {
            let key = format!("entry:{}", id);
            if !self.storage.exists(&key)? {
                return Err(SylvaError::internal(format!(
                    "Entry {} missing from storage",
                    id
                )));
            }
        }

        // todo: add more comprehensive validation

        Ok(())
    }

    /// add tag to existing entry
    pub fn add_entry_tag(&mut self, id: Uuid, tag: String) -> Result<()> {
        let mut entry = self.get_entry(id)?;
        if !entry.metadata.tags.contains(&tag) {
            entry.metadata.tags.push(tag);

            let key = format!("entry:{}", id);
            let entry_data = serde_json::to_vec(&entry)?;
            self.storage.store(&key, &entry_data)?;

            self.entry_index.insert(id, entry.metadata);
        }
        Ok(())
    }

    /// find entries with specific tag
    pub fn find_entries_by_tag(&self, tag: &str) -> Result<Vec<Uuid>> {
        let mut results = Vec::new();
        for (id, metadata) in &self.entry_index {
            if metadata.tags.contains(&tag.to_string()) {
                results.push(*id);
            }
        }
        Ok(results)
    }

    fn load_entries(&mut self) -> Result<()> {
        let keys = self.storage.list_keys()?;

        for key in keys {
            if key.starts_with("entry:") {
                let entry_data = self.storage.retrieve(&key)?;
                let entry: LedgerEntry = serde_json::from_slice(&entry_data)?;
                self.entry_index.insert(entry.id, entry.metadata);

                if entry.version > self.current_version {
                    self.current_version = entry.version;
                }
            }
        }

        Ok(())
    }

    fn save_version_info(&mut self) -> Result<()> {
        let version_info = serde_json::json!({
            "current_version": self.current_version,
            "entry_count": self.entry_index.len()
        });

        let version_data = serde_json::to_vec(&version_info)?;
        self.storage.store("version_info", &version_data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_ledger_creation() {
        let storage = Box::new(MemoryStorage::new());
        let ledger = Ledger::with_storage(storage).unwrap();
        assert_eq!(ledger.current_version, 0);
    }

    #[test]
    fn test_add_and_get_entry() {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage).unwrap();

        let data = b"test data".to_vec();
        let message = Some("Test entry".to_string());

        let id = ledger.add_entry(data.clone(), message.clone()).unwrap();
        let entry = ledger.get_entry(id).unwrap();

        assert_eq!(entry.data, data);
        assert_eq!(entry.metadata.message, message);
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn test_entry_versioning() {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage).unwrap();

        let data1 = b"initial data".to_vec();
        let id1 = ledger
            .add_entry(data1, Some("Initial".to_string()))
            .unwrap();

        let data2 = b"updated data".to_vec();
        let id2 = ledger
            .update_entry(id1, data2.clone(), Some("Updated".to_string()))
            .unwrap();

        let entry2 = ledger.get_entry(id2).unwrap();
        assert_eq!(entry2.data, data2);
        assert_eq!(entry2.metadata.previous_id, Some(id1));
        assert_eq!(entry2.version, 2);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage).unwrap();

        let data = b"test data for proof".to_vec();
        let id = ledger.add_entry(data.clone(), None).unwrap();

        let proof = ledger.generate_proof(id).unwrap();
        let is_valid = ledger.verify_proof(&proof, &data).unwrap();

        assert!(is_valid);
        assert_eq!(proof.entry_id, id);
    }

    #[test]
    fn test_entry_tags() {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage).unwrap();

        let data = b"tagged data".to_vec();
        let id = ledger.add_entry(data, None).unwrap();

        ledger.add_entry_tag(id, "important".to_string()).unwrap();

        let tagged_entries = ledger.find_entries_by_tag("important").unwrap();
        assert!(tagged_entries.contains(&id));
    }

    #[test]
    fn test_ledger_stats() {
        let storage = Box::new(MemoryStorage::new());
        let mut ledger = Ledger::with_storage(storage).unwrap();

        let data1 = b"data1".to_vec();
        let data2 = b"data2".to_vec();

        ledger.add_entry(data1, None).unwrap();
        ledger.add_entry(data2, None).unwrap();

        let stats = ledger.stats().unwrap();
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.current_version, 2);
    }
}
