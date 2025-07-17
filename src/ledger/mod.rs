use crate::error::Result;
use crate::hash::HashDigest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub timestamp: u64,
    pub data: Vec<u8>,
    pub version: u64,
    pub metadata: HashMap<String, String>,
    pub previous_hash: Option<HashDigest>,
}

impl LedgerEntry {
    pub fn new(data: Vec<u8>, version: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            data,
            version,
            metadata: HashMap::new(),
            previous_hash: None,
        }
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_previous_hash(mut self, previous_hash: HashDigest) -> Self {
        self.previous_hash = Some(previous_hash);
        self
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    pub fn data_size(&self) -> usize {
        self.data.len()
    }

    pub fn is_version(&self, version: u64) -> bool {
        self.version == version
    }

    pub fn is_newer_than(&self, other: &LedgerEntry) -> bool {
        self.version > other.version
            || (self.version == other.version && self.timestamp > other.timestamp)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    entries: Vec<LedgerEntry>,
    version_counter: u64,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            version_counter: 0,
        }
    }

    pub fn add_entry(&mut self, data: Vec<u8>) -> Result<Uuid> {
        let entry = LedgerEntry::new(data, self.version_counter);
        let id = entry.id;
        self.entries.push(entry);
        self.version_counter += 1;
        Ok(id)
    }

    pub fn add_entry_with_metadata(
        &mut self,
        data: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<Uuid> {
        let entry = LedgerEntry::new(data, self.version_counter).with_metadata(metadata);
        let id = entry.id;
        self.entries.push(entry);
        self.version_counter += 1;
        Ok(id)
    }

    pub fn get_entry(&self, id: &Uuid) -> Result<Option<&LedgerEntry>> {
        Ok(self.entries.iter().find(|e| e.id == *id))
    }

    pub fn get_entry_mut(&mut self, id: &Uuid) -> Result<Option<&mut LedgerEntry>> {
        Ok(self.entries.iter_mut().find(|e| e.id == *id))
    }

    pub fn get_entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    pub fn get_entries_by_version(&self, version: u64) -> Vec<&LedgerEntry> {
        self.entries
            .iter()
            .filter(|e| e.version == version)
            .collect()
    }

    pub fn get_entries_since_version(&self, version: u64) -> Vec<&LedgerEntry> {
        self.entries
            .iter()
            .filter(|e| e.version >= version)
            .collect()
    }

    pub fn latest_version(&self) -> u64 {
        self.entries.iter().map(|e| e.version).max().unwrap_or(0)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn version_count(&self) -> u64 {
        self.version_counter
    }

    pub fn remove_entry(&mut self, id: &Uuid) -> Result<Option<LedgerEntry>> {
        if let Some(pos) = self.entries.iter().position(|e| e.id == *id) {
            Ok(Some(self.entries.remove(pos)))
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.version_counter = 0;
    }

    pub fn entries_sorted_by_timestamp(&self) -> Vec<&LedgerEntry> {
        let mut entries: Vec<&LedgerEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        entries
    }

    pub fn entries_sorted_by_version(&self) -> Vec<&LedgerEntry> {
        let mut entries: Vec<&LedgerEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.version.cmp(&b.version));
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_entry_creation() {
        let data = b"test data".to_vec();
        let entry = LedgerEntry::new(data.clone(), 1);

        assert_eq!(entry.data, data);
        assert_eq!(entry.version, 1);
        assert!(entry.metadata.is_empty());
        assert!(entry.previous_hash.is_none());
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_ledger_entry_with_metadata() {
        let data = b"test data".to_vec();
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "test".to_string());

        let entry = LedgerEntry::new(data, 1).with_metadata(metadata.clone());

        assert_eq!(entry.metadata, metadata);
        assert_eq!(entry.get_metadata("author"), Some(&"test".to_string()));
        assert_eq!(entry.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_ledger_entry_version_comparison() {
        let entry1 = LedgerEntry::new(b"data1".to_vec(), 1);
        let entry2 = LedgerEntry::new(b"data2".to_vec(), 2);

        assert!(entry2.is_newer_than(&entry1));
        assert!(!entry1.is_newer_than(&entry2));
        assert!(entry1.is_version(1));
        assert!(!entry1.is_version(2));
    }

    #[test]
    fn test_ledger_operations() {
        let mut ledger = Ledger::new();

        assert!(ledger.is_empty());
        assert_eq!(ledger.entry_count(), 0);
        assert_eq!(ledger.latest_version(), 0);

        let id1 = ledger.add_entry(b"data1".to_vec()).unwrap();
        let id2 = ledger.add_entry(b"data2".to_vec()).unwrap();

        assert!(!ledger.is_empty());
        assert_eq!(ledger.entry_count(), 2);
        assert_eq!(ledger.latest_version(), 1);

        let entry1 = ledger.get_entry(&id1).unwrap().unwrap();
        assert_eq!(entry1.data, b"data1");
        assert_eq!(entry1.version, 0);

        let entry2 = ledger.get_entry(&id2).unwrap().unwrap();
        assert_eq!(entry2.data, b"data2");
        assert_eq!(entry2.version, 1);
    }

    #[test]
    fn test_ledger_version_queries() {
        let mut ledger = Ledger::new();

        let _id1 = ledger.add_entry(b"data1".to_vec()).unwrap();
        let _id2 = ledger.add_entry(b"data2".to_vec()).unwrap();
        let _id3 = ledger.add_entry(b"data3".to_vec()).unwrap();

        let entries_v1 = ledger.get_entries_by_version(1);
        assert_eq!(entries_v1.len(), 1);
        assert_eq!(entries_v1[0].data, b"data2");

        let entries_since_v1 = ledger.get_entries_since_version(1);
        assert_eq!(entries_since_v1.len(), 2);

        let entries_v99 = ledger.get_entries_by_version(99);
        assert_eq!(entries_v99.len(), 0);
    }

    #[test]
    fn test_ledger_with_metadata() {
        let mut ledger = Ledger::new();
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "test".to_string());

        let id = ledger
            .add_entry_with_metadata(b"data".to_vec(), metadata.clone())
            .unwrap();
        let entry = ledger.get_entry(&id).unwrap().unwrap();

        assert_eq!(entry.metadata, metadata);
    }

    #[test]
    fn test_ledger_sorting() {
        let mut ledger = Ledger::new();

        // Add entries with slight delays to ensure different timestamps
        let _id1 = ledger.add_entry(b"data1".to_vec()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let _id2 = ledger.add_entry(b"data2".to_vec()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let _id3 = ledger.add_entry(b"data3".to_vec()).unwrap();

        let sorted_by_version = ledger.entries_sorted_by_version();
        assert_eq!(sorted_by_version[0].version, 0);
        assert_eq!(sorted_by_version[1].version, 1);
        assert_eq!(sorted_by_version[2].version, 2);

        let sorted_by_timestamp = ledger.entries_sorted_by_timestamp();
        assert!(sorted_by_timestamp[0].timestamp <= sorted_by_timestamp[1].timestamp);
        assert!(sorted_by_timestamp[1].timestamp <= sorted_by_timestamp[2].timestamp);
    }

    #[test]
    fn test_ledger_entry_removal() {
        let mut ledger = Ledger::new();
        let id = ledger.add_entry(b"data".to_vec()).unwrap();

        assert_eq!(ledger.entry_count(), 1);

        let removed = ledger.remove_entry(&id).unwrap();
        assert!(removed.is_some());
        assert_eq!(ledger.entry_count(), 0);

        let removed_again = ledger.remove_entry(&id).unwrap();
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_ledger_clear() {
        let mut ledger = Ledger::new();
        let _id1 = ledger.add_entry(b"data1".to_vec()).unwrap();
        let _id2 = ledger.add_entry(b"data2".to_vec()).unwrap();

        assert_eq!(ledger.entry_count(), 2);
        assert_eq!(ledger.version_count(), 2);

        ledger.clear();

        assert_eq!(ledger.entry_count(), 0);
        assert_eq!(ledger.version_count(), 0);
        assert!(ledger.is_empty());
    }
}
