//! versioned ledger entries for sylva

pub mod legacy;

// re-export legacy types for compatibility
pub use legacy::{EntryMetadata, Ledger, LedgerEntry, LedgerStats};

use crate::hash::Hash;
use std::collections::HashMap;
use uuid::Uuid;

// utility functions for working with ledger entries
impl LedgerEntry {
    /// create new ledger entry
    pub fn new(data: Vec<u8>, message: Option<String>) -> Self {
        let id = Uuid::new_v4();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = crate::ledger::EntryMetadata {
            timestamp,
            message,
            tags: Vec::new(),
            content_type: None,
            size: data.len() as u64,
            previous_id: None,
            properties: HashMap::new(),
        };

        let data_hash = {
            let hasher = crate::hash::Blake3Hasher::new();
            let context = crate::hash::EntryHashContext {
                entry_id: id,
                version: 1,
                timestamp,
                previous_id: None,
                content_type: None,
                metadata: HashMap::new(),
            };

            hasher
                .hash_entry(&data, &context)
                .unwrap_or_else(|_| crate::hash::HashOutput::zero())
        };

        Self {
            id,
            version: 1,
            data,
            metadata,
            data_hash,
        }
    }
    /// create new version of existing entry
    pub fn new_version(previous: &Self, data: Vec<u8>, message: Option<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // create new entry with incremented version
        Self {
            id: Uuid::new_v4(),
            version: previous.version + 1,
            data: data.clone(),
            metadata: EntryMetadata {
                timestamp,
                message,
                tags: previous.metadata.tags.clone(),
                content_type: previous.metadata.content_type.clone(),
                size: data.len() as u64,
                previous_id: Some(previous.id),
                properties: previous.metadata.properties.clone(),
            },
            data_hash: {
                // calculate hash with proper context
                let hasher = crate::hash::Blake3Hasher::new();
                let context = crate::hash::EntryHashContext {
                    entry_id: Uuid::new_v4(), // will be set properly below
                    version: previous.version + 1,
                    timestamp,
                    previous_id: Some(previous.id),
                    content_type: previous.metadata.content_type.clone(),
                    metadata: previous.metadata.properties.clone(),
                };

                hasher
                    .hash_entry(&data, &context)
                    .unwrap_or_else(|_| crate::hash::HashOutput::zero())
            },
        }
    }
    /// add tag to entry
    pub fn add_tag(&mut self, tag: String) {
        if !self.metadata.tags.contains(&tag) {
            self.metadata.tags.push(tag);
        }
    }

    /// remove tag from entry
    pub fn remove_tag(&mut self, tag: &str) {
        self.metadata.tags.retain(|t| t != tag);
    }

    /// set property on entry
    pub fn set_property(&mut self, key: String, value: String) {
        self.metadata.properties.insert(key, value);
    }

    /// get property from entry
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.properties.get(key)
    }

    /// remove property from entry
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.metadata.properties.remove(key)
    }

    /// check if entry has a previous version
    pub fn has_previous_version(&self) -> bool {
        self.metadata.previous_id.is_some()
    }

    /// check if entry has specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.metadata.tags.contains(&tag.to_string())
    }

    /// get entry size in bytes
    pub fn size(&self) -> u64 {
        self.metadata.size
    }

    /// set content type
    pub fn set_content_type(&mut self, content_type: Option<String>) {
        self.metadata.content_type = content_type;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_entry_creation() {
        let data = b"test data".to_vec();
        let message = Some("Test entry".to_string());

        let entry = LedgerEntry::new(data.clone(), message.clone());

        assert_eq!(entry.data, data);
        assert_eq!(entry.metadata.message, message);
        assert_eq!(entry.version, 1);
        assert_eq!(entry.metadata.size, data.len() as u64);
        assert!(!entry.has_previous_version());
    }

    #[test]
    fn test_ledger_entry_versioning() {
        let data1 = b"initial data".to_vec();
        let entry1 = LedgerEntry::new(data1, Some("Initial".to_string()));

        let data2 = b"updated data".to_vec();
        let entry2 = LedgerEntry::new_version(&entry1, data2.clone(), Some("Updated".to_string()));

        assert_eq!(entry2.data, data2);
        assert_eq!(entry2.version, 2);
        assert_eq!(entry2.metadata.previous_id, Some(entry1.id));
        assert!(entry2.has_previous_version());
    }

    #[test]
    fn test_entry_tags() {
        let mut entry = LedgerEntry::new(b"test".to_vec(), None);

        entry.add_tag("important".to_string());
        assert!(entry.has_tag("important"));
        assert_eq!(entry.metadata.tags.len(), 1);

        // adding same tag should not duplicate
        entry.add_tag("important".to_string());
        assert_eq!(entry.metadata.tags.len(), 1);

        entry.remove_tag("important");
        assert!(!entry.has_tag("important"));
        assert_eq!(entry.metadata.tags.len(), 0);
    }

    #[test]
    fn test_entry_properties() {
        let mut entry = LedgerEntry::new(b"test".to_vec(), None);

        entry.set_property("key1".to_string(), "value1".to_string());
        assert_eq!(entry.get_property("key1"), Some(&"value1".to_string()));

        let removed = entry.remove_property("key1");
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(entry.get_property("key1"), None);
    }

    #[test]
    fn test_entry_content_type() {
        let mut entry = LedgerEntry::new(b"test".to_vec(), None);

        entry.set_content_type(Some("text/plain".to_string()));
        assert_eq!(entry.metadata.content_type, Some("text/plain".to_string()));

        entry.set_content_type(None);
        assert_eq!(entry.metadata.content_type, None);
    }

    #[test]
    fn test_versioning_preserves_metadata() {
        let mut entry1 = LedgerEntry::new(b"data1".to_vec(), Some("Initial".to_string()));
        entry1.add_tag("important".to_string());
        entry1.set_property("author".to_string(), "alice".to_string());
        entry1.set_content_type(Some("text/plain".to_string()));

        let entry2 =
            LedgerEntry::new_version(&entry1, b"data2".to_vec(), Some("Updated".to_string()));

        // tags, properties, and content type should be preserved
        assert!(entry2.has_tag("important"));
        assert_eq!(entry2.get_property("author"), Some(&"alice".to_string()));
        assert_eq!(entry2.metadata.content_type, Some("text/plain".to_string()));

        // but message should be updated
        assert_eq!(entry2.metadata.message, Some("Updated".to_string()));
    }
}
