//! storage backends

pub mod ledger;

use crate::error::{Result, SylvaError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// trait for storage backends
pub trait Storage: Send + Sync {
    /// store data with key
    fn store(&mut self, key: &str, data: &[u8]) -> Result<()>;
    /// retrieve data by key
    fn retrieve(&self, key: &str) -> Result<Vec<u8>>;
    /// check if key exists
    fn exists(&self, key: &str) -> Result<bool>;
    /// delete data by key
    fn delete(&mut self, key: &str) -> Result<()>;
    /// list all stored keys
    fn list_keys(&self) -> Result<Vec<String>>;
    /// get storage statistics
    fn stats(&self) -> Result<StorageStats>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// storage statistics
pub struct StorageStats {
    /// number of stored entries
    pub entry_count: usize,
    /// total size in bytes
    pub total_size: u64,
    /// available space if known
    pub available_space: Option<u64>,
}

#[derive(Debug, Default)]
/// in-memory storage backend
pub struct MemoryStorage {
    data: HashMap<String, Vec<u8>>,
}

impl MemoryStorage {
    /// create new memory storage
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Storage for MemoryStorage {
    fn store(&mut self, key: &str, data: &[u8]) -> Result<()> {
        self.data.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        self.data
            .get(key)
            .cloned()
            .ok_or_else(|| SylvaError::storage_error(format!("Key not found: {}", key)))
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.data.contains_key(key))
    }

    fn delete(&mut self, key: &str) -> Result<()> {
        if self.data.remove(key).is_some() {
            Ok(())
        } else {
            Err(SylvaError::storage_error(format!("Key not found: {}", key)))
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.data.keys().cloned().collect())
    }

    fn stats(&self) -> Result<StorageStats> {
        let total_size = self.data.values().map(|v| v.len() as u64).sum();
        Ok(StorageStats {
            entry_count: self.data.len(),
            total_size,
            available_space: None,
        })
    }
}

#[derive(Debug)]
/// file-based storage backend
pub struct FileSystemStorage {
    base_path: std::path::PathBuf,
}

impl FileSystemStorage {
    /// create new filesystem storage
    pub fn new(base_path: std::path::PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_path)?;
        Ok(Self { base_path })
    }

    fn key_to_path(&self, key: &str) -> std::path::PathBuf {
        let encoded_key = URL_SAFE_NO_PAD.encode(key.as_bytes());
        self.base_path.join(encoded_key)
    }
}

impl Storage for FileSystemStorage {
    fn store(&mut self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.key_to_path(key);
        std::fs::write(path, data)?;
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.key_to_path(key);
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SylvaError::storage_error(format!("Key not found: {}", key))
            } else {
                SylvaError::from(e)
            }
        })
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    fn delete(&mut self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);
        std::fs::remove_file(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SylvaError::storage_error(format!("Key not found: {}", key))
            } else {
                SylvaError::from(e)
            }
        })
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&self.base_path)?;

        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(filename) = entry.file_name().to_str() {
                    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(filename) {
                        if let Ok(key) = String::from_utf8(decoded) {
                            keys.push(key);
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    fn stats(&self) -> Result<StorageStats> {
        let mut entry_count = 0;
        let mut total_size = 0;

        let entries = std::fs::read_dir(&self.base_path)?;
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                entry_count += 1;
                total_size += entry.metadata()?.len();
            }
        }

        Ok(StorageStats {
            entry_count,
            total_size,
            available_space: None,
        })
    }
}

/// factory for creating storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// create memory storage backend
    pub fn memory() -> Box<dyn Storage> {
        Box::new(MemoryStorage::new())
    }

    /// create filesystem storage backend
    pub fn filesystem(path: std::path::PathBuf) -> Result<Box<dyn Storage>> {
        Ok(Box::new(FileSystemStorage::new(path)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_memory_storage() {
        let mut storage = MemoryStorage::new();
        let key = "test_key";
        let data = b"test_data";

        assert!(!storage.exists(key).unwrap());
        storage.store(key, data).unwrap();
        assert!(storage.exists(key).unwrap());

        let retrieved = storage.retrieve(key).unwrap();
        assert_eq!(retrieved, data);

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys, vec![key.to_string()]);

        storage.delete(key).unwrap();
        assert!(!storage.exists(key).unwrap());
    }

    #[test]
    fn test_filesystem_storage() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let key = "test_key";
        let data = b"test_data";

        assert!(!storage.exists(key).unwrap());
        storage.store(key, data).unwrap();
        assert!(storage.exists(key).unwrap());

        let retrieved = storage.retrieve(key).unwrap();
        assert_eq!(retrieved, data);

        storage.delete(key).unwrap();
        assert!(!storage.exists(key).unwrap());
    }

    #[test]
    fn test_storage_stats() {
        let mut storage = MemoryStorage::new();
        let stats = storage.stats().unwrap();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size, 0);

        storage.store("key1", b"data1").unwrap();
        storage.store("key2", b"data22").unwrap();

        let stats = storage.stats().unwrap();
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.total_size, 11);
    }
}
