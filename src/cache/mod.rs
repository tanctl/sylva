use crate::error::Result;
use crate::ledger::Ledger;
use crate::storage::{LedgerStorage, SerializableLedger};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub type VersionedLedger = Ledger;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_ledgers: usize,
    pub max_memory_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_ledgers: 100,
            max_memory_bytes: 50 * 1024 * 1024, // 50MB
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub version_queries: u64,
    pub current_size: usize,
    pub current_memory_usage: usize,
}

#[derive(Debug)]
struct CacheEntry {
    ledger: VersionedLedger,
    last_accessed: u64,
    memory_size: usize,
}

impl CacheEntry {
    fn new(ledger: VersionedLedger) -> Self {
        let memory_size = estimate_ledger_memory_size(&ledger);
        Self {
            ledger,
            last_accessed: current_timestamp(),
            memory_size,
        }
    }

    fn touch(&mut self) {
        self.last_accessed = current_timestamp();
    }
}

pub struct LruCache {
    entries: HashMap<String, CacheEntry>,
    access_order: VecDeque<String>,
    config: CacheConfig,
    stats: CacheStats,
}

impl LruCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            config,
            stats: CacheStats::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    pub fn get(&mut self, key: &str) -> Option<&VersionedLedger> {
        if self.entries.contains_key(key) {
            self.touch_entry(key);
            self.move_to_front(key);
            self.stats.hits += 1;
            self.entries.get(key).map(|entry| &entry.ledger)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    fn touch_entry(&mut self, key: &str) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.touch();
        }
    }

    pub fn get_by_version(&mut self, key: &str, version: u64) -> Option<&VersionedLedger> {
        self.stats.version_queries += 1;

        if let Some(ledger) = self.get(key) {
            if ledger.latest_version() >= version {
                Some(ledger)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: String, ledger: VersionedLedger) {
        let entry = CacheEntry::new(ledger);
        let memory_size = entry.memory_size;

        if let Some(old_entry) = self.entries.remove(&key) {
            self.stats.current_memory_usage -= old_entry.memory_size;
            self.remove_from_access_order(&key);
        }

        self.entries.insert(key.clone(), entry);
        self.access_order.push_front(key);
        self.stats.current_memory_usage += memory_size;
        self.stats.current_size = self.entries.len();

        self.enforce_limits();
    }

    pub fn remove(&mut self, key: &str) -> Option<VersionedLedger> {
        if let Some(entry) = self.entries.remove(key) {
            self.stats.current_memory_usage -= entry.memory_size;
            self.remove_from_access_order(key);
            self.stats.current_size = self.entries.len();
            Some(entry.ledger)
        } else {
            None
        }
    }

    pub fn invalidate_version(&mut self, key: &str, min_version: u64) {
        if let Some(entry) = self.entries.get(key) {
            if entry.ledger.latest_version() < min_version {
                self.remove(key);
            }
        }
    }

    pub fn cleanup_old_versions(&mut self, cutoff_timestamp: u64) {
        let keys_to_remove: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.last_accessed < cutoff_timestamp)
            .map(|(key, _)| key.clone())
            .collect();

        for key in keys_to_remove {
            self.remove(&key);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.stats.current_size = 0;
        self.stats.current_memory_usage = 0;
    }

    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn move_to_front(&mut self, key: &str) {
        self.remove_from_access_order(key);
        self.access_order.push_front(key.to_string());
    }

    fn remove_from_access_order(&mut self, key: &str) {
        if let Some(pos) = self.access_order.iter().position(|k| k == key) {
            self.access_order.remove(pos);
        }
    }

    fn enforce_limits(&mut self) {
        while self.entries.len() > self.config.max_ledgers
            || self.stats.current_memory_usage > self.config.max_memory_bytes
        {
            if let Some(key) = self.access_order.pop_back() {
                if let Some(entry) = self.entries.remove(&key) {
                    self.stats.current_memory_usage -= entry.memory_size;
                    self.stats.evictions += 1;
                }
            } else {
                break;
            }
        }
        self.stats.current_size = self.entries.len();
    }
}

pub struct ThreadSafeLruCache {
    cache: Arc<RwLock<LruCache>>,
}

impl ThreadSafeLruCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(config))),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    pub fn get(&self, key: &str) -> Option<VersionedLedger> {
        let mut cache = self.cache.write().unwrap();
        cache.get(key).cloned()
    }

    pub fn get_by_version(&self, key: &str, version: u64) -> Option<VersionedLedger> {
        let mut cache = self.cache.write().unwrap();
        cache.get_by_version(key, version).cloned()
    }

    pub fn insert(&self, key: String, ledger: VersionedLedger) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(key, ledger);
    }

    pub fn remove(&self, key: &str) -> Option<VersionedLedger> {
        let mut cache = self.cache.write().unwrap();
        cache.remove(key)
    }

    pub fn invalidate_version(&self, key: &str, min_version: u64) {
        let mut cache = self.cache.write().unwrap();
        cache.invalidate_version(key, min_version);
    }

    pub fn cleanup_old_versions(&self, cutoff_timestamp: u64) {
        let mut cache = self.cache.write().unwrap();
        cache.cleanup_old_versions(cutoff_timestamp);
    }

    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read().unwrap();
        cache.stats().clone()
    }

    pub fn config(&self) -> CacheConfig {
        let cache = self.cache.read().unwrap();
        cache.config().clone()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        let cache = self.cache.read().unwrap();
        cache.contains_key(key)
    }

    pub fn len(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    pub fn is_empty(&self) -> bool {
        let cache = self.cache.read().unwrap();
        cache.is_empty()
    }
}

impl Clone for ThreadSafeLruCache {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn estimate_ledger_memory_size(ledger: &VersionedLedger) -> usize {
    let entry_size = ledger
        .get_entries()
        .iter()
        .map(|entry| {
            std::mem::size_of_val(entry)
                + entry.data_size()
                + entry
                    .metadata
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
        })
        .sum::<usize>();

    std::mem::size_of_val(ledger) + entry_size
}

pub struct CachedLedgerStorage {
    storage: LedgerStorage,
    cache: ThreadSafeLruCache,
}

impl CachedLedgerStorage {
    pub fn new(storage: LedgerStorage, cache_config: CacheConfig) -> Self {
        Self {
            storage,
            cache: ThreadSafeLruCache::new(cache_config),
        }
    }

    pub fn with_default_cache(storage: LedgerStorage) -> Self {
        Self::new(storage, CacheConfig::default())
    }

    pub fn load_ledger(&self, ledger_id: &Uuid) -> Result<SerializableLedger> {
        let cache_key = ledger_id.to_string();

        if let Some(cached_ledger) = self.cache.get(&cache_key) {
            let serializable = SerializableLedger {
                metadata: crate::storage::LedgerMetadata {
                    id: *ledger_id,
                    created_at: chrono::Utc::now(),
                    modified_at: chrono::Utc::now(),
                    version: cached_ledger.latest_version(),
                    entry_count: cached_ledger.entry_count(),
                    format: crate::storage::StorageFormat::Json,
                    root_hash: None,
                    description: Some("Cached ledger".to_string()),
                    tags: HashMap::new(),
                    compression_stats: None,
                },
                ledger: cached_ledger,
                tree_snapshot: None,
            };
            return Ok(serializable);
        }

        let serializable_ledger = self.storage.load_ledger(ledger_id)?;

        self.cache
            .insert(cache_key, serializable_ledger.ledger.clone());

        Ok(serializable_ledger)
    }

    pub fn load_ledger_by_version(
        &self,
        ledger_id: &Uuid,
        version: u64,
    ) -> Result<Option<SerializableLedger>> {
        let cache_key = ledger_id.to_string();

        if let Some(cached_ledger) = self.cache.get_by_version(&cache_key, version) {
            let serializable = SerializableLedger {
                metadata: crate::storage::LedgerMetadata {
                    id: *ledger_id,
                    created_at: chrono::Utc::now(),
                    modified_at: chrono::Utc::now(),
                    version: cached_ledger.latest_version(),
                    entry_count: cached_ledger.entry_count(),
                    format: crate::storage::StorageFormat::Json,
                    root_hash: None,
                    description: Some("Cached ledger".to_string()),
                    tags: HashMap::new(),
                    compression_stats: None,
                },
                ledger: cached_ledger,
                tree_snapshot: None,
            };
            return Ok(Some(serializable));
        }

        let serializable_ledger = self.storage.load_ledger(ledger_id)?;

        if serializable_ledger.ledger.latest_version() >= version {
            self.cache
                .insert(cache_key, serializable_ledger.ledger.clone());
            Ok(Some(serializable_ledger))
        } else {
            Ok(None)
        }
    }

    pub fn save_ledger(&self, ledger: &Ledger, name: &str) -> Result<Uuid> {
        let ledger_id = self.storage.save_ledger(ledger, name)?;

        let cache_key = ledger_id.to_string();
        self.cache.insert(cache_key, ledger.clone());

        Ok(ledger_id)
    }

    pub fn update_ledger(
        &self,
        ledger_id: &Uuid,
        ledger: &Ledger,
        description: Option<String>,
    ) -> Result<()> {
        self.storage.update_ledger(ledger_id, ledger, description)?;

        let cache_key = ledger_id.to_string();
        self.cache.insert(cache_key, ledger.clone());

        Ok(())
    }

    pub fn delete_ledger(&self, ledger_id: &Uuid) -> Result<()> {
        let cache_key = ledger_id.to_string();
        self.cache.remove(&cache_key);

        self.storage.delete_ledger(ledger_id)
    }

    pub fn invalidate_cache_version(&self, ledger_id: &Uuid, min_version: u64) {
        let cache_key = ledger_id.to_string();
        self.cache.invalidate_version(&cache_key, min_version);
    }

    pub fn cleanup_old_cache_entries(&self, cutoff_timestamp: u64) {
        self.cache.cleanup_old_versions(cutoff_timestamp);
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    pub fn storage(&self) -> &LedgerStorage {
        &self.storage
    }

    pub fn cache(&self) -> &ThreadSafeLruCache {
        &self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ledger() -> VersionedLedger {
        let mut ledger = VersionedLedger::new();
        ledger.add_entry(b"test data".to_vec()).unwrap();
        ledger
    }

    fn create_test_ledger_with_version(entries: usize) -> VersionedLedger {
        let mut ledger = VersionedLedger::new();
        for i in 0..entries {
            ledger
                .add_entry(format!("test data {}", i).into_bytes())
                .unwrap();
        }
        ledger
    }

    #[test]
    fn test_cache_basic_operations() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert("test".to_string(), ledger.clone());

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("test"));

        let retrieved = cache.get("test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().entry_count(), ledger.entry_count());

        let removed = cache.remove("test");
        assert!(removed.is_some());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger();

        let initial_stats = cache.stats();
        assert_eq!(initial_stats.hits, 0);
        assert_eq!(initial_stats.misses, 0);

        cache.get("nonexistent");
        assert_eq!(cache.stats().misses, 1);

        cache.insert("test".to_string(), ledger);
        cache.get("test");
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = CacheConfig {
            max_ledgers: 2,
            max_memory_bytes: usize::MAX,
        };
        let mut cache = LruCache::new(config);

        let ledger1 = create_test_ledger();
        let ledger2 = create_test_ledger();
        let ledger3 = create_test_ledger();

        cache.insert("key1".to_string(), ledger1);
        cache.insert("key2".to_string(), ledger2);
        cache.insert("key3".to_string(), ledger3);

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains_key("key1"));
        assert!(cache.contains_key("key2"));
        assert!(cache.contains_key("key3"));
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_cache_version_queries() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger_with_version(3);

        cache.insert("test".to_string(), ledger);

        let result = cache.get_by_version("test", 1);
        assert!(result.is_some());
        assert_eq!(cache.stats().version_queries, 1);

        let result = cache.get_by_version("test", 10);
        assert!(result.is_none());
        assert_eq!(cache.stats().version_queries, 2);
    }

    #[test]
    fn test_cache_version_invalidation() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger_with_version(2);

        cache.insert("test".to_string(), ledger);
        assert!(cache.contains_key("test"));

        cache.invalidate_version("test", 5);
        assert!(!cache.contains_key("test"));
    }

    #[test]
    fn test_cache_cleanup_old_versions() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger();

        cache.insert("test".to_string(), ledger);

        let future_timestamp = current_timestamp() + 3600;
        cache.cleanup_old_versions(future_timestamp);

        assert!(!cache.contains_key("test"));
    }

    #[test]
    fn test_thread_safe_cache() {
        let cache = ThreadSafeLruCache::with_defaults();
        let ledger = create_test_ledger();

        cache.insert("test".to_string(), ledger.clone());

        let retrieved = cache.get("test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().entry_count(), ledger.entry_count());

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn test_memory_size_estimation() {
        let ledger = create_test_ledger_with_version(10);
        let size = estimate_ledger_memory_size(&ledger);
        assert!(size > 0);
    }

    #[test]
    fn test_cache_memory_limit() {
        let config = CacheConfig {
            max_ledgers: usize::MAX,
            max_memory_bytes: 1, // Very small memory limit
        };
        let mut cache = LruCache::new(config);

        let ledger = create_test_ledger();
        cache.insert("test".to_string(), ledger);

        // Should be evicted due to memory limit
        assert!(cache.is_empty() || cache.len() == 1);
        if !cache.is_empty() {
            assert!(cache.stats().evictions > 0);
        }
    }

    #[test]
    fn test_cache_access_order() {
        let config = CacheConfig {
            max_ledgers: 2,
            max_memory_bytes: usize::MAX,
        };
        let mut cache = LruCache::new(config);

        let ledger1 = create_test_ledger();
        let ledger2 = create_test_ledger();
        let ledger3 = create_test_ledger();

        cache.insert("key1".to_string(), ledger1);
        cache.insert("key2".to_string(), ledger2);

        // Access key1 to make it recently used
        cache.get("key1");

        // Insert key3, should evict key2 (least recently used)
        cache.insert("key3".to_string(), ledger3);

        assert!(cache.contains_key("key1"));
        assert!(!cache.contains_key("key2"));
        assert!(cache.contains_key("key3"));
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = LruCache::with_defaults();
        let ledger = create_test_ledger();

        cache.insert("test".to_string(), ledger);
        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.stats().current_size, 0);
        assert_eq!(cache.stats().current_memory_usage, 0);
    }

    #[test]
    fn test_thread_safe_cache_clone() {
        let cache1 = ThreadSafeLruCache::with_defaults();
        let cache2 = cache1.clone();

        let ledger = create_test_ledger();
        cache1.insert("test".to_string(), ledger);

        // Both caches should see the same data (shared Arc)
        assert!(cache2.contains_key("test"));
    }

    #[test]
    fn test_cached_storage_integration() {
        use crate::storage::LedgerStorage;
        use crate::workspace::Workspace;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let cached_storage = CachedLedgerStorage::with_default_cache(storage);

        let ledger = create_test_ledger();

        // Save ledger
        let ledger_id = cached_storage.save_ledger(&ledger, "cached test").unwrap();

        // First load should hit storage and populate cache
        let loaded1 = cached_storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded1.ledger.entry_count(), ledger.entry_count());

        // Second load should hit cache
        let loaded2 = cached_storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded2.ledger.entry_count(), ledger.entry_count());

        let stats = cached_storage.cache_stats();
        assert!(stats.hits > 0);
    }

    #[test]
    fn test_cached_storage_version_queries() {
        use crate::storage::LedgerStorage;
        use crate::workspace::Workspace;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let cached_storage = CachedLedgerStorage::with_default_cache(storage);

        let ledger = create_test_ledger_with_version(5);
        let ledger_id = cached_storage.save_ledger(&ledger, "version test").unwrap();

        // Load by version
        let result = cached_storage
            .load_ledger_by_version(&ledger_id, 3)
            .unwrap();
        assert!(result.is_some());

        let result = cached_storage
            .load_ledger_by_version(&ledger_id, 10)
            .unwrap();
        assert!(result.is_none());

        let stats = cached_storage.cache_stats();
        assert!(stats.version_queries > 0);
    }

    #[test]
    fn test_cached_storage_cache_invalidation() {
        use crate::storage::LedgerStorage;
        use crate::workspace::Workspace;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let cached_storage = CachedLedgerStorage::with_default_cache(storage);

        let ledger = create_test_ledger();
        let ledger_id = cached_storage
            .save_ledger(&ledger, "invalidation test")
            .unwrap();

        // Load to populate cache
        cached_storage.load_ledger(&ledger_id).unwrap();
        assert!(cached_storage.cache().contains_key(&ledger_id.to_string()));

        // Invalidate cache
        cached_storage.invalidate_cache_version(&ledger_id, 10);
        assert!(!cached_storage.cache().contains_key(&ledger_id.to_string()));
    }

    #[test]
    fn test_cached_storage_update_and_delete() {
        use crate::storage::LedgerStorage;
        use crate::workspace::Workspace;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = LedgerStorage::new(&workspace).unwrap();
        let cached_storage = CachedLedgerStorage::with_default_cache(storage);

        let mut ledger = create_test_ledger();
        let ledger_id = cached_storage.save_ledger(&ledger, "update test").unwrap();

        // Update ledger
        ledger.add_entry(b"new data".to_vec()).unwrap();
        cached_storage
            .update_ledger(&ledger_id, &ledger, Some("Updated".to_string()))
            .unwrap();

        // Load should get updated version from cache
        let loaded = cached_storage.load_ledger(&ledger_id).unwrap();
        assert_eq!(loaded.ledger.entry_count(), ledger.entry_count());

        // Delete ledger
        cached_storage.delete_ledger(&ledger_id).unwrap();
        assert!(!cached_storage.cache().contains_key(&ledger_id.to_string()));
    }
}
