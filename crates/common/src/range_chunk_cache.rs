use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;

pub const RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES: usize = 1024 * 1024;
pub const RANGE_CHUNK_CACHE_MAX_CHUNKS: usize = 16;

/// LRU cache with O(1) get/insert/remove, backed by `lru::LruCache`.
///
/// `max_chunks == 0` disables caching entirely (`lru::LruCache` requires a
/// non-zero capacity), which matches the previous linear implementation's
/// behavior of never retaining entries in that case.
#[derive(Debug)]
pub struct RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    inner: Option<LruCache<K, Arc<V>>>,
}

impl<K, V> Default for RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new(RANGE_CHUNK_CACHE_MAX_CHUNKS)
    }
}

impl<K, V> RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    pub fn new(max_chunks: usize) -> Self {
        Self {
            inner: NonZeroUsize::new(max_chunks).map(LruCache::new),
        }
    }

    pub fn get(&mut self, key: &K) -> Option<Arc<V>> {
        self.inner.as_mut()?.get(key).cloned()
    }

    pub fn insert(&mut self, key: K, value: V) -> Arc<V> {
        let value = Arc::new(value);
        if let Some(inner) = self.inner.as_mut() {
            inner.put(key, Arc::clone(&value));
        }
        value
    }

    pub fn remove(&mut self, key: &K) -> Option<Arc<V>> {
        self.inner.as_mut()?.pop(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_least_recently_used_entry() {
        let mut cache = RangeChunkCache::<String, usize>::new(2);

        cache.insert("alpha".to_string(), 1);
        cache.insert("beta".to_string(), 2);
        let _ = cache.get(&"alpha".to_string());
        cache.insert("gamma".to_string(), 3);

        assert_eq!(cache.get(&"alpha".to_string()).as_deref(), Some(&1));
        assert_eq!(cache.get(&"beta".to_string()).as_deref(), None);
        assert_eq!(cache.get(&"gamma".to_string()).as_deref(), Some(&3));
    }

    #[test]
    fn remove_evicts_entry_and_its_access_order() {
        let mut cache = RangeChunkCache::<String, usize>::new(2);

        cache.insert("alpha".to_string(), 1);
        let removed = cache.remove(&"alpha".to_string());

        assert_eq!(removed.as_deref(), Some(&1));
        assert_eq!(cache.get(&"alpha".to_string()).as_deref(), None);

        cache.insert("beta".to_string(), 2);
        cache.insert("gamma".to_string(), 3);
        cache.insert("delta".to_string(), 4);

        assert_eq!(cache.get(&"beta".to_string()).as_deref(), None);
        assert_eq!(cache.get(&"gamma".to_string()).as_deref(), Some(&3));
        assert_eq!(cache.get(&"delta".to_string()).as_deref(), Some(&4));
    }

    #[test]
    fn zero_capacity_cache_does_not_retain_entries() {
        let mut cache = RangeChunkCache::<String, usize>::new(0);

        let inserted = cache.insert("alpha".to_string(), 1);

        assert_eq!(inserted.as_ref(), &1);
        assert_eq!(cache.get(&"alpha".to_string()).as_deref(), None);
    }
}
