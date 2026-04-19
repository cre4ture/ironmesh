use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Arc;

pub const RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES: usize = 1024 * 1024;
pub const RANGE_CHUNK_CACHE_MAX_CHUNKS: usize = 16;

#[derive(Debug)]
pub struct RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    chunks: HashMap<K, Arc<V>>,
    access_order: VecDeque<K>,
    max_chunks: usize,
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
            chunks: HashMap::new(),
            access_order: VecDeque::new(),
            max_chunks,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<Arc<V>> {
        let value = self.chunks.get(key).cloned()?;
        self.touch(key);
        Some(value)
    }

    pub fn insert(&mut self, key: K, value: V) -> Arc<V> {
        let value = Arc::new(value);
        self.chunks.insert(key.clone(), Arc::clone(&value));
        self.touch(&key);

        while self.chunks.len() > self.max_chunks {
            let Some(oldest) = self.access_order.pop_front() else {
                break;
            };
            if self.chunks.remove(&oldest).is_some() {
                break;
            }
        }

        value
    }

    fn touch(&mut self, key: &K) {
        self.access_order.retain(|existing| existing != key);
        self.access_order.push_back(key.clone());
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
    fn zero_capacity_cache_does_not_retain_entries() {
        let mut cache = RangeChunkCache::<String, usize>::new(0);

        let inserted = cache.insert("alpha".to_string(), 1);

        assert_eq!(inserted.as_ref(), &1);
        assert_eq!(cache.get(&"alpha".to_string()).as_deref(), None);
    }
}
