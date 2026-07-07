use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

pub const RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES: usize = 1024 * 1024;
pub const RANGE_CHUNK_CACHE_MAX_CHUNKS: usize = 16;

/// A cache entry plus its links in the intrusive recency list, stored in a
/// `Vec`-backed arena so the list can be maintained without `unsafe` pointers.
struct Slot<K, V> {
    key: K,
    value: Arc<V>,
    prev: Option<usize>,
    next: Option<usize>,
}

/// LRU cache with O(1) `get`/`insert`/`remove`, including recency tracking.
///
/// Recency order is an intrusive doubly-linked list threaded through `slots`
/// via index-based links (rather than a `VecDeque` scanned with `retain`),
/// so a hit or insert no longer costs O(capacity).
pub struct RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    slots: Vec<Option<Slot<K, V>>>,
    free_slots: Vec<usize>,
    index: HashMap<K, usize>,
    most_recent: Option<usize>,
    least_recent: Option<usize>,
    max_chunks: usize,
}

impl<K, V> std::fmt::Debug for RangeChunkCache<K, V>
where
    K: Clone + Eq + Hash,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeChunkCache")
            .field("len", &self.len())
            .field("capacity", &self.max_chunks)
            .finish()
    }
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
            slots: Vec::new(),
            free_slots: Vec::new(),
            index: HashMap::new(),
            most_recent: None,
            least_recent: None,
            max_chunks,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<Arc<V>> {
        let idx = *self.index.get(key)?;
        self.move_to_front(idx);
        Some(Arc::clone(&self.slots[idx].as_ref().unwrap().value))
    }

    pub fn insert(&mut self, key: K, value: V) -> Arc<V> {
        let value = Arc::new(value);

        if let Some(&idx) = self.index.get(&key) {
            self.slots[idx].as_mut().unwrap().value = Arc::clone(&value);
            self.move_to_front(idx);
            return value;
        }

        let idx = self.alloc_slot(key.clone(), Arc::clone(&value));
        self.index.insert(key, idx);
        self.push_front(idx);

        while self.index.len() > self.max_chunks {
            self.evict_least_recent();
        }

        value
    }

    pub fn remove(&mut self, key: &K) -> Option<Arc<V>> {
        let idx = self.index.remove(key)?;
        Some(self.detach(idx).value)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_chunks
    }

    fn alloc_slot(&mut self, key: K, value: Arc<V>) -> usize {
        let slot = Some(Slot {
            key,
            value,
            prev: None,
            next: None,
        });
        if let Some(idx) = self.free_slots.pop() {
            self.slots[idx] = slot;
            idx
        } else {
            self.slots.push(slot);
            self.slots.len() - 1
        }
    }

    /// Removes `idx` from the recency list and its arena slot, but not from `index`.
    fn detach(&mut self, idx: usize) -> Slot<K, V> {
        self.unlink(idx);
        let slot = self.slots[idx].take().unwrap();
        self.free_slots.push(idx);
        slot
    }

    fn evict_least_recent(&mut self) {
        if let Some(idx) = self.least_recent {
            let slot = self.detach(idx);
            self.index.remove(&slot.key);
        }
    }

    fn unlink(&mut self, idx: usize) {
        let (prev, next) = {
            let slot = self.slots[idx].as_ref().unwrap();
            (slot.prev, slot.next)
        };
        match prev {
            Some(p) => self.slots[p].as_mut().unwrap().next = next,
            None => self.most_recent = next,
        }
        match next {
            Some(n) => self.slots[n].as_mut().unwrap().prev = prev,
            None => self.least_recent = prev,
        }
    }

    fn push_front(&mut self, idx: usize) {
        let old_head = self.most_recent;
        {
            let slot = self.slots[idx].as_mut().unwrap();
            slot.prev = None;
            slot.next = old_head;
        }
        if let Some(head) = old_head {
            self.slots[head].as_mut().unwrap().prev = Some(idx);
        }
        self.most_recent = Some(idx);
        if self.least_recent.is_none() {
            self.least_recent = Some(idx);
        }
    }

    fn move_to_front(&mut self, idx: usize) {
        if self.most_recent == Some(idx) {
            return;
        }
        self.unlink(idx);
        self.push_front(idx);
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

    #[test]
    fn reinserting_existing_key_updates_value_and_recency() {
        let mut cache = RangeChunkCache::<String, usize>::new(2);

        cache.insert("alpha".to_string(), 1);
        cache.insert("beta".to_string(), 2);
        cache.insert("alpha".to_string(), 10);
        cache.insert("gamma".to_string(), 3);

        assert_eq!(cache.get(&"alpha".to_string()).as_deref(), Some(&10));
        assert_eq!(cache.get(&"beta".to_string()).as_deref(), None);
        assert_eq!(cache.get(&"gamma".to_string()).as_deref(), Some(&3));
    }

    #[test]
    fn large_cache_maintains_lru_order_without_quadratic_blowup() {
        let capacity = 10_000;
        let mut cache = RangeChunkCache::<usize, usize>::new(capacity);

        for i in 0..capacity {
            cache.insert(i, i);
        }
        // Touch every entry once so recency order is a known permutation,
        // then insert one more entry: only key `0` (now least-recently-used)
        // should be evicted.
        for i in 0..capacity {
            assert_eq!(cache.get(&i).as_deref(), Some(&i));
        }
        cache.insert(capacity, capacity);

        assert_eq!(cache.len(), capacity);
        assert_eq!(cache.get(&0).as_deref(), None);
        assert_eq!(cache.get(&1).as_deref(), Some(&1));
        assert_eq!(cache.get(&capacity).as_deref(), Some(&capacity));
    }
}
