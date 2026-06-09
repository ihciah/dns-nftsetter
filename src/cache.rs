use hashlink::LruCache;
use std::time::Instant;

#[cfg(test)]
const MIN_TTL: u32 = 1;
#[cfg(not(test))]
const MIN_TTL: u32 = 60;

const MAX_TTL: u32 = 86400; // 1 day

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub original: String,
    pub expire_at: Instant,
    pub ttl_secs: u32,
}

pub struct CnameCache {
    cache: LruCache<String, CacheEntry>,
}

impl CnameCache {
    pub fn new(capacity: usize) -> Self {
        // Ensure capacity is at least 1 to prevent panics in LruCache
        let cap = if capacity == 0 { 1 } else { capacity };
        Self {
            cache: LruCache::new(cap),
        }
    }

    pub fn insert(&mut self, target: String, original: String, ttl: u32) {
        let target_lower = target.to_lowercase();
        let original_lower = original.to_lowercase();

        // Clamp TTL: min MIN_TTL, max MAX_TTL
        let clamped_ttl = ttl.clamp(MIN_TTL, MAX_TTL);

        let now = Instant::now();
        let expire_at = now + std::time::Duration::from_secs(clamped_ttl as u64);

        // If target already points to this original, update expiration time and TTL
        if let Some(existing) = self.cache.get_mut(&target_lower) {
            if existing.original == original_lower {
                existing.expire_at = expire_at;
                existing.ttl_secs = clamped_ttl;
                return;
            }
        }

        let entry = CacheEntry {
            original: original_lower,
            expire_at,
            ttl_secs: clamped_ttl,
        };

        self.cache.insert(target_lower, entry);
    }

    /// Recursively traces a resolved domain back to the original queried domain.
    /// Updates the LRU cache ordering for accessed entries.
    /// Removes expired entries from the cache and refreshes the expiration of active ones.
    pub fn resolve(&mut self, domain: &str) -> String {
        let mut current = domain.to_lowercase();
        let mut depth = 0;
        const MAX_CNAME_DEPTH: usize = 10;
        let now = Instant::now();

        loop {
            let mut expired = false;
            let next = if let Some(entry) = self.cache.get_mut(&current) {
                if entry.expire_at < now {
                    expired = true;
                    None
                } else {
                    // Refresh expiration
                    entry.expire_at = now + std::time::Duration::from_secs(entry.ttl_secs as u64);
                    Some(entry.original.clone())
                }
            } else {
                None
            };

            if expired {
                self.cache.remove(&current);
            }

            if let Some(original) = next {
                current = original;
                depth += 1;
                if depth >= MAX_CNAME_DEPTH {
                    break;
                }
            } else {
                break;
            }
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cname_resolution() {
        let mut cache = CnameCache::new(5);
        cache.insert("b.com".to_string(), "a.com".to_string(), 120);
        cache.insert("c.com".to_string(), "b.com".to_string(), 120);

        // Recursive resolution
        assert_eq!(cache.resolve("c.com"), "a.com".to_string());
        assert_eq!(cache.resolve("b.com"), "a.com".to_string());
        // Unmapped remains unchanged
        assert_eq!(cache.resolve("d.com"), "d.com".to_string());
    }

    #[test]
    fn test_cname_cache_eviction() {
        let mut cache = CnameCache::new(2);
        cache.insert("b.com".to_string(), "a.com".to_string(), 120);
        cache.insert("c.com".to_string(), "b.com".to_string(), 120);
        // Now capacity is full (2 items: b.com, c.com)
        assert_eq!(cache.resolve("c.com"), "a.com".to_string());
        // At this point, resolve("c.com") accessed:
        // 1. "c.com" (making c.com MRU, b.com LRU)
        // 2. "b.com" (making b.com MRU, c.com LRU)

        // Insert third item. Since c.com is LRU, c.com should be evicted.
        cache.insert("d.com".to_string(), "c.com".to_string(), 120);

        // c.com is evicted, so resolving it returns "c.com" itself
        assert_eq!(cache.resolve("c.com"), "c.com".to_string());
        // d.com traces to c.com. Since c.com is evicted, resolve("d.com") returns "c.com"
        assert_eq!(cache.resolve("d.com"), "c.com".to_string());
        // b.com is still in the cache, so it resolves to a.com
        assert_eq!(cache.resolve("b.com"), "a.com".to_string());
    }

    #[test]
    fn test_cname_loop_prevention() {
        let mut cache = CnameCache::new(2);
        cache.insert("a.com".to_string(), "b.com".to_string(), 120);
        cache.insert("b.com".to_string(), "a.com".to_string(), 120); // Loop!

        // Should not hang, should exit before MAX_CNAME_DEPTH
        let result = cache.resolve("a.com");
        assert!(result == "a.com" || result == "b.com");
    }

    #[test]
    fn test_cname_expiration_and_refresh() {
        let mut cache = CnameCache::new(5);
        // Insert with 1 second TTL (under test, MIN_TTL = 1)
        cache.insert("b.com".to_string(), "a.com".to_string(), 1);

        // Before 1 second, it should resolve successfully
        assert_eq!(cache.resolve("b.com"), "a.com".to_string());

        // Wait for 1.2 seconds to allow expiration
        std::thread::sleep(std::time::Duration::from_millis(1200));

        // After expiration, resolve should return original domain itself (expired mapping is deleted)
        assert_eq!(cache.resolve("b.com"), "b.com".to_string());
    }
}
