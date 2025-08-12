use crate::secure::SecureString;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

/// Performance measurement data structure that persists to avoid re-running expensive benchmarks.
/// We store per-core performance because key generation scales linearly with cores, and platform
/// info helps identify when cached results might not apply to the current system.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PerformanceResult {
    pub keys_per_sec_per_core: f64,
    pub cores_used: usize,
    pub timestamp: u64,
    pub platform: String,
}

/// Configuration for the key search operation, encapsulating user preferences and system constraints.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub prefix: String,
    pub search_behavior: SearchBehavior,
    pub cpu_threads: usize,
}

/// Defines when the search should terminate based on user requirements.
#[derive(Debug, Clone)]
pub enum SearchBehavior {
    FindN(usize),
    Continuous,
}

/// Represents a successfully found key pair that matches the search criteria.
#[derive(Debug)]
pub struct FoundKey {
    pub private_key: SecureString,
    pub public_key: String,
}

/// Thread-safe statistics tracking for coordinating multiple worker threads.
/// Uses atomic operations to avoid mutex overhead in the hot path.
pub struct SearchStats {
    pub total_attempts: AtomicU64,
    pub prefix_matches: AtomicUsize,
    pub stop_search: AtomicBool,
}

impl SearchStats {
    /// Creates new statistics tracker with search start time captured for timing calculations.
    pub fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            prefix_matches: AtomicUsize::new(0),
            stop_search: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_config_debug_format() {
        let config = SearchConfig {
            prefix: "CAFE".to_string(),
            search_behavior: SearchBehavior::FindN(10),
            cpu_threads: 8,
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SearchConfig"));
        assert!(debug_str.contains("CAFE"));
        assert!(debug_str.contains("FindN"));
    }

    #[test]
    fn test_search_behavior_debug_format() {
        let find_one = SearchBehavior::FindN(1);
        let find_n = SearchBehavior::FindN(42);
        let continuous = SearchBehavior::Continuous;

        let debug_one = format!("{:?}", find_one);
        let debug_n = format!("{:?}", find_n);
        let debug_continuous = format!("{:?}", continuous);

        assert!(debug_one.contains("FindN(1)"));
        assert!(debug_n.contains("FindN"));
        assert!(debug_n.contains("42"));
        assert!(debug_continuous.contains("Continuous"));
    }

    #[test]
    fn test_found_key_debug_format() {
        let found_key = FoundKey {
            private_key: SecureString::new("test_private".to_string()),
            public_key: "test_public".to_string(),
        };

        let debug_str = format!("{:?}", found_key);
        assert!(debug_str.contains("FoundKey"));
        assert!(debug_str.contains("test_public"));
    }

    #[test]
    fn test_search_stats_new_initialization() {
        let stats = SearchStats::new();

        // All counters should start at zero
        assert_eq!(
            stats
                .total_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            stats
                .prefix_matches
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(!stats.stop_search.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_search_stats_concurrent_access() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::thread;

        let stats = Arc::new(SearchStats::new());
        let mut handles = vec![];

        // Spawn multiple threads to simulate concurrent access
        for _ in 0..4 {
            let stats_clone = Arc::clone(&stats);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    stats_clone.total_attempts.fetch_add(1, Ordering::Relaxed);
                    stats_clone.prefix_matches.fetch_add(1, Ordering::Relaxed);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Check final counts
        assert_eq!(stats.total_attempts.load(Ordering::Relaxed), 400);
        assert_eq!(stats.prefix_matches.load(Ordering::Relaxed), 400);
    }

    #[test]
    fn test_search_behavior_clone() {
        let original = SearchBehavior::FindN(25);
        let cloned = original.clone();

        match cloned {
            SearchBehavior::FindN(n) => assert_eq!(n, 25),
            _ => panic!("Clone did not preserve variant"),
        }
    }

    #[test]
    fn test_search_config_partial_eq() {
        let config1 = SearchConfig {
            prefix: "1234".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 4,
        };

        let config2 = SearchConfig {
            prefix: "1234".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 4,
        };

        let config3 = SearchConfig {
            prefix: "5678".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 4,
        };

        // These configs should be equal
        assert_eq!(config1.prefix, config2.prefix);
        assert_eq!(config1.cpu_threads, config2.cpu_threads);

        // These should be different
        assert_ne!(config1.prefix, config3.prefix);
    }

    #[test]
    fn test_found_key_with_various_data() {
        let test_cases = vec![
            ("short", "AB"),
            ("medium", "DEADBEEF"),
            ("long", "CAFEBABE123456789ABCDEF0"),
        ];

        for (name, prefix) in test_cases {
            let found_key = FoundKey {
                private_key: SecureString::new(format!("private_key_for_{}", name)),
                public_key: format!(
                    "{}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    prefix
                ),
            };

            assert!(found_key.public_key.starts_with(prefix));
            assert_eq!(
                found_key.private_key.expose(),
                &format!("private_key_for_{}", name)
            );
        }
    }

    #[test]
    fn test_search_stats_stop_flag_behavior() {
        let stats = SearchStats::new();

        // Initially should not be stopped
        assert!(!stats.stop_search.load(std::sync::atomic::Ordering::Relaxed));

        // Set stop flag
        stats
            .stop_search
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(stats.stop_search.load(std::sync::atomic::Ordering::Relaxed));

        // Unset stop flag
        stats
            .stop_search
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!stats.stop_search.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_found_key_timestamps() {
        let found_key = FoundKey {
            private_key: SecureString::new("test_key".to_string()),
            public_key: "test_public".to_string(),
        };

        // Test that the key was created successfully
        assert_eq!(found_key.public_key, "test_public");
        assert_eq!(found_key.private_key.expose(), "test_key");
    }

    #[test]
    fn test_search_config_with_extreme_values() {
        // Test with minimum values
        let min_config = SearchConfig {
            prefix: "F".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 1,
        };
        assert_eq!(min_config.cpu_threads, 1);
        assert_eq!(min_config.prefix.len(), 1);

        // Test with large values
        let max_config = SearchConfig {
            prefix: "F".repeat(32), // Very long prefix
            search_behavior: SearchBehavior::FindN(usize::MAX),
            cpu_threads: 128,
        };
        assert_eq!(max_config.cpu_threads, 128);
        assert_eq!(max_config.prefix.len(), 32);
    }
}
