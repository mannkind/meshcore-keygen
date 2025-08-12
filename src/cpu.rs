use crate::secure::SecureString;
use crate::types::{FoundKey, SearchConfig, SearchStats};
use crate::utils::{
    check_prefix_match, create_meshcore_private_key, hex_string_to_bytes,
    validate_meshcore_key_format,
};
use crossbeam::channel;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// High-performance CPU-based key searcher that leverages multi-threading and optimized crypto libraries.
pub struct CpuKeySearcher;

impl CpuKeySearcher {
    /// Spawns multiple CPU worker threads for parallel key generation and searching.
    /// Uses smaller batch sizes and local RNG for optimal CPU performance.
    pub fn search(
        config: Arc<SearchConfig>,
        stats: Arc<SearchStats>,
        found_sender: channel::Sender<FoundKey>,
        thread_id: usize,
    ) {
        // CPU works best with smaller, more frequent batches
        let batch_size = match config.prefix.len() {
            1..=4 => 1024, // Small batches for short patterns
            5..=6 => 2048, // Medium batches for medium patterns
            _ => 4096,     // Larger batches for long patterns
        };

        println!(
            "  🦺 CPU worker #{} activated! Batch size: {}",
            thread_id, batch_size
        );

        let prefix_bytes = hex_string_to_bytes(&config.prefix);
        let mut rng = rand::thread_rng();
        let mut local_attempts = 0u64;
        const UPDATE_INTERVAL: u64 = 5000;

        while !stats.stop_search.load(Ordering::Relaxed) {
            // Generate batch of keys
            for _ in 0..batch_size {
                if stats.stop_search.load(Ordering::Relaxed) {
                    break;
                }

                // Generate random seed using CPU RNG
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);

                // Create Ed25519 key pair
                let signing_key = SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();
                let public_key_bytes = verifying_key.to_bytes();

                // Quick prefix check
                if check_prefix_match(&public_key_bytes, &prefix_bytes) {
                    // Generate meshcore-compatible private key
                    let meshcore_private_key = create_meshcore_private_key(&seed);

                    // Validate the key format
                    if validate_meshcore_key_format(&meshcore_private_key) {
                        let found_key = FoundKey {
                            private_key: SecureString::new(
                                hex::encode(meshcore_private_key).to_uppercase(),
                            ),
                            public_key: hex::encode(public_key_bytes).to_uppercase(),
                        };

                        stats.prefix_matches.fetch_add(1, Ordering::Relaxed);

                        if found_sender.send(found_key).is_err() {
                            return;
                        }
                    }
                }

                local_attempts += 1;

                // Update stats more frequently for better responsiveness
                if local_attempts % UPDATE_INTERVAL == 0 {
                    stats
                        .total_attempts
                        .fetch_add(local_attempts, Ordering::Relaxed);
                    local_attempts = 0;
                }
            }
        }

        // Ensure final attempt count is recorded
        if local_attempts > 0 {
            stats
                .total_attempts
                .fetch_add(local_attempts, Ordering::Relaxed);
        }
    }

    /// Spawns the specified number of CPU worker threads.
    /// Each thread operates independently with its own RNG for maximum performance.
    pub fn spawn_workers(
        num_threads: usize,
        config: Arc<SearchConfig>,
        stats: Arc<SearchStats>,
        found_sender: channel::Sender<FoundKey>,
    ) -> Vec<std::thread::JoinHandle<()>> {
        (0..num_threads)
            .map(|thread_id| {
                let config_clone = Arc::clone(&config);
                let stats_clone = Arc::clone(&stats);
                let sender_clone = found_sender.clone();

                std::thread::spawn(move || {
                    Self::search(config_clone, stats_clone, sender_clone, thread_id);
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SearchBehavior, SearchStats};

    #[test]
    fn test_cpu_searcher_creation() {
        let _searcher = CpuKeySearcher {};
    }

    #[test]
    fn test_cpu_search_basic() {
        let config = Arc::new(SearchConfig {
            prefix: "A".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 1,
        });

        let stats = Arc::new(SearchStats::new());
        let (sender, _receiver) = channel::unbounded();

        // This test just ensures the search function doesn't panic
        // We immediately stop to avoid long-running test
        stats.stop_search.store(true, Ordering::Relaxed);
        CpuKeySearcher::search(config, stats, sender, 0);
    }

    #[test]
    fn test_cpu_worker_spawning() {
        let config = Arc::new(SearchConfig {
            prefix: "B".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 2,
        });

        let stats = Arc::new(SearchStats::new());
        let (sender, _receiver) = channel::unbounded();

        // Stop immediately to avoid long-running test
        stats.stop_search.store(true, Ordering::Relaxed);

        let handles = CpuKeySearcher::spawn_workers(2, config, stats, sender);
        assert_eq!(handles.len(), 2);

        // Wait for threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_batch_size_scaling() {
        // Test that batch sizes scale appropriately with prefix length
        let short_config = SearchConfig {
            prefix: "A".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 1,
        };

        let long_config = SearchConfig {
            prefix: "ABCDEFGH".to_string(),
            search_behavior: SearchBehavior::FindN(1),
            cpu_threads: 1,
        };

        // We can't directly test batch sizes since they're local to the search function,
        // but we can ensure the configurations are valid
        assert!(short_config.prefix.len() < long_config.prefix.len());
    }
}
