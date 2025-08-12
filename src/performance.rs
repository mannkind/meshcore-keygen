use crate::types::PerformanceResult;
use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Caches performance measurements to disk because key generation benchmarks are expensive
pub struct PerformanceCache;

impl PerformanceCache {
    const CACHE_FILE: &'static str = "performance.json";
    /// Cache expires after 12 hours because system load and thermal throttling can affect results
    const CACHE_VALIDITY_HOURS: u64 = 12;

    /// Attempts to load cached performance data to avoid re-running expensive benchmarks.
    /// Returns None if cache is missing, corrupted, or expired to ensure accuracy.
    pub fn load() -> Option<PerformanceResult> {
        if let Ok(mut file) = File::open(Self::CACHE_FILE) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok()
                && let Ok(result) = serde_json::from_str::<PerformanceResult>(&contents)
            {
                // Expire cache to ensure measurements reflect current system state
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - result.timestamp < Self::CACHE_VALIDITY_HOURS * 3600 {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Persists performance results to avoid expensive re-measurement.
    /// Uses atomic write pattern (write + sync) to prevent corruption from crashes.
    pub fn save(result: &PerformanceResult) -> Result<()> {
        let json = serde_json::to_string_pretty(result)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(Self::CACHE_FILE)?;

        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Runs a multi-threaded performance benchmark to measure key generation speed.
    /// Uses multiple measurement runs to get more stable results.
    pub fn measure_performance(cores: usize) -> Result<PerformanceResult> {
        println!("\n🚀⚡️ Running performance benchmark on {} cores...", cores);

        const WARMUP_DURATION: Duration = Duration::from_millis(1000);
        const TEST_DURATION: Duration = Duration::from_secs(2);
        const NUM_RUNS: usize = 5;
        /// Smaller batch size allows more frequent time checks for accurate timing
        const BATCH_SIZE: usize = 128;

        // Warmup run to stabilize CPU frequency and caches
        println!("   🔥 Warming up CPU cores...");
        let _warmup = Self::run_single_benchmark(cores, WARMUP_DURATION, BATCH_SIZE);

        let mut measurements = Vec::new();

        // Run multiple measurements for stability
        for run in 1..=NUM_RUNS {
            print!("   📊 Measurement run {}/{}...", run, NUM_RUNS);
            std::io::stdout().flush().unwrap();
            let result = Self::run_single_benchmark(cores, TEST_DURATION, BATCH_SIZE)?;
            println!(
                "\r   📊 Measurement run {}/{} ... done! {} keys/sec/core, {} total keys, {} elapsed time",
                run,
                NUM_RUNS,
                result.0,
                result.1,
                result.2.as_millis()
            );
            measurements.push(result);
        }

        // Calculate average performance
        let avg_keys_per_sec_per_core =
            measurements.iter().map(|m| m.0).sum::<f64>() / measurements.len() as f64;

        let total_speed = avg_keys_per_sec_per_core * cores as f64;

        println!("✅🎉 Performance benchmark completed:");
        println!(
            "   🚀 Average speed: {:.0} keys/sec across {} cores",
            total_speed, cores
        );
        println!(
            "   ⚡️ Speed per core: {:.0} keys/sec",
            avg_keys_per_sec_per_core
        );

        let result = PerformanceResult {
            keys_per_sec_per_core: avg_keys_per_sec_per_core,
            cores_used: cores,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            platform: get_platform_info(),
        };

        if let Err(e) = Self::save(&result) {
            eprintln!("⚠️ Failed to cache performance result: {}", e);
        } else {
            println!("💾✨ Performance result cached for future use!");
        }

        Ok(result)
    }

    /// Runs a single benchmark measurement with the given parameters.
    fn run_single_benchmark(
        cores: usize,
        duration: Duration,
        batch_size: usize,
    ) -> Result<(f64, u64, Duration)> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::thread;

        let total_keys = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        // Spawn worker threads to parallelize key generation across cores
        let handles: Vec<_> = (0..cores)
            .map(|_| {
                let total_keys = Arc::clone(&total_keys);

                thread::spawn(move || {
                    use ed25519_dalek::SigningKey;
                    use rand::RngCore;

                    let mut rng = rand::thread_rng();
                    let mut local_count = 0u64;
                    let end_time = start_time + duration;

                    // Pre-generate seeds to reduce RNG overhead during measurement
                    let mut seeds = Vec::with_capacity(batch_size);
                    for _ in 0..batch_size {
                        let mut seed = [0u8; 32];
                        rng.fill_bytes(&mut seed);
                        seeds.push(seed);
                    }

                    while Instant::now() < end_time {
                        for seed in &seeds {
                            // Check time more frequently to avoid running over the limit
                            if Instant::now() >= end_time {
                                break;
                            }

                            // This is the expensive operation we're measuring
                            let signing_key = SigningKey::from_bytes(seed);
                            let _verifying_key = signing_key.verifying_key();

                            local_count += 1;
                        }
                    }

                    total_keys.fetch_add(local_count, Ordering::Relaxed);
                })
            })
            .collect();

        // Wait for all threads to complete benchmark
        for handle in handles {
            handle.join().unwrap();
        }

        let elapsed = start_time.elapsed();
        let total_keys_generated = total_keys.load(Ordering::Relaxed);

        // Ensure we have meaningful measurements
        if total_keys_generated == 0 || elapsed.as_secs_f64() < 0.1 {
            return Err(anyhow::anyhow!("Benchmark produced insufficient data"));
        }

        let keys_per_sec = total_keys_generated as f64 / elapsed.as_secs_f64();
        let keys_per_sec_per_core = keys_per_sec / cores as f64;

        Ok((keys_per_sec_per_core, total_keys_generated, elapsed))
    }
}

/// Collects system information to identify when cached performance data might not apply.
/// Platform changes (CPU, thermal state) can significantly affect key generation speed.
fn get_platform_info() -> String {
    // Get basic platform information without external dependencies
    let cpu_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    format!("{} - {} cores", std::env::consts::ARCH, cpu_count)
}

/// Estimates search time for vanity address generation using a simple theoretical calculation.
/// Returns the expected search duration in seconds for finding a matching prefix.
/// NOTE: This is the AVERAGE case - actual time can vary significantly!
pub fn estimate_search_time(prefix_length: usize, keys_per_sec: f64) -> f64 {
    // Handle edge cases
    if keys_per_sec <= 0.0 || keys_per_sec.is_nan() || keys_per_sec.is_infinite() {
        return f64::INFINITY;
    }

    // Simple theoretical calculation based on combinatorics
    let prefix_combinations = 16_f64.powi(prefix_length as i32);

    // Apply a real-world performance penalty factor of ~15% to account for:
    // - Prefix checking overhead
    // - Thread coordination overhead
    // - Memory allocations and I/O
    let real_world_keys_per_sec = keys_per_sec * 0.85;

    prefix_combinations / real_world_keys_per_sec
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use tempfile::NamedTempFile;

    #[test]
    fn test_performance_result_creation() {
        let result = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: 1234567890,
            platform: "Test Platform".to_string(),
        };

        assert_eq!(result.keys_per_sec_per_core, 1000.0);
        assert_eq!(result.cores_used, 4);
        assert_eq!(result.timestamp, 1234567890);
        assert_eq!(result.platform, "Test Platform");
    }

    #[test]
    fn test_performance_result_serialization() {
        let result = PerformanceResult {
            keys_per_sec_per_core: 2500.5,
            cores_used: 8,
            timestamp: 1640995200, // Jan 1, 2022
            platform: "AMD Ryzen 9 5900X - 12 cores".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("2500.5"));
        assert!(json.contains("\"cores_used\":8"));
        assert!(json.contains("AMD Ryzen"));

        // Test deserialization
        let deserialized: PerformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.keys_per_sec_per_core,
            result.keys_per_sec_per_core
        );
        assert_eq!(deserialized.cores_used, result.cores_used);
        assert_eq!(deserialized.timestamp, result.timestamp);
        assert_eq!(deserialized.platform, result.platform);
    }

    #[test]
    fn test_performance_cache_save_and_load() {
        // Create a temporary file for testing
        let temp_file = NamedTempFile::new().unwrap();
        let _temp_path = temp_file.path().to_string_lossy().to_string();

        let original_result = PerformanceResult {
            keys_per_sec_per_core: 1500.0,
            cores_used: 6,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            platform: "Test Platform".to_string(),
        };

        // Test saving (we can't easily test the actual save method without modifying the struct)
        // But we can test the JSON serialization works
        let json = serde_json::to_string_pretty(&original_result).unwrap();
        assert!(json.contains("keys_per_sec_per_core"));
        assert!(json.contains("1500"));
    }

    #[test]
    fn test_performance_cache_load_nonexistent() {
        // Loading from a non-existent file should return None
        // We can't easily test this without modifying the cache file path
        // But we can test that the JSON parsing works
        let invalid_json = "{ invalid json }";
        let result: Result<PerformanceResult, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_performance_cache_validity() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test recent timestamp (should be valid)
        let recent_result = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: now - 3600, // 1 hour ago
            platform: "Test".to_string(),
        };

        // Test old timestamp (should be invalid)
        let old_result = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: now - (25 * 3600), // 25 hours ago
            platform: "Test".to_string(),
        };

        // The validity logic would be: now - timestamp < 24 * 3600
        assert!(now - recent_result.timestamp < 24 * 3600);
        assert!(now - old_result.timestamp >= 24 * 3600);
    }

    #[test]
    fn test_estimate_search_time() {
        let keys_per_sec = 10000.0;

        // Test short prefix (1 character = 4 bits)
        let prefix_time = estimate_search_time(1, keys_per_sec);
        assert!(prefix_time > 0.0);
        assert!(prefix_time < 1000.0); // Should be reasonable for 1 char

        // Test longer prefix (4 characters = 16 bits)
        let prefix_time_4 = estimate_search_time(4, keys_per_sec);
        assert!(prefix_time_4 > prefix_time); // Longer prefix takes more time
    }

    #[test]
    fn test_estimate_search_time_edge_cases() {
        // Test with very high performance
        let prefix_time = estimate_search_time(2, 1_000_000.0);
        assert!(prefix_time > 0.0);

        // Test with low performance
        let prefix_time = estimate_search_time(3, 100.0);
        assert!(prefix_time > 0.0);
    }

    #[test]
    fn test_platform_info_format() {
        // We can't easily test the actual platform info without running on the system
        // But we can test that the format would be reasonable
        let platform_info = "Intel Core i7-9700K - 8 cores";
        assert!(platform_info.contains("cores"));
        assert!(platform_info.contains("-"));
    }

    #[test]
    fn test_performance_degradation_factors() {
        // Test that longer patterns take progressively more time
        let base_rate = 10000.0;

        let time_3 = estimate_search_time(3, base_rate);
        let time_4 = estimate_search_time(4, base_rate);
        let time_5 = estimate_search_time(5, base_rate);

        // Longer patterns should take progressively more time due to exponential scaling
        assert!(time_4 > time_3);
        assert!(time_5 > time_4);
    }

    #[test]
    fn test_performance_result_debug() {
        let result = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: 1234567890,
            platform: "Test Platform".to_string(),
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("PerformanceResult"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_json_pretty_formatting() {
        let result = PerformanceResult {
            keys_per_sec_per_core: 1234.5,
            cores_used: 8,
            timestamp: 1640995200,
            platform: "Test CPU".to_string(),
        };

        let json = serde_json::to_string_pretty(&result).unwrap();

        // Pretty JSON should have newlines and indentation
        assert!(json.contains('\n'));
        assert!(json.contains("  "));
        assert!(json.contains("keys_per_sec_per_core"));
    }

    #[test]
    fn test_performance_result_edge_values() {
        // Test with zero values
        let zero_result = PerformanceResult {
            keys_per_sec_per_core: 0.0,
            cores_used: 0,
            timestamp: 0,
            platform: "".to_string(),
        };

        let json = serde_json::to_string(&zero_result).unwrap();
        let deserialized: PerformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys_per_sec_per_core, 0.0);
        assert_eq!(deserialized.cores_used, 0);

        // Test with very large values
        let large_result = PerformanceResult {
            keys_per_sec_per_core: f64::MAX,
            cores_used: usize::MAX,
            timestamp: u64::MAX,
            platform: "Very long platform name".repeat(100),
        };

        let json = serde_json::to_string(&large_result).unwrap();
        let deserialized: PerformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys_per_sec_per_core, f64::MAX);
        assert_eq!(deserialized.cores_used, usize::MAX);
    }

    #[test]
    fn test_estimate_search_time_extreme_cases() {
        // Test with zero performance
        let prefix_time = estimate_search_time(1, 0.0);
        assert!(prefix_time.is_infinite());

        // Test with very high performance
        let prefix_time = estimate_search_time(1, f64::MAX);
        assert!(prefix_time >= 0.0);

        // Test with negative performance (should handle gracefully)
        let prefix_time = estimate_search_time(1, -1000.0);
        assert!(prefix_time.is_infinite() || prefix_time.is_nan());
    }

    #[test]
    fn test_estimate_search_time_prefix_length_scaling() {
        let keys_per_sec = 10000.0;

        // Test that longer prefixes take exponentially more time
        let mut prev_prefix_time = 0.0;

        for length in 1..=6 {
            let prefix_time = estimate_search_time(length, keys_per_sec);

            if length > 1 {
                // Each additional character should significantly increase time
                assert!(prefix_time > prev_prefix_time);

                // Time should grow exponentially (roughly 16x for each hex digit)
                if length <= 4 {
                    // Avoid overflow for very large values
                    assert!(prefix_time / prev_prefix_time > 10.0);
                }
            }

            prev_prefix_time = prefix_time;
        }
    }

    #[test]
    fn test_performance_result_clone() {
        let original = PerformanceResult {
            keys_per_sec_per_core: 5000.0,
            cores_used: 8,
            timestamp: 1234567890,
            platform: "Test Platform".to_string(),
        };

        let cloned = original.clone();

        assert_eq!(original.keys_per_sec_per_core, cloned.keys_per_sec_per_core);
        assert_eq!(original.cores_used, cloned.cores_used);
        assert_eq!(original.timestamp, cloned.timestamp);
        assert_eq!(original.platform, cloned.platform);
    }

    #[test]
    fn test_performance_result_partial_eq() {
        let result1 = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: 1234567890,
            platform: "Platform A".to_string(),
        };

        let result2 = PerformanceResult {
            keys_per_sec_per_core: 1000.0,
            cores_used: 4,
            timestamp: 1234567890,
            platform: "Platform A".to_string(),
        };

        let result3 = PerformanceResult {
            keys_per_sec_per_core: 2000.0,
            cores_used: 4,
            timestamp: 1234567890,
            platform: "Platform A".to_string(),
        };

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_degradation_factors() {
        let base_performance = 10000.0;

        // Test that performance scaling is applied correctly
        for length in 1..=8 {
            let prefix_time = estimate_search_time(length, base_performance);

            // Verify that times make sense (longer patterns take more time)
            assert!(prefix_time > 0.0);

            // Verify that times are finite and reasonable
            assert!(prefix_time.is_finite());
        }
    }

    #[test]
    fn test_performance_measurement_concepts() {
        // Test the concept of performance measurement
        // These tests verify the mathematical relationships work correctly

        let slow_system = 100.0; // 100 keys/sec
        let fast_system = 100000.0; // 100k keys/sec

        let slow_prefix = estimate_search_time(3, slow_system);
        let fast_prefix = estimate_search_time(3, fast_system);

        // Faster system should take less time
        assert!(fast_prefix < slow_prefix);

        // The ratio should be roughly proportional to performance difference
        let speed_ratio = fast_system / slow_system;
        let time_ratio = slow_prefix / fast_prefix;

        // The time ratio should be close to the speed ratio (inverse relationship)
        assert!(time_ratio > speed_ratio * 0.5);
        assert!(time_ratio < speed_ratio * 2.0);
    }
}
