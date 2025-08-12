use crate::cpu::CpuKeySearcher;
use crate::performance::{PerformanceCache, estimate_search_time};
use crate::types::{FoundKey, SearchBehavior, SearchConfig, SearchStats};
use crate::utils::{format_duration, format_large_number};
use anyhow::Result;
use crossbeam::channel;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Persists found keys to disk for user access.
/// Uses append mode to avoid losing previously found keys if the search continues.
pub fn log_found_key(key: &FoundKey, _stats: &SearchStats) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("meshcore-keys.txt")?;

    writeln!(file, "{}; {}", key.private_key.expose(), key.public_key)?;
    Ok(())
}

/// Displays performance metrics and search time estimates to help users understand expected runtime.
/// Uses cached performance data when available to avoid repeated benchmarking.
pub fn print_performance_info(config: &SearchConfig) -> Result<()> {
    // Use cached data to avoid re-benchmarking on every run
    let perf_result = if let Some(cached) = PerformanceCache::load() {
        println!("\n📈✨ Using cached performance data:");
        println!(
            "   ⚡️ Speed per core: {:.0} keys/sec",
            cached.keys_per_sec_per_core
        );
        println!("   🌟 Platform: {}!", cached.platform);
        cached
    } else {
        PerformanceCache::measure_performance(config.cpu_threads)?
    };

    let total_speed = perf_result.keys_per_sec_per_core * config.cpu_threads as f64;
    let prefix_len = config.prefix.len();

    println!("\n📊🔥 Search Statistics:");
    println!("   🎯 Prefix length: {} hex characters", prefix_len);
    println!("   🚀 Expected speed: {:.0} keys/sec!", total_speed);

    let prefix_time = estimate_search_time(prefix_len, total_speed);

    // Calculate search probability ranges for better user expectations
    let probability_50_percent = prefix_time * 0.693; // ln(2) ≈ 0.693
    let probability_90_percent = prefix_time * 2.303; // ln(10) ≈ 2.303

    println!(
        "   ⏰ Estimated time (AVERAGE): {}!",
        format_duration(prefix_time)
    );
    println!("   📈 Search time ranges:");
    println!(
        "      • 50% chance: Found within {}",
        format_duration(probability_50_percent)
    );
    println!(
        "      • 90% chance: Found within {}",
        format_duration(probability_90_percent)
    );
    println!(
        "   ⚠️  Note: This is probabilistic - you might get lucky (seconds) or unlucky (much longer)!"
    );

    Ok(())
}

/// Main key search orchestration function.
/// Sets up worker threads, manages communication between them, and handles user output.
pub fn run_key_search(config: SearchConfig) -> Result<()> {
    print_performance_info(&config)?;

    let stats = Arc::new(SearchStats::new());
    let config = Arc::new(config);

    let (found_sender, found_receiver) = channel::unbounded();

    // Use CPU workers for key search
    let total_cpu_threads = config.cpu_threads;
    println!(
        "💻🔥 Using {} workers for maximum performance! ",
        total_cpu_threads
    );

    let mut worker_handles = Vec::new();

    // Spawn CPU workers
    let cpu_handles = CpuKeySearcher::spawn_workers(
        total_cpu_threads,
        Arc::clone(&config),
        Arc::clone(&stats),
        found_sender.clone(),
    );
    worker_handles.extend(cpu_handles);

    // Close the channel when all workers finish
    drop(found_sender);

    // Monitor search progress and enforce stopping conditions
    let stats_clone = Arc::clone(&stats);
    let config_clone = Arc::clone(&config);

    let monitor_handle = std::thread::spawn(move || {
        let mut last_attempts = 0u64;
        let mut last_time = Instant::now();
        let search_start_time = Instant::now();

        loop {
            std::thread::sleep(Duration::from_secs(3));

            let current_attempts = stats_clone.total_attempts.load(Ordering::Relaxed);
            let prefix_found = stats_clone.prefix_matches.load(Ordering::Relaxed);

            let now = Instant::now();
            let elapsed = now.duration_since(last_time).as_secs_f64();
            let keys_per_sec = (current_attempts - last_attempts) as f64 / elapsed;

            // Calculate search progress and time estimates
            let total_search_time = search_start_time.elapsed().as_secs();

            // Show progress with percentage for long searches (> 30 seconds)
            if total_search_time > 30 {
                print!(
                    "\r\x1B[K🚀 Attempts: {} | ✨ Matches: {} | ⚡️ Keys/sec: {:.0} | 🕐 Running: {}",
                    format_large_number(current_attempts),
                    prefix_found,
                    keys_per_sec,
                    format_duration(total_search_time as f64)
                );
            } else {
                print!(
                    "\r\x1B[K🚀 Total Attempts: {} | ✨ Matches: {} | ⚡️ Keys/sec: {:.0}",
                    format_large_number(current_attempts),
                    prefix_found,
                    keys_per_sec
                );
            }
            std::io::stdout().flush().unwrap();

            last_attempts = current_attempts;
            last_time = now;

            // Stop workers when the target number of keys is found
            let should_stop = match &config_clone.search_behavior {
                SearchBehavior::FindN(n) => prefix_found >= *n,
                SearchBehavior::Continuous => false,
            };

            if should_stop {
                stats_clone.stop_search.store(true, Ordering::Relaxed);
                break;
            }
        }
    });

    // Process and display found keys as they arrive
    let mut total_found = 0usize;
    while let Ok(found_key) = found_receiver.recv() {
        println!(
            "\n🎉✨ BOOM! Found key #{} 💎🔥\n   Public Key: {}",
            total_found + 1,
            found_key.public_key
        );

        if let Err(e) = log_found_key(&found_key, &stats) {
            eprintln!("😤 Ugh, error logging key (but we found it anyway!): {}", e);
        }

        total_found += 1;

        // Stop searching when the user's target is reached
        let should_stop = match config.search_behavior {
            SearchBehavior::FindN(n) => total_found >= n,
            SearchBehavior::Continuous => false,
        };

        if should_stop {
            stats.stop_search.store(true, Ordering::Relaxed);
            break;
        }
    }

    // Ensure all worker threads complete before exiting
    for handle in worker_handles {
        handle.join().unwrap();
    }

    monitor_handle.join().unwrap();

    if total_found > 0 {
        println!(
            "\n\n🎉🌟 SUCCESS! Found {} matching key(s) because we're THAT good! ✨",
            total_found
        );
        println!("📝💎 Keys have been saved to: meshcore-keys.txt");
        println!("🔒🗑️ Remember to securely delete the file when done: ./meshcore-keygen --delete");
    } else {
        println!("\n\n❌💔 No matching keys found");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureString;
    use crate::types::{FoundKey, SearchStats};

    #[test]
    fn test_log_found_key() {
        let found_key = FoundKey {
            private_key: SecureString::new("test_private_key".to_string()),
            public_key: "test_public_key".to_string(),
        };
        let stats = SearchStats::new();

        // This test will create a file, so we should clean up
        let result = log_found_key(&found_key, &stats);
        assert!(result.is_ok());

        // Clean up the test file
        std::fs::remove_file("meshcore-keys.txt").ok();
    }
}
