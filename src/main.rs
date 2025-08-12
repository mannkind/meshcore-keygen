mod cpu;
mod keygen;
mod performance;
mod secure;
mod types;
mod utils;
use crate::keygen::run_key_search;
use crate::secure::secure_wipe_file;
use crate::types::{SearchBehavior, SearchConfig};
use anyhow::Result;
use clap::{Arg, Command};

/// Main entry point that handles command-line argument parsing and delegates to keygen module.
fn main() -> Result<()> {
    let matches = Command::new("meshcore-keygen")
        .version("0.1.0")
        .about("High-performance Ed25519 key searcher for generating custom public key patterns")
        .long_about("Searches for Ed25519 keys with specific hex patterns in the public key. \
                     Uses multi-threaded CPU processing for maximum performance.")
        .arg(
            Arg::new("pattern")
                .help("Hex pattern to search for in the public key (e.g., BEEF, 123456, 00ABC)")
                .long_help("The hexadecimal pattern to search for. Only characters 0-9 and A-F are allowed. \
                           Examples: BEEF, 123456, 00ABC, FFCAFE")
                .value_name("PATTERN")
                .required_unless_present("delete")
                .index(1),
        )
        .arg(
            Arg::new("max-keys")
                .long("max-keys")
                .short('n')
                .value_name("NUMBER")
                .help("Maximum number of keys to find before stopping")
                .long_help("Stop searching after finding this many keys. Use 0 for unlimited search.")
                .value_parser(clap::value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("delete")
                .long("delete")
                .short('d')
                .action(clap::ArgAction::SetTrue)
                .help("Securely delete the meshcore-keys.txt and exit")
                .long_help("Securely deletes meshcore-keys.txt using platform specific tooling."),
        )
        .get_matches();

    // Handle secure delete option
    if matches.get_flag("delete") {
        return handle_secure_delete();
    }

    // Parse arguments and create configuration
    let pattern = matches
        .get_one::<String>("pattern")
        .ok_or_else(|| anyhow::anyhow!("Pattern is required"))?
        .clone();

    let max_keys = *matches.get_one::<usize>("max-keys").unwrap();

    let config = create_search_config(pattern, max_keys)?;

    // Run the key search
    run_key_search(config)
}

/// Handles the secure deletion of the keys file.
pub fn handle_secure_delete() -> Result<()> {
    secure_wipe_file("meshcore-keys.txt")?;
    Ok(())
}

/// Validates command-line pattern and creates search configuration.
/// Enforces Ed25519 constraints to prevent generating invalid keys that would be rejected by meshcore.
pub fn create_search_config(pattern: String, max_keys: usize) -> Result<SearchConfig> {
    let pattern = pattern.to_uppercase();

    // Reject invalid hex characters to prevent runtime errors during key generation
    if !pattern.chars().all(|c| "0123456789ABCDEF".contains(c)) {
        anyhow::bail!(
            "Invalid hex characters in pattern '{}'. Only 0-9 and A-F are allowed.",
            pattern
        );
    }

    if pattern.is_empty() {
        anyhow::bail!("Pattern cannot be empty.");
    }

    let search_behavior = match max_keys {
        0 => SearchBehavior::Continuous,
        n => SearchBehavior::FindN(n),
    };

    // Reserve one core for system operations to maintain responsiveness during intensive computation
    let cpu_threads = std::thread::available_parallelism()?
        .get()
        .saturating_sub(1)
        .max(1);

    Ok(SearchConfig {
        prefix: pattern,
        search_behavior,
        cpu_threads,
    })
}

#[cfg(test)]
mod tests {
    use crate::create_search_config;
    use crate::types::SearchBehavior;

    #[test]
    fn test_create_search_config() {
        let config = create_search_config("BEEF".to_string(), 1).unwrap();
        assert_eq!(config.prefix, "BEEF");
        assert!(matches!(config.search_behavior, SearchBehavior::FindN(1)));
    }

    #[test]
    fn test_create_search_config_invalid_hex() {
        let result = create_search_config("XYZT".to_string(), 1);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid hex characters")
        );
    }

    #[test]
    fn test_create_search_config_valid_prefix_00() {
        let result = create_search_config("00BEEF".to_string(), 1);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.prefix, "00BEEF");
    }

    #[test]
    fn test_create_search_config_valid_prefix_ff() {
        let result = create_search_config("FFBEEF".to_string(), 1);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.prefix, "FFBEEF");
    }

    #[test]
    fn test_create_search_config_empty_pattern() {
        let result = create_search_config("".to_string(), 1);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Pattern cannot be empty")
        );
    }

    #[test]
    fn test_create_search_config_max_keys_variants() {
        let config_one = create_search_config("BEEF".to_string(), 1).unwrap();
        assert!(matches!(
            config_one.search_behavior,
            SearchBehavior::FindN(1)
        ));

        let config_n = create_search_config("BEEF".to_string(), 5).unwrap();
        assert!(matches!(config_n.search_behavior, SearchBehavior::FindN(5)));

        let config_continuous = create_search_config("BEEF".to_string(), 0).unwrap();
        assert!(matches!(
            config_continuous.search_behavior,
            SearchBehavior::Continuous
        ));
    }
}
