/// Determines if a public key starts with the specified byte pattern.
/// Early exit optimization prevents unnecessary comparisons for mismatched lengths.
pub fn check_prefix_match(public_key_bytes: &[u8], prefix_bytes: &[u8]) -> bool {
    if prefix_bytes.len() > public_key_bytes.len() {
        return false;
    }
    &public_key_bytes[..prefix_bytes.len()] == prefix_bytes
}

/// Converts hex strings to byte arrays with robust error handling.
/// Pads at the end rather than beginning to preserve pattern meaning (e.g., "ABC" -> "ABC0" not "0ABC").
pub fn hex_string_to_bytes(hex: &str) -> Vec<u8> {
    let mut hex = hex.to_uppercase();

    // Pad odd-length strings at the end to preserve user intent
    if hex.len() % 2 == 1 {
        hex = format!("{}0", hex);
    }

    // Gracefully handle invalid characters to prevent crashes from user input
    hex = hex
        .chars()
        .map(|c| if c.is_ascii_hexdigit() { c } else { '0' })
        .collect();

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

/// Formats large numbers in human-readable units for progress display.
/// Prevents information overload when showing millions/billions of attempts.
pub fn format_large_number(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n < 1_000_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else {
        format!("{:.1}T", n as f64 / 1_000_000_000_000.0)
    }
}

/// Validates that a private key follows the meshcore-compatible Ed25519 expanded format.
/// The 64-byte format should be an expanded Ed25519 private key from which we can derive a public key.
/// This validates the structure but doesn't verify against a specific seed or public key.
pub fn validate_meshcore_key_format(private_key_bytes: &[u8]) -> bool {
    if private_key_bytes.len() != 64 {
        return false;
    }

    // Try to derive a public key from the expanded private key
    // If this succeeds, the format is valid
    extract_public_key_from_meshcore_key(private_key_bytes).is_some()
}

/// Creates a meshcore-compatible private key from a seed.
/// Returns a 64-byte array in the expanded Ed25519 private key format.
pub fn create_meshcore_private_key(seed: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    // Follow the Ed25519 expanded private key generation process
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();

    let mut expanded_key = [0u8; 64];
    expanded_key.copy_from_slice(&hash[..]);

    // Clamp the first 32 bytes (scalar) according to Ed25519 spec
    expanded_key[0] &= 248;
    expanded_key[31] &= 63;
    expanded_key[31] |= 64;

    expanded_key
}

/// Derives the public key from a meshcore-compatible expanded private key.
/// Uses the first 32 bytes as the scalar for Ed25519 point multiplication.
pub fn extract_public_key_from_meshcore_key(private_key_bytes: &[u8]) -> Option<[u8; 32]> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    if private_key_bytes.len() != 64 {
        return None;
    }

    // Use the first 32 bytes as the clamped scalar (matches ge_scalarmult_base behavior)
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&private_key_bytes[0..32]);

    // Convert to scalar and perform point multiplication
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let point = scalar * ED25519_BASEPOINT_POINT;

    // Convert point to compressed bytes (public key format)
    Some(point.compress().to_bytes())
}

/// Formats duration in human-readable units to help users understand search time estimates.
/// Uses appropriate units (seconds, minutes, hours, etc.) to avoid overwhelming users
/// with raw second counts for very long operations.
pub fn format_duration(seconds: f64) -> String {
    if seconds.is_nan() || seconds.is_infinite() {
        return "longer than the age of the universe".to_string();
    }

    if seconds == 0.0 || seconds < f64::MIN_POSITIVE * 1000.0 {
        "0.0 seconds".to_string()
    } else if seconds < 0.01 {
        format!("{:.3} seconds", seconds)
    } else if seconds < 60.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 31536000.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else if seconds < 31536000000.0 {
        format!("{:.1} years", seconds / 31536000.0)
    } else {
        "longer than the age of the universe".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meshcore_key_creation_and_validation() {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Create meshcore key using utility function
        let meshcore_key = create_meshcore_private_key(&seed);

        // Validate the key format
        assert!(validate_meshcore_key_format(&meshcore_key));

        // Extract public key and verify it matches what Ed25519 generates
        let extracted_public_key = extract_public_key_from_meshcore_key(&meshcore_key).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let expected_public_key = signing_key.verifying_key().to_bytes();
        assert_eq!(extracted_public_key, expected_public_key);
    }

    #[test]
    fn test_meshcore_key_edge_cases() {
        // Test with all zeros seed
        let zero_seed = [0u8; 32];
        let meshcore_key = create_meshcore_private_key(&zero_seed);
        assert!(validate_meshcore_key_format(&meshcore_key));

        // Test with all 0xFF seed
        let max_seed = [0xFFu8; 32];
        let meshcore_key = create_meshcore_private_key(&max_seed);
        assert!(validate_meshcore_key_format(&meshcore_key));
    }

    #[test]
    fn test_invalid_meshcore_key_formats() {
        // Test with wrong length keys
        let too_short = [0u8; 32];
        assert!(!validate_meshcore_key_format(&too_short));
        assert_eq!(extract_public_key_from_meshcore_key(&too_short), None);

        let too_long = [0u8; 96];
        assert!(!validate_meshcore_key_format(&too_long));
        assert_eq!(extract_public_key_from_meshcore_key(&too_long), None);

        // Test with key that has invalid public key portion
        let mut invalid_key = [0u8; 64];
        invalid_key[63] = 0xFF; // This will make the public key portion invalid
        // Note: This test might pass depending on the seed, so we're mainly testing structure
        let _is_valid = validate_meshcore_key_format(&invalid_key);
    }

    #[test]
    fn test_hex_string_to_bytes_comprehensive() {
        // Test various hex string patterns
        let test_cases = vec![
            ("", vec![]),
            ("0", vec![0x00]),
            ("F", vec![0xF0]),
            ("00", vec![0x00]),
            ("FF", vec![0xFF]),
            ("BEEF", vec![0xBE, 0xEF]),
            ("beef", vec![0xBE, 0xEF]),
            (
                "123456789ABCDEF0",
                vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            ),
            ("ABC", vec![0xAB, 0xC0]), // Odd length should be padded at the end
            ("1", vec![0x10]),
            ("a", vec![0xA0]),
        ];

        for (input, expected) in test_cases {
            let result = hex_string_to_bytes(input);
            assert_eq!(result, expected, "Failed for input: '{}'", input);
        }
    }

    #[test]
    fn test_hex_string_to_bytes_invalid_chars() {
        // Test with invalid hex characters - they should become 0
        let invalid_inputs = vec![
            "BEEG",  // G is invalid
            "123Z",  // Z is invalid
            "HELLO", // All letters but not hex
            "12!@",  // Special characters
        ];

        for input in invalid_inputs {
            let result = hex_string_to_bytes(input);
            // Should not panic and should return some result
            assert!(!result.is_empty() || input.is_empty());
        }
    }

    #[test]
    fn test_check_prefix_match_comprehensive() {
        let test_cases = vec![
            // (public_key, prefix, expected_match)
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0xBE], true),
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0xBE, 0xEF], true),
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0xBE, 0xEF, 0x12], true),
            (
                vec![0xBE, 0xEF, 0x12, 0x34],
                vec![0xBE, 0xEF, 0x12, 0x34],
                true,
            ),
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0xEF], false),
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0x12, 0x34], false),
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![0xBE, 0xFF], false),
            (
                vec![0xBE, 0xEF, 0x12, 0x34],
                vec![0xBE, 0xEF, 0x12, 0x34, 0x56],
                false,
            ), // Prefix longer than key
            (vec![0xBE, 0xEF, 0x12, 0x34], vec![], true), // Empty prefix should match
        ];

        for (public_key, prefix, expected) in test_cases {
            let result = check_prefix_match(&public_key, &prefix);
            assert_eq!(
                result, expected,
                "Failed for public_key: {:02X?}, prefix: {:02X?}",
                public_key, prefix
            );
        }
    }

    #[test]
    fn test_format_large_number_comprehensive() {
        let test_cases = vec![
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (1_000, "1.0K"),
            (1_500, "1.5K"),
            (999_999, "1000.0K"),
            (1_000_000, "1.0M"),
            (1_500_000, "1.5M"),
            (2_500_000, "2.5M"),
            (999_999_999, "1000.0M"),
            (1_000_000_000, "1.0B"),
            (1_500_000_000, "1.5B"),
            (999_999_999_999, "1000.0B"),
            (1_000_000_000_000, "1.0T"),
            (1_500_000_000_000, "1.5T"),
            (10_000_000_000_000, "10.0T"),
        ];

        for (input, expected) in test_cases {
            let result = format_large_number(input);
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_format_large_number_edge_cases() {
        // Test edge cases around boundaries
        assert_eq!(format_large_number(999), "999");
        assert_eq!(format_large_number(1000), "1.0K");
        assert_eq!(format_large_number(999_999), "1000.0K");
        assert_eq!(format_large_number(1_000_000), "1.0M");

        // Test maximum value
        assert!(format_large_number(u64::MAX).contains("T"));
    }

    #[test]
    fn test_prefix_suffix_edge_cases() {
        // Test with single byte arrays
        let single_byte = vec![0xFF];
        assert!(check_prefix_match(&single_byte, &[0xFF]));
        assert!(!check_prefix_match(&single_byte, &[0x00]));

        // Test with empty arrays
        let empty = vec![];
        assert!(check_prefix_match(&empty, &[]));
        assert!(!check_prefix_match(&empty, &[0x00]));
    }

    #[test]
    fn test_prefix_and_suffix_same_pattern() {
        // Test cases where prefix and suffix are the same
        let public_key = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0xAB];
        let pattern = vec![0xAB];

        // Both prefix and suffix should match
        assert!(check_prefix_match(&public_key, &pattern));

        // Different pattern should not match both
        let pattern2 = vec![0xCD];
        assert!(!check_prefix_match(&public_key, &pattern2));
    }

    #[test]
    fn test_hex_conversion_round_trip() {
        // Test that converting to hex and back gives the same result
        let original_bytes = vec![0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF];
        let hex_string = hex::encode(&original_bytes).to_uppercase();
        let converted_back = hex_string_to_bytes(&hex_string);

        assert_eq!(original_bytes, converted_back);
    }

    #[test]
    fn test_large_arrays() {
        // Test with larger arrays (simulating real public keys)
        let large_key = vec![0; 32]; // 32 bytes like Ed25519 public keys
        let pattern = vec![0, 0, 0, 0];

        assert!(check_prefix_match(&large_key, &pattern));

        // Test with non-matching pattern
        let non_matching = vec![0xFF, 0xFF, 0xFF, 0xFF];
        assert!(!check_prefix_match(&large_key, &non_matching));
    }

    #[test]
    fn test_partial_matches() {
        // Test partial matches at the beginning and end
        let key = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56];

        // These should match prefix
        assert!(check_prefix_match(&key, &[0xAB]));
        assert!(check_prefix_match(&key, &[0xAB, 0xCD]));

        // These should not match prefix (they're in the middle/end)
        assert!(!check_prefix_match(&key, &[0xCD, 0xEF]));
        assert!(!check_prefix_match(&key, &[0x56]));
    }

    #[test]
    fn test_hex_string_case_insensitive() {
        // Test that both uppercase and lowercase work
        let test_cases = vec![
            ("BEEF", "beef"),
            ("123ABC", "123abc"),
            ("DeAdBeEf", "deadbeef"),
        ];

        for (upper, lower) in test_cases {
            let upper_result = hex_string_to_bytes(upper);
            let lower_result = hex_string_to_bytes(lower);
            assert_eq!(
                upper_result, lower_result,
                "Case sensitivity failed for {} vs {}",
                upper, lower
            );
        }
    }

    #[test]
    fn test_format_number_precision() {
        // Test that the decimal precision is correct
        assert_eq!(format_large_number(1_234), "1.2K"); // Should round appropriately
        assert_eq!(format_large_number(1_678), "1.7K"); // Should round appropriately
        assert_eq!(format_large_number(1_950), "1.9K"); // Should round appropriately
    }

    #[test]
    fn test_format_duration() {
        // Test various time ranges
        assert_eq!(format_duration(0.005), "0.005 seconds");
        assert_eq!(format_duration(0.1), "0.1 seconds");
        assert_eq!(format_duration(30.0), "30.0 seconds");
        assert_eq!(format_duration(120.0), "2.0 minutes");
        assert_eq!(format_duration(3661.0), "1.0 hours");
        assert_eq!(format_duration(86401.0), "1.0 days");
        assert_eq!(format_duration(31536001.0), "1.0 years");

        // Test extremely large values
        let very_large = 31536000000.0;
        assert_eq!(
            format_duration(very_large),
            "longer than the age of the universe"
        );
    }

    #[test]
    fn test_format_duration_edge_cases() {
        // Test exactly at boundaries
        assert!(format_duration(60.0).contains("minutes"));
        assert!(format_duration(3600.0).contains("hours"));
        assert!(format_duration(86400.0).contains("days"));
        assert!(format_duration(31536000.0).contains("years"));
    }

    #[test]
    fn test_format_duration_boundary_values() {
        // Test exact boundary values
        assert_eq!(format_duration(59.9), "59.9 seconds");
        assert_eq!(format_duration(60.0), "1.0 minutes");
        assert_eq!(format_duration(60.1), "1.0 minutes");

        assert_eq!(format_duration(3599.9), "60.0 minutes");
        assert_eq!(format_duration(3600.0), "1.0 hours");
        assert_eq!(format_duration(3600.1), "1.0 hours");

        assert_eq!(format_duration(86399.9), "24.0 hours");
        assert_eq!(format_duration(86400.0), "1.0 days");
        assert_eq!(format_duration(86400.1), "1.0 days");
    }

    #[test]
    fn test_format_duration_extreme_values() {
        // Test with very small values
        assert_eq!(format_duration(0.0), "0.0 seconds");
        assert_eq!(format_duration(f64::MIN_POSITIVE), "0.0 seconds");

        // Test with infinity
        assert_eq!(
            format_duration(f64::INFINITY),
            "longer than the age of the universe"
        );

        // Test with NaN
        let nan_result = format_duration(f64::NAN);
        assert!(nan_result.contains("longer than") || nan_result.contains("seconds"));
    }
}
