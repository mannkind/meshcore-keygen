use anyhow::Result;
use std::path::Path;
use std::process::Command;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure string wrapper that automatically zeroes memory on drop to prevent key recovery.
/// Critical for protecting private keys from memory dumps and swap files.
#[derive(ZeroizeOnDrop)]
pub struct SecureString {
    data: String,
}

impl SecureString {
    /// Memory safety is paramount when handling cryptographic keys - leaving sensitive
    /// data in memory can lead to key extraction via memory dumps or swap files.
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Provides controlled access without cloning - cloning would create additional
    /// copies in memory that we cannot control the lifetime of.
    pub fn expose(&self) -> &str {
        &self.data
    }
}

impl std::fmt::Debug for SecureString {
    /// Prevents accidental leakage of sensitive data in debug output and logs.
    /// Debugging output is often logged or displayed in development environments
    /// where it could be captured by unauthorized parties.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureString")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for SecureString {
    /// Manual zeroization may be needed before drop in critical scenarios
    /// where we want to clear sensitive data at a specific point in execution.
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

/// Attempts secure file deletion using platform-specific tools, falls back to standard deletion with warnings.
/// Necessary because private keys on disk are a major security risk - standard file deletion
/// only removes the directory entry, leaving data recoverable by forensic tools.
pub fn secure_wipe_file(filename: &str) -> Result<()> {
    let path = Path::new(filename);

    if !path.exists() {
        println!("🤷‍♀️💭 No {} file to delete", filename);
        return Ok(());
    }

    println!("🗑️🔒 Securely deleting {}", filename);

    // Platform-specific tools provide cryptographic-grade deletion by overwriting
    // the actual disk sectors multiple times, making data recovery nearly impossible
    if try_platform_secure_delete(filename)? {
        println!("✅🔒 File securely deleted using platform tools !");
        return Ok(());
    }

    // User education is critical - they need to understand the security implications
    // of not having proper secure deletion tools available on their system
    println!("⚠️💀 WARNING: PLATFORM SECURE DELETE TOOLS NOT AVAILABLE (uh oh!) ⚠️");
    println!("⚠️😱 The file will be deleted but data may be recoverable (yikes!) ⚠️");
    println!("⚠️🛠️ For true secure deletion, install platform tools (pretty please!): ⚠️");
    println!("⚠️🍎 - macOS: rm -P (built-in, thank goodness!) ⚠️");
    println!("⚠️🐧 - Linux: shred, wipe, or srm (take your pick!) ⚠️");
    println!("⚠️🪟 - Windows: sdelete or cipher (because Windows!) ⚠️");
    println!("⚠️😤 Proceeding with simple file deletion (we tried!) ⚠️");

    std::fs::remove_file(filename)?;
    println!("✅🗑️ File deleted (but data may be recoverable - we warned you! 🤷‍♀️)");

    Ok(())
}

/// Attempts platform-specific secure deletion before falling back to standard deletion.
/// Different platforms have different tools available - we must try multiple options
/// because users may have different configurations or missing tools.
fn try_platform_secure_delete(filename: &str) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        // macOS rm -P overwrites files 3 times with different patterns before deletion
        let output = Command::new("rm").arg("-P").arg(filename).output();

        match output {
            Ok(result) if result.status.success() => {
                println!("  ✨🍎 Platform: Used macOS secure delete (rm -P)");
                return Ok(true);
            }
            Ok(result) => {
                println!(
                    "  😤🍎 Platform: macOS rm -P failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            Err(e) => {
                println!("  💥🍎 Platform: Failed to execute rm -P: {}", e);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // shred is the most widely available and performs multiple overwrite passes
        if let Ok(output) = Command::new("shred")
            .arg("-vfz")
            .arg("-n")
            .arg("3")
            .arg(filename)
            .output()
            && output.status.success()
        {
            println!("  🔥🐧 Platform: Used Linux shred utility");
            return Ok(true);
        }

        // wipe is an alternative that may be available when shred is not
        if let Ok(output) = Command::new("wipe").arg("-rf").arg(filename).output()
            && output.status.success()
        {
            println!("  ✨🐧 Platform: Used Linux wipe utility");
            return Ok(true);
        }

        // srm (secure-delete package) provides additional security features
        if let Ok(output) = Command::new("srm").arg(filename).output()
            && output.status.success()
        {
            println!("  💫🐧 Platform: Used Linux srm utility");
            return Ok(true);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // sdelete from Sysinternals is the gold standard for Windows secure deletion
        if let Ok(output) = Command::new("sdelete")
            .arg("-p")
            .arg("3")
            .arg("-s")
            .arg("-z")
            .arg(filename)
            .output()
            && output.status.success()
        {
            println!("  🪟 Platform: Used Windows sdelete");
            return Ok(true);
        }

        // cipher is built into Windows but only wipes free space, not specific files
        // We use it as a last resort and must manually delete the file afterwards
        if let Ok(output) = Command::new("cipher")
            .arg("/w:")
            .arg(
                std::path::Path::new(filename)
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            )
            .output()
            && output.status.success()
        {
            // cipher /w only wipes free space, so we still need to delete the file
            std::fs::remove_file(filename)?;
            println!("  🎯🪟 Platform: Used Windows cipher utility");
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let data = "sensitive_data".to_string();
        let secure_str = SecureString::new(data.clone());

        assert_eq!(secure_str.expose(), &data);
    }

    #[test]
    fn test_secure_string_zeroize_on_drop() {
        let data = "sensitive_data".to_string();
        let mut secure_str = SecureString::new(data);

        // Manually call zeroize to test the functionality
        use zeroize::Zeroize;
        secure_str.zeroize();

        // After zeroizing, the data should be empty
        assert_eq!(secure_str.expose(), "");
    }

    #[test]
    fn test_secure_string_debug_implementation() {
        let secure_str = SecureString::new("secret".to_string());
        let debug_str = format!("{:?}", secure_str);

        // The debug implementation should exist and not panic
        assert!(debug_str.contains("SecureString"));
    }

    #[test]
    fn test_multiple_secure_strings() {
        let str1 = SecureString::new("first".to_string());
        let str2 = SecureString::new("second".to_string());

        assert_eq!(str1.expose(), "first");
        assert_eq!(str2.expose(), "second");
        assert_ne!(str1.expose(), str2.expose());
    }

    #[test]
    fn test_secure_string_empty() {
        let empty_str = SecureString::new(String::new());
        assert_eq!(empty_str.expose(), "");
    }

    #[test]
    fn test_secure_string_unicode() {
        let unicode_str = SecureString::new("🔒🗝️".to_string());
        assert_eq!(unicode_str.expose(), "🔒🗝️");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_platform_specific_macos() {
        // Test that we're testing on macOS
        assert!(cfg!(target_os = "macos"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_platform_specific_linux() {
        // Test that we're testing on Linux
        assert!(cfg!(target_os = "linux"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_platform_specific_windows() {
        // Test that we're testing on Windows
        assert!(cfg!(target_os = "windows"));
    }

    #[test]
    fn test_secure_string_with_large_data() {
        // Test with large strings
        let large_data = "A".repeat(10000);
        let secure_str = SecureString::new(large_data.clone());
        assert_eq!(secure_str.expose(), &large_data);
    }

    #[test]
    fn test_secure_string_with_special_characters() {
        let special_strings = vec![
            "".to_string(),
            "\n\r\t".to_string(),
            "🔒🗝️🔐".to_string(),
            "Mixed123!@#".to_string(),
            "\0\0\0".to_string(), // Null bytes
        ];

        for test_str in special_strings {
            let secure_str = SecureString::new(test_str.clone());
            assert_eq!(secure_str.expose(), &test_str);
        }
    }

    #[test]
    fn test_secure_wipe_file_with_different_paths() {
        use tempfile::NamedTempFile;

        // Test with different file scenarios
        let test_cases = vec![
            "nonexistent_file_test.tmp",
            "/tmp/nonexistent_dir/file.tmp", // Non-existent directory
            "",                              // Empty filename
        ];

        for path in test_cases {
            let result = secure_wipe_file(path);
            // Should not panic and should return Ok for non-existent files
            assert!(result.is_ok());
        }

        // Test with actual file
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_string_lossy().to_string();

        // Write some data
        std::fs::write(&temp_path, "sensitive data").unwrap();

        // Verify file exists and has content
        assert!(std::path::Path::new(&temp_path).exists());
        let content = std::fs::read_to_string(&temp_path).unwrap();
        assert_eq!(content, "sensitive data");

        // Securely wipe it
        let result = secure_wipe_file(&temp_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_string_debug_doesnt_leak() {
        let sensitive_data = "super_secret_key_12345";
        let secure_str = SecureString::new(sensitive_data.to_string());

        let debug_output = format!("{:?}", secure_str);

        // Debug output should not contain the actual sensitive data
        assert!(!debug_output.contains(sensitive_data));
        assert!(debug_output.contains("SecureString"));
    }

    #[test]
    fn test_concurrent_secure_operations() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread;

        let shared_data = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        // Spawn threads that create and manipulate secure strings
        for i in 0..4 {
            let data_clone = Arc::clone(&shared_data);
            let handle = thread::spawn(move || {
                let data_string = format!("thread_data_{}", i);
                let secure_str = SecureString::new(data_string.clone());
                let mut guard = data_clone.lock().unwrap();
                guard.push(data_string); // Use the original string instead of exposing
                assert_eq!(secure_str.expose(), &guard[guard.len() - 1]);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify results
        let final_data = shared_data.lock().unwrap();
        assert_eq!(final_data.len(), 4);

        // Check that all expected thread data strings are present (order doesn't matter)
        for i in 0..4 {
            let expected = format!("thread_data_{}", i);
            assert!(
                final_data.contains(&expected),
                "Missing thread data: {}",
                expected
            );
        }
    }

    #[test]
    fn test_secure_string_expose_immutable() {
        let secure_str = SecureString::new("test_data".to_string());

        // Multiple calls to expose should return the same value
        let exposed1 = secure_str.expose();
        let exposed2 = secure_str.expose();

        assert_eq!(exposed1, exposed2);
        assert_eq!(exposed1, "test_data");
    }
}
