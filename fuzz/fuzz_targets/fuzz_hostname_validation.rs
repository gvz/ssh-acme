#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::validate_hostname;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Cap input length to avoid wasting cycles on huge strings
        if s.len() > 512 {
            return;
        }
        let result = validate_hostname(s);
        // If validation passed, verify the invariants:
        if result.is_ok() {
            assert!(!s.is_empty());
            assert!(!s.contains('/'));
            assert!(!s.contains('\\'));
            assert!(!s.contains(".."));
            assert!(!s.contains('\0'));
        }
    }
});
