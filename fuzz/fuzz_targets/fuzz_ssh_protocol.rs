#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_key::PublicKey;

fuzz_target!(|data: &[u8]| {
    // Try to parse as SSH public key from raw bytes
    let _ = PublicKey::from_bytes(data);

    // Try to parse as OpenSSH-format public key string
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = PublicKey::from_openssh(s);
    }
});
