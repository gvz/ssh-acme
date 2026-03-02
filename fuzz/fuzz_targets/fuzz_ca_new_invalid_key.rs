#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Exercises `CertificateAuthority::new()` with fuzzer-generated key file
/// contents.  The private-key parsing code (`PrivateKey::from_openssh`) is
/// the target — it must not panic on arbitrary input.
fuzz_target!(|data: &[u8]| {
    // Cap input to avoid wasting cycles on huge buffers
    if data.len() > 8192 {
        return;
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let base_path = temp_dir.path();

    // Write fuzz data as if it were a CA private key file
    let key_path = base_path.join("ca_key");
    fs::write(&key_path, data).unwrap();

    let ca_config = CaConfig {
        user_list_file: PathBuf::from("/dev/null"),
        ca_key: key_path,
        default_user_template: PathBuf::from("/dev/null"),
        host_inventory: base_path.join("hosts"),
    };

    // Must not panic regardless of input
    let _ = CertificateAuthority::new(&ca_config);
});
