#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use ssh_key::Algorithm;
use ssh_key::PublicKey;
use ssh_key::private::PrivateKey;
use ssh_key::rand_core::OsRng;
use std::fs;
use tempfile::TempDir;

/// Structured fuzz input for direct `sign_host_certificate` testing.
///
/// The `public_key` field uses the project's `arbitrary_public_key` generator
/// to produce valid Ed25519 public keys that the cert-builder can process.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    host_name: String,
    #[arbitrary(with = ssh_ca_server::certificat_authority::arbitrary_public_key)]
    public_key: PublicKey,
    /// The string written as `public_key` in the host config TOML.
    /// When this differs from `public_key`, the key-mismatch path is exercised.
    /// When this is not valid OpenSSH, the config-parse-failure path is exercised.
    config_public_key: String,
    validity_in_days: u32,
    hostnames: Vec<String>,
    extensions: Vec<String>,
}

/// Exercises `CertificateAuthority::sign_host_certificate` directly with
/// fuzz-generated host config content, hostnames, extensions, and key
/// match/mismatch scenarios.
fuzz_target!(|input: FuzzInput| {
    // Skip inputs that would fail at the filesystem level before reaching
    // the interesting code paths.
    if input.host_name.is_empty()
        || input.host_name.len() > 256
        || input.host_name.contains('/')
        || input.host_name.contains('\\')
        || input.host_name.contains('\0')
        || input.host_name.contains("..")
    {
        return;
    }

    // Cap collection sizes to avoid wasting cycles
    if input.hostnames.len() > 32 || input.extensions.len() > 32 {
        return;
    }

    // Clamp validity to a reasonable range (0 would be an interesting edge case)
    let validity_in_days = input.validity_in_days.min(3650);

    let temp_dir = TempDir::new().expect("temp dir");
    let base_path = temp_dir.path();

    // Set up CA
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let ca_key_path = base_path.join("ca_key");
    fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

    let user_list_path = base_path.join("user.toml");
    fs::write(&user_list_path, "[users]\n").unwrap();
    let default_path = base_path.join("user_default.toml");
    fs::write(
        &default_path,
        "validity_in_days = 1\nprincipals = []\nextensions = []\n",
    )
    .unwrap();

    let host_inventory = base_path.join("hosts");
    fs::create_dir(&host_inventory).unwrap();

    // Build host config TOML with fuzz-controlled content.
    // Escape strings for TOML safety.
    let escape_toml = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");

    let hostnames_toml: Vec<String> = input
        .hostnames
        .iter()
        .take(32)
        .map(|h| format!("\"{}\"", escape_toml(h)))
        .collect();
    let extensions_toml: Vec<String> = input
        .extensions
        .iter()
        .take(32)
        .map(|e| format!("\"{}\"", escape_toml(e)))
        .collect();

    let host_config = format!(
        "public_key = \"{}\"\nvalidity_in_days = {}\nhostnames = [{}]\nextensions = [{}]\n",
        escape_toml(&input.config_public_key),
        validity_in_days,
        hostnames_toml.join(", "),
        extensions_toml.join(", "),
    );
    let _ = fs::write(
        host_inventory.join(format!("{}.toml", input.host_name)),
        host_config,
    );

    let ca_config = CaConfig {
        user_list_file: user_list_path,
        default_user_template: default_path,
        host_inventory,
        ca_key: ca_key_path,
    };

    if let Ok(ca) = CertificateAuthority::new(&ca_config) {
        // Must not panic regardless of input
        let _ = ca.sign_host_certificate(&input.host_name, &input.public_key);
    }
});
