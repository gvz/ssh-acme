#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::CaRequest;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::ca_server::CaServer;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use ssh_key::Algorithm;
use ssh_key::private::PrivateKey;
use ssh_key::rand_core::OsRng;
use std::fs;
use tempfile::TempDir;

fuzz_target!(|request: CaRequest| {
    let temp_dir = TempDir::new().expect("Failed to create temporary directory");
    let base_path = temp_dir.path();

    // Generate a CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let ca_key_path = base_path.join("ca_key");
    fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

    // Create minimal user list
    let user_list_path = base_path.join("user.toml");
    fs::write(&user_list_path, "[users]\n").unwrap();

    // Create default user template
    let default_path = base_path.join("user_default.toml");
    fs::write(
        &default_path,
        "validity_in_days = 7\nprincipals = [\"{{ user_name }}\"]\nextensions = []\n",
    )
    .unwrap();

    // Create host inventory directory
    let host_inventory = base_path.join("hosts");
    fs::create_dir(&host_inventory).unwrap();

    let ca_config = CaConfig {
        user_list_file: user_list_path,
        default_user_template: default_path,
        host_inventory,
        ca_key: ca_key_path,
    };

    if let Ok(ca) = CertificateAuthority::new(&ca_config) {
        let server = CaServer::new("fuzz_socket".to_string(), ca, "fuzz_token".to_string());
        let _ = server.handle_request(request);
    }
});
