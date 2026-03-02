#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_ca_server::certificat_authority::ca_server::CaServer;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;
use ssh_ca_server::certificat_authority::{
    AuthenticatedRequest, CaRequest, CaResponse, CertificateAuthority,
};
use ssh_key::Algorithm;
use ssh_key::private::PrivateKey;
use ssh_key::rand_core::OsRng;
use std::fs;
use subtle::ConstantTimeEq;
use tempfile::TempDir;

/// Shared auth token used by the fuzz harness.
const FUZZ_TOKEN: &str = "fuzz_token";

fuzz_target!(|data: &[u8]| {
    // Fuzz AuthenticatedRequest deserialization from raw bytes
    let auth_req = match serde_json::from_slice::<AuthenticatedRequest>(data) {
        Ok(req) => req,
        Err(_) => return,
    };

    // Also fuzz CaResponse deserialization (external code, but exercises
    // serde Deserialize impls for project types).
    let _ = serde_json::from_slice::<CaResponse>(data);

    // Replicate the authentication and dispatch logic from CaServer::run
    // so that project code in ca_server.rs and mod.rs gets instrumented.

    // Constant-time token comparison (mirrors ca_server.rs:120-124).
    let token_valid: bool = auth_req
        .token
        .as_bytes()
        .ct_eq(FUZZ_TOKEN.as_bytes())
        .into();
    if !token_valid {
        return;
    }

    // Skip replay counter check — the fuzzer generates arbitrary counters
    // and we want to exercise handle_request regardless.

    // Set up a minimal CaServer to process the request.
    let temp_dir = TempDir::new().expect("Failed to create temporary directory");
    let base_path = temp_dir.path();

    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let ca_key_path = base_path.join("ca_key");
    fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

    let user_list_path = base_path.join("user.toml");
    fs::write(&user_list_path, "[users]\n").unwrap();

    let default_path = base_path.join("user_default.toml");
    fs::write(
        &default_path,
        "validity_in_days = 7\nprincipals = [\"{{ user_name }}\"]\nextensions = []\n",
    )
    .unwrap();

    let host_inventory = base_path.join("hosts");
    fs::create_dir(&host_inventory).unwrap();

    // Populate host inventory when the request targets a host, so the fuzzer
    // can reach sign_host_certificate's key-comparison, cert-building, and
    // signing code paths.
    if let CaRequest::SignHostCertificate {
        ref host_name,
        ref public_key,
    } = auth_req.request
    {
        let safe_name = host_name.replace(['/', '\\', '\0'], "_");
        let safe_name = if safe_name.is_empty() || safe_name.contains("..") {
            "fuzz_host"
        } else {
            &safe_name
        };

        // Vary the config key to exercise different code paths:
        //   len % 3 == 0 → matching key   (cert-building + signing)
        //   len % 3 == 1 → mismatched key  (WrongPublicKey error)
        //   len % 3 == 2 → invalid key     (config key parse failure)
        let config_key = match host_name.len() % 3 {
            0 => public_key
                .to_openssh()
                .unwrap_or_else(|_| "invalid".to_string()),
            1 => {
                let other_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
                other_key.public_key().to_openssh().unwrap()
            }
            _ => "not-a-valid-ssh-key".to_string(),
        };

        let host_config = format!(
            "public_key = \"{}\"\nvalidity_in_days = 30\nhostnames = [\"{}\"]\nextensions = []\n",
            config_key.replace('\\', "\\\\").replace('"', "\\\""),
            safe_name.replace('\\', "\\\\").replace('"', "\\\""),
        );
        let _ = fs::write(
            host_inventory.join(format!("{}.toml", safe_name)),
            host_config,
        );
    }

    let ca_config = CaConfig {
        user_list_file: user_list_path,
        default_user_template: default_path,
        host_inventory,
        ca_key: ca_key_path,
    };

    if let Ok(ca) = CertificateAuthority::new(&ca_config) {
        let server = CaServer::new("fuzz_socket".to_string(), ca, FUZZ_TOKEN.to_string());
        let _ = server.handle_request(auth_req.request);
    }
});
