use std::fs::File;
use std::io::Write;

#[macro_use]
extern crate afl;

use once_cell::sync::Lazy;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, private::PrivateKey};
use tempfile::tempdir;
use tokio::runtime::Runtime;

use ssh_ca_server::certificat_authority::CaRequest;
use ssh_ca_server::certificat_authority::CertificateAuthority;
use ssh_ca_server::certificat_authority::ca_server::CaServer;
use ssh_ca_server::certificat_authority::config::Ca as CaConfig;

fn main() {
    let ca = setup_ca();
    fuzz!(|request: CaRequest| {
        let _ = ca.handle_request(request);
    });
}

fn setup_ca() -> CaServer {
    let temp_dir = tempdir().expect("Failed to create temporary directory");

    let ca_private_key_path = temp_dir.path().join("ca_key");

    // Generate a dummy CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut ca_private_key_file = File::create_new(&ca_private_key_path).unwrap();
    ca_private_key_file
        .write_all(
            ca_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    //user list
    let user_list_path = temp_dir.path().join("user.toml");
    let user_list = format!(
        r#"
        [users]
        test="./user_template.toml"
        test2="./test2_user_template.toml"
        "#,
    );
    std::fs::write(&user_list_path, user_list).expect("Failed to write user list file");
    //default template
    let default_path = temp_dir.path().join("default_template.toml");
    let default_template = format!(
        r#"
        validity_in_days=7
        principals=[
        "{{user}}"
        ]
        extensions=[
        "permit-x11-forwarding",
        "permit-pty",
        "permit-user-rc",
        "permit-agent-forwarding"
        ]

        [critical_options]
        "#,
    );
    std::fs::write(&default_path, default_template).expect("Failed to write default template file");

    //user template
    let user_path = temp_dir.path().join("user_template.toml");
    let user_template = format!(
        r#"
        validity_in_days=7
        principals=[
        "{{user}}"
        ]
        extensions=[
        "permit-x11-forwarding",
        "permit-pty",
        "permit-user-rc",
        "permit-agent-forwarding"
        ]

        [critical_options]
        "#,
    );
    std::fs::write(&user_path, user_template).expect("Failed to write user template file");

    //host cert template
    let host_cert_path = temp_dir.path().join("host_cert_template.toml");
    let host_cert_template = format!(
        r#"
        validity_in_days=7
        principals=[
        "{{host_name}}"
        ]
        extensions=[
        "no-port-forwarding",
        "no-agent-forwarding",
        "no-pty",
        "no-user-rc",
        "no-x11-forwarding"
        ]

        [critical_options]
        "#,
    );
    std::fs::write(&host_cert_path, host_cert_template)
        .expect("Failed to write host cert template file");

    let ca_config = CaConfig {
        user_list_file: user_list_path,
        default_user_template: default_path,
        host_cert_template: host_cert_path,
        ca_key: ca_private_key_path,
    };
    let ca = CertificateAuthority::new(&ca_config).unwrap();
    let ca_server = CaServer::new("test_socket".to_string(), ca, "fuzz_token".to_string());

    ca_server
}
