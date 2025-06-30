use std::time::Duration;
use tempfile::tempdir;
use tokio::time::sleep;
use tokio::process::{Command, Child};

#[tokio::test]
async fn test_server_startup() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let config_path = temp_dir.path().join("config.toml");
    let ca_key_path = temp_dir.path().join("ca_key.pem");

    // Generate a dummy CA key
    Command::new("ssh-keygen")
        .arg("-t")
        .arg("rsa")
        .arg("-b")
        .arg("2048")
        .arg("-f")
        .arg(&ca_key_path)
        .arg("-N")
        .arg("") // No passphrase
        .output().await
        .expect("Failed to generate CA key");

    // Write a minimal config file
    let config_content = format!(
        r#"
        [ssh]
        host_key_dir = "{}/host_keys"
        listen_address = "0.0.0.0:2222"
        bind = "127.0.0.1:2222"
        port = 2222
        private_key = "{}/host_keys/ssh_host_rsa_key"

        [ca]
        ca_key = "{}"
        certificate_validity_days = 30

        [identity_handlers]
        user_authenticators = []
        "#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        ca_key_path.to_str().unwrap()
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config file");

    // Create host_keys directory
    let host_keys_dir = temp_dir.path().join("host_keys");
    std::fs::create_dir_all(&host_keys_dir).expect("Failed to create host_keys directory");

    // Generate a dummy host key
    let host_key_path = host_keys_dir.join("ssh_host_rsa_key");
    Command::new("ssh-keygen")
        .arg("-t")
        .arg("rsa")
        .arg("-b")
        .arg("2048")
        .arg("-f")
        .arg(&host_key_path)
        .arg("-N")
        .arg("") // No passphrase
        .output().await
        .expect("Failed to generate host key");


    let mut command = Command::new(env!("CARGO_BIN_EXE_ssh_acme_server"));
    command
        .arg("-c")
        .arg(&config_path);

    let mut child: Child = command.spawn().expect("Failed to start server");

    // Give the server some time to start up
    sleep(Duration::from_secs(10)).await;

    // Check if the CA socket file exists (this is a proxy for server startup)
    let socket_path = format!("/tmp/ssh_acme_ca.{}.sock", child.id().expect("Failed to get child process ID"));
    let socket_file_exists = std::path::Path::new(&socket_path).exists();

    // Kill the child process
    child.kill().await.expect("Failed to kill server process");
    child.wait().await.expect("Failed to wait for server process");

    // Clean up the socket file
    let _ = std::fs::remove_file(&socket_path);

    assert!(socket_file_exists, "CA socket file was not created, indicating server did not start.");
}
