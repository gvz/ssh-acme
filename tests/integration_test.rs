use async_trait::async_trait;
use env_logger;
use russh::Error;
use russh::client::{AuthResult, Config, Handler, Session};
use ssh_key::public::PublicKey;
use ssh_key::rand_core::OsRng;
use ssh_key::{
    Algorithm, Certificate,
    private::{Ed25519Keypair, PrivateKey},
};
use std::env::{self, temp_dir};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use clap::Parser;
use log::{debug, error, info, log};
use ssh_acme_server::{CliArgs, run_server};

#[derive(Clone)]
struct ClientHandler;

impl Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Always accept the server's key (not safe for production!)
        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _extended: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let openssh_cert = String::from_utf8_lossy(data).to_string();
        info!("got certificate: {}", openssh_cert);
        let _cert = Certificate::from_openssh(&openssh_cert).unwrap();

        Ok(())
    }
}

#[tokio::test]
async fn test_server_startup() {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let config_path = temp_dir.path().join("config.toml");
    let ca_private_key_path = temp_dir.path().join("ca_key");

    // Generate a dummy CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut ca_private_key_file = File::create_new(&ca_private_key_path).unwrap();
    ca_private_key_file.write_all(
        ca_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    );

    // Create host_keys directory
    let host_keys_dir = temp_dir.path().join("host_keys");
    std::fs::create_dir_all(&host_keys_dir).expect("Failed to create host_keys directory");

    // Generate a dummy host key
    let host_key_path = host_keys_dir.join("ssh_host_rsa_key");
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut host_private_key_file = File::create_new(host_key_path).unwrap();
    host_private_key_file.write_all(
        ca_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    );
    // Generate a dummy host key
    let mut user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    user_key.set_comment("integration_test_user@test.com");

    let user_public_key = user_key.public_key().to_openssh().unwrap();

    let socket_path = temp_dir.path().join("ca_socket");

    // Write a minimal config file
    let config_content = format!(
        r#"
        [ssh]
        host_key_dir = "{}/host_keys"
        bind = "127.0.0.1"
        port = 2223
        private_key = "{}/host_keys/ssh_host_rsa_key"

        [ca]
        ca_key = "{}"
        certificate_validity_days = 30
        user_list_file="{}/user.toml"
        default_user_template="{}/default_template.toml"

        [identity_handlers]
        user_authenticators = []
        "#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        ca_private_key_path.to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
    );
    info!("{}", config_content);
    std::fs::write(&config_path, config_content).expect("Failed to write config file");

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

    info!("start SSH");
    let ssh_args = CliArgs::parse_from(
        [
            "-c",
            "--config-file",
            &config_path.as_os_str().to_str().unwrap(),
            "--disable-ca",
            "-s",
            &socket_path.as_os_str().to_str().unwrap(),
        ]
        .iter(),
    );
    debug!("ssh_args: {:?}", ssh_args);
    let ssh_server = tokio::spawn(async move { run_server(ssh_args).await });

    info!("start CA");
    let ca_args = CliArgs::parse_from(
        [
            "-c",
            "--config-file",
            &config_path.as_os_str().to_str().unwrap(),
            "-a",
            "-s",
            &socket_path.as_os_str().to_str().unwrap(),
        ]
        .iter(),
    );

    debug!("ca_args: {:?}", ca_args);
    let ca_server = tokio::spawn(async move { run_server(ca_args).await });

    info!("waiting for 10s");

    // Give the server some time to start up
    sleep(Duration::from_secs(1)).await;

    info!("attempting connect");
    // Attempt to connect with a client
    let config = Config::default();
    let config = Arc::new(config);
    let sh = ClientHandler;
    let mut session = russh::client::connect(config, ("127.0.0.1", 2223), sh)
        .await
        .expect("Failed to connect to server");

    let auth = session
        .authenticate_password("test", "test")
        .await
        .expect("Failed to authenticate to server");
    assert_eq!(auth, AuthResult::Success);

    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    // send public key to server
    channel.data(user_public_key.as_bytes()).await.unwrap();
    channel.wait().await.unwrap();

    // You can add more client interactions here if needed
    session
        .disconnect(russh::Disconnect::ByApplication, "Test complete", "en")
        .await
        .expect("Failed to disconnect client");
    ca_server.abort();
    ssh_server.abort();
}
