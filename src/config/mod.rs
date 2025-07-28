//! # Configuration
//!
//! This module handles the reading and parsing of the main configuration file.
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::certificat_authority::config::Ca;
use crate::identiy_handlers::IndentityHanderConfig;
use crate::ssh_server::config::SshServerConfig;

/// The main configuration for the SSH ACME server.
#[derive(Deserialize, Debug)]
pub struct Config {
    /// The SSH server configuration.
    pub ssh: SshServerConfig,
    /// The Certificate Authority (CA) configuration.
    pub ca: Ca,
    /// The identity handler configuration.
    pub identity_handlers: IndentityHanderConfig,
}

/// A trait for inserting the configuration root path into a configuration struct.
///
/// This is used to resolve relative paths in the configuration.
pub(crate) trait InsertConfigRoot {
    /// Inserts the configuration root path into the configuration struct.
    ///
    /// # Arguments
    ///
    /// * `config_root` - The root path of the configuration file.
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()>;
    /// Checks if the paths in the configuration are valid.
    fn check_paths(&self) -> Result<()>;
}

/// Reads and parses the main configuration file.
///
/// # Arguments
///
/// * `file_path` - The path to the configuration file.
///
/// # Returns
///
/// A `Result` containing the parsed `Config` or an error.
pub fn read_config(file_path: &str) -> Result<Config> {
    let config_path: PathBuf = PathBuf::from(file_path);
    let config_root = match config_path.exists() {
        false => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Config file {} not found", file_path),
            )
            .into());
        }
        true => config_path.parent().unwrap().to_path_buf(),
    };

    let mut config_file = File::open(file_path)?;
    let mut config = String::new();
    let _ = config_file.read_to_string(&mut config)?;

    let mut config: Config = toml::from_str(&config)?;
    let _ = config.ca.insert_config_path(&config_root);
    config.ca.check_paths()?;

    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn read_config_test() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_key");
        let mut key_file = File::create(&key_path).unwrap();
        key_file.write_all(b"test key data").unwrap();

        let config_path = dir.path().join("config.toml");
        let mut config_file = File::create(&config_path).unwrap();
        let config_content = format!(
            r#"
[ssh]
bind = "127.0.0.1"
port = 2222
private_key = "/etc/ssh/ssh_host_ed25519_key"

[ca]
ca_key = "{}"
certificate_validity_days = 30
user_list_file="../test_data/test_key"
default_user_template="../test_data/test_key"
host_cert_template="../test_data/test_key"

[identity_handlers]
user_authenticators = ["pam"]
"#,
            key_path.to_str().unwrap()
        );
        config_file.write_all(config_content.as_bytes()).unwrap();

        let config = read_config(config_path.to_str().unwrap()).unwrap();
        println!("config: {:?}", config);
    }
}
