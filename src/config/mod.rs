use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;
use toml;

use crate::certificat_authority::config::Ca;
use crate::identiy_handlers::IndentityHanderConfig;
use crate::ssh_server::config::SshServerConfig;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub ssh: SshServerConfig,
    pub ca: Ca,
    pub identity_handlers: IndentityHanderConfig,
}

pub(crate) trait InsertConfigRoot {
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()>;
    fn check_paths(&self) -> Result<()>;
}

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
