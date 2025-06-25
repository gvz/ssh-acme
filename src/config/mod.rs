use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::{collections::HashMap, hash::Hash};

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
    config.ca.insert_config_path(&config_root);
    config.ca.check_paths()?;

    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_config_test() {
        let config = read_config("./config/config.toml").unwrap();
        println!("config: {:?}", config);
    }
}
