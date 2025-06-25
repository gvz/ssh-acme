use std::io;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::config::InsertConfigRoot;

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct SshServerConfig {
    pub bind: String,
    pub port: u16,
    pub private_key: String,
}

impl InsertConfigRoot for SshServerConfig {
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()> {
        let mut ca_key_path = config_root.clone();
        if !PathBuf::from(&self.private_key).has_root() {
            ca_key_path.push(&self.private_key);
            self.private_key = ca_key_path.to_string_lossy().to_string();
        }
        Ok(())
    }

    fn check_paths(&self) -> Result<()> {
        let path = PathBuf::from(&self.private_key);
        if path.exists() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CA key file {} not found", self.private_key),
            )
            .into())
        }
    }
}
