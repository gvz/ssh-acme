use std::io;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::config::InsertConfigRoot;

#[derive(Deserialize, Debug)]
pub struct Ca {
    pub ca_key: String,
}

impl InsertConfigRoot for Ca {
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()> {
        let mut ca_key_path = config_root.clone();
        if !PathBuf::from(&self.ca_key).has_root() {
            ca_key_path.push(&self.ca_key);
            self.ca_key = ca_key_path.to_string_lossy().to_string();
        }
        Ok(())
    }

    fn check_paths(&self) -> Result<()> {
        let path = PathBuf::from(&self.ca_key);
        if path.exists() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CA key file {} not found", self.ca_key),
            )
            .into())
        }
    }
}
