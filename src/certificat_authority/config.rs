use std::io;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::config::InsertConfigRoot;

#[derive(Deserialize, Debug, Clone)]
pub struct Ca {
    pub user_list_file: PathBuf,
    pub default_user_template: PathBuf,
    pub ca_key: PathBuf,
}

impl InsertConfigRoot for Ca {
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()> {
        if !&self.ca_key.has_root() {
            let mut ca_key_path = config_root.clone();
            ca_key_path.push(&self.ca_key);
            self.ca_key = ca_key_path;
        }
        if !&self.default_user_template.has_root() {
            let mut ca_key_path = config_root.clone();
            ca_key_path.push(&self.default_user_template);
            self.default_user_template = ca_key_path;
        }
        if !&self.user_list_file.has_root() {
            let mut ca_key_path = config_root.clone();
            ca_key_path.push(&self.user_list_file);
            self.user_list_file = ca_key_path;
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
                format!("CA key file {:?} not found", self.ca_key),
            )
            .into())
        }
    }
}
