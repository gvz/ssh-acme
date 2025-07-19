//! # CA Configuration
//!
//! This module defines the configuration structures for the Certificate Authority (CA).
use std::io;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::config::InsertConfigRoot;

/// Configuration for the Certificate Authority.
#[derive(Deserialize, Debug, Clone)]
pub struct Ca {
    /// The path to the file containing the list of authorized users.
    pub user_list_file: PathBuf,
    /// The path to the default user template file.
    pub default_user_template: PathBuf,
    /// The path to the CA's private key.
    pub ca_key: PathBuf,
}

impl InsertConfigRoot for Ca {
    /// Inserts the configuration root path into the CA configuration.
    ///
    /// This function is used to resolve relative paths in the configuration.
    ///
    /// # Arguments
    ///
    /// * `config_root` - The root path of the configuration file.
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

    /// Checks if the paths in the CA configuration are valid.
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
