//! # SSH Server Configuration
//!
//! This module defines the configuration for the SSH server.
use std::io;
use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;

use crate::config::InsertConfigRoot;

/// Configuration for the SSH server.
#[derive(Deserialize, Debug, Clone)]
pub(crate) struct SshServerConfig {
    /// The address to bind the SSH server to.
    pub bind: String,
    /// The port to bind the SSH server to.
    pub port: u16,
    /// The path to the server's private key.
    pub private_key: String,
}

impl InsertConfigRoot for SshServerConfig {
    /// Inserts the configuration root path into the SSH server configuration.
    ///
    /// This function is used to resolve relative paths in the configuration.
    ///
    /// # Arguments
    ///
    /// * `config_root` - The root path of the configuration file.
    fn insert_config_path(&mut self, config_root: &PathBuf) -> Result<()> {
        let mut ca_key_path = config_root.clone();
        if !PathBuf::from(&self.private_key).has_root() {
            ca_key_path.push(&self.private_key);
            self.private_key = ca_key_path.to_string_lossy().to_string();
        }
        Ok(())
    }

    /// Checks if the paths in the SSH server configuration are valid.
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
