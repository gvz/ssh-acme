//! # Host Defaults Reader
//!
//! This module is responsible for reading and parsing host-specific certificate templates.

use std::fs::File;
use std::io::Read;

use anyhow::Result;
use glob::glob;
use log::{debug, error};
use serde::Deserialize;

use crate::certificat_authority::config;

/// Represents the host-specific certificate parameters.
#[derive(Deserialize, Debug)]
pub struct HostConfig {
    /// Hosts public key
    pub public_key: String,
    /// The validity period of the certificate in days.
    pub validity_in_days: u16,
    /// A list of principals (e.g., hostnames) to be included in the certificate.
    pub hostnames: Vec<String>,
    /// A list of extensions to be included in the certificate.
    pub extensions: Vec<String>,
}

/// Reads and parses the host-specific certificate template for a given host.
///
/// # Arguments
///
/// * `host_name` - The hostname for which to read the defaults.
/// * `config` - The CA configuration containing the path to the host template.
///
/// # Returns
///
/// A `Result` containing the `HostConfig` for the host or an error.
pub fn read_host_config(host_name: &str, config: &config::Ca) -> Result<HostConfig> {
    let mut host_inventory_path = config.host_inventory.clone();
    host_inventory_path.push(format!("{}.toml", host_name));
    let host_config = read_config(host_inventory_path.to_str().unwrap())?;
    Ok(host_config)
}

pub fn find_config_by_public_key(public_key: &str, config: &config::Ca) -> Option<HostConfig> {
    for file in glob(&format!(
        "{}/**/*.toml",
        config.host_inventory.to_str().unwrap()
    ))
    .unwrap()
    .flatten()
    {
        debug!("checking for public key in {}", file.to_str().unwrap());
        let host_config = match read_config(file.to_str().unwrap()) {
            Err(e) => {
                error!("could not read {}: {}", file.to_str().unwrap(), e);
                return None;
            }
            Ok(conf) => conf,
        };
        if host_config.public_key != public_key {
            debug!(
                "host key not matching for {}: {} != {}",
                host_config.hostnames[0], host_config.public_key, public_key
            );
            continue;
        } else {
            debug!(
                "host for public key found: {}",
                host_config.hostnames.first().unwrap()
            );
            return Some(host_config);
        }
    }
    None
}

fn read_config(file: &str) -> Result<HostConfig> {
    let mut config_file = match File::open(&file).map_err(|e| {
        error!("failed to open host inventory, {:?}: {}", &file, e);
        e
    }) {
        Err(e) => {
            error!("failed to read {}: {}", file, e);
            return Err(e.into());
        }
        Ok(config_file) => config_file,
    };
    let mut config_text = String::new();
    let _ = match config_file.read_to_string(&mut config_text).map_err(|e| {
        error!("failed to read host template, {:?}: {}", &file, e);
        e
    }) {
        Err(e) => {
            error!("failed to read to string {}: {}", config_text, e);
            return Err(e.into());
        }
        Ok(_) => {}
    };
    let config: HostConfig = toml::from_str(&config_text)?;

    Ok(config)
}
