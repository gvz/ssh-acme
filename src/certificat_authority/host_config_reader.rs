//! # Host Defaults Reader
//!
//! This module is responsible for reading and parsing host-specific certificate templates.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Result, anyhow};
use glob::glob;
use log::{debug, error, warn};
use serde::Deserialize;

use crate::certificat_authority::config;

/// Verifies that `candidate` is contained within `base_dir` after canonicalization.
///
/// Both paths are canonicalized to resolve symlinks and `..` components, then
/// `candidate` is checked to be a child of `base_dir`. Returns an error if
/// canonicalization fails or the candidate escapes the base directory.
fn ensure_path_within_directory(candidate: &Path, base_dir: &Path) -> Result<std::path::PathBuf> {
    let canonical_base = base_dir.canonicalize().map_err(|e| {
        error!(
            "failed to canonicalize base directory {:?}: {}",
            base_dir, e
        );
        anyhow!("failed to resolve inventory directory: {}", e)
    })?;
    let canonical_candidate = candidate.canonicalize().map_err(|e| {
        error!(
            "failed to canonicalize candidate path {:?}: {}",
            candidate, e
        );
        anyhow!("failed to resolve host config path: {}", e)
    })?;
    if !canonical_candidate.starts_with(&canonical_base) {
        error!(
            "path traversal detected: {:?} is not within {:?}",
            canonical_candidate, canonical_base
        );
        return Err(anyhow!("path traversal detected in host name"));
    }
    Ok(canonical_candidate)
}

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

    // Verify the resolved path stays within the host inventory directory
    let safe_path = ensure_path_within_directory(&host_inventory_path, &config.host_inventory)?;

    let host_config = read_config(safe_path.to_str().unwrap())?;
    Ok(host_config)
}

/// Searches the host inventory for a configuration whose public key matches the given key.
///
/// Returns `Some((host_name, config))` if a match is found, or `None` otherwise.
pub fn find_config_by_public_key(
    public_key: &str,
    config: &config::Ca,
) -> Option<(String, HostConfig)> {
    // Canonicalize the inventory path before constructing the glob pattern
    // to prevent unsanitized config paths from affecting glob behavior
    let canonical_inventory = match config.host_inventory.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            error!(
                "failed to canonicalize host inventory path {:?}: {}",
                config.host_inventory, e
            );
            return None;
        }
    };
    for file in glob(&format!(
        "{}/**/*.toml",
        canonical_inventory.to_str().unwrap()
    ))
    .unwrap()
    .flatten()
    {
        // Verify each glob result stays within the inventory directory
        // (defense against symlink attacks within the inventory)
        let canonical_file = match file.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                warn!("skipping unresolvable path {:?}: {}", file, e);
                continue;
            }
        };
        if !canonical_file.starts_with(&canonical_inventory) {
            warn!(
                "skipping file outside inventory directory: {:?}",
                canonical_file
            );
            continue;
        }
        debug!("checking for public key in {}", file.to_str().unwrap());
        let host_config = match read_config(file.to_str().unwrap()) {
            Err(e) => {
                error!("could not read {}: {}", file.to_str().unwrap(), e);
                return None;
            }
            Ok(conf) => conf,
        };
        let key_parts: Vec<&str> = host_config.public_key.split_whitespace().collect();
        if key_parts.len() < 2 {
            warn!(
                "skipping malformated key in config {}: {}",
                file.to_str().unwrap(),
                public_key
            );
            continue;
        }
        let formatted_host_key = format!("{} {}", key_parts[0], key_parts[1]);
        if formatted_host_key != public_key {
            debug!(
                "host key not matching for {}: {} != {}",
                host_config.hostnames[0], formatted_host_key, public_key
            );
            continue;
        } else {
            debug!(
                "host for public key found: {}",
                host_config.hostnames.first().unwrap()
            );
            let file_stem = file.file_stem().unwrap().to_str().unwrap().to_string();
            return Some((file_stem, host_config));
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
