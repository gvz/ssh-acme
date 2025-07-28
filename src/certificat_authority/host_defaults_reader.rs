//! # Host Defaults Reader
//!
//! This module is responsible for reading and parsing host-specific certificate templates.

use std::fs::File;
use std::io::Read;

use anyhow::Result;
use log::error;
use minijinja::{context, Environment};
use serde::Deserialize;

use crate::certificat_authority::config;

/// Represents the host-specific certificate parameters.
#[derive(Deserialize, Debug)]
pub struct HostDefaults {
    /// The validity period of the certificate in days.
    pub validity_in_days: u16,
    /// A list of principals (e.g., hostnames) to be included in the certificate.
    pub principals: Vec<String>,
    /// A list of extensions to be included in the certificate.
    pub extensions: Vec<String>,
    
}

/// Reads and parses the host-specific certificate template for a given host.
///
/// It uses Jinja2 to render the template with the hostname and parses the
/// result as a `HostDefaults` struct.
///
/// # Arguments
///
/// * `host_name` - The hostname for which to read the defaults.
/// * `config` - The CA configuration containing the path to the host template.
///
/// # Returns
///
/// A `Result` containing the `HostDefaults` for the host or an error.
pub fn read_host_defaults(host_name: &str, config: &config::Ca) -> Result<HostDefaults> {
    let template_path = config.host_cert_template.clone();

    let mut template_file = File::open(&template_path).map_err(|e| {
        error!("failed to open host template, {:?}: {}", &template_path, e);
        e
    })?;
    let mut template_text = String::new();
    let _ = template_file
        .read_to_string(&mut template_text)
        .map_err(|e| {
            error!("failed to read host template, {:?}: {}", &template_path, e);
            e
        })?;
    let mut jinja_env = Environment::new();
    jinja_env.add_template(host_name, &template_text)?;
    let host_template = jinja_env.get_template(host_name)?;
    let host_defaults = host_template.render(context!(host_name => host_name))?;

    let template: HostDefaults = toml::from_str(&host_defaults)?;

    Ok(template)
}