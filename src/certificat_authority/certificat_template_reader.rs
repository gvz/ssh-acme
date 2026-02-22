use std::fs::File;
use std::io::Read;
use std::{collections::HashMap, hash::Hash};

use anyhow::Result;
use minijinja::{Environment, context};
use serde::Deserialize;
use toml;

/// Parsed certificate configuration from a Jinja-templated TOML file.
#[derive(Deserialize, Debug)]
pub struct CertificateConfig {
    /// The certificate type (e.g. "user" or "host").
    pub cert_type: String,
    /// A unique key identifier assigned by the CA.
    pub key_id: u64,
    /// A list of principals (usernames or hostnames) for the certificate.
    pub principals: Vec<String>,
    /// Extensions to include in the certificate (key-value pairs).
    pub extensions: HashMap<String, String>,
    /// Critical options to include in the certificate (key-value pairs).
    pub critical_options: HashMap<String, String>,
    /// The validity span of the certificate in hours.
    pub validity_span_h: u32,
}

/// Reads and parses a certificate configuration from a Jinja-templated TOML file.
///
/// # Arguments
///
/// * `file_path` - Path to the TOML template file.
///
/// # Returns
///
/// A `Result` containing the parsed [`CertificateConfig`] or an error.
pub fn read_certificate_config(file_path: &str) -> Result<CertificateConfig> {
    let mut config_file = File::open(file_path)?;
    let mut config = String::new();
    let _ = config_file.read_to_string(&mut config)?;

    let mut env = Environment::new();
    env.add_template("config", &config).unwrap();
    let tmpl = env.get_template("config").unwrap();
    let mut critical_options: HashMap<String, String> = HashMap::new();
    critical_options.insert("test".to_string(), "map".to_string());
    let json = tmpl
        .render(context!(
        KeyID => 200,
        Principals => vec!("test", "list"),
        CriticalOptions => critical_options,
        ValiditySpan => 24*30
        ))
        .unwrap();

    let config: CertificateConfig = toml::from_str(&json)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_cert_config_test() {
        let config = read_certificate_config("./test_data/user_cert_config.toml").unwrap();
        println!("config: {:?}", config);
    }
}
