use std::fs::File;
use std::io::Read;
use std::{collections::HashMap, hash::Hash};

use anyhow::Result;
use minijinja::{Environment, context};
use serde::Deserialize;
use toml;

#[derive(Deserialize, Debug)]
pub struct CertificateConfig {
    pub cert_type: String,
    pub key_id: u64,
    pub principals: Vec<String>,
    pub extensions: HashMap<String, String>,
    pub critical_options: HashMap<String, String>,
    pub validity_span_h: u32,
}

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
