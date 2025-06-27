use std::fs::File;
use std::io::Read;
use std::time::Duration;
use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;
use toml;

#[derive(Deserialize, Debug)]
pub struct UserDefaults {
    pub validity: Duration,
    pub principals: Vec<String>,
    pub extensions: Vec<String>,
    pub critical_options: HashMap<String, String>,
}

pub fn read_user_defaults(file_path: &str) -> Result<UserDefaults> {
    let mut config_file = File::open(file_path)?;
    let mut config_text = String::new();
    let _ = config_file.read_to_string(&mut config_text)?;

    let config: UserDefaults = toml::from_str(&config_text)?;

    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_user_defaults_test() {
        let config = read_user_defaults("./config/user_default.toml").unwrap();
        println!("{:?}", config.validity);
    }
}
