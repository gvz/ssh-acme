use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Deserializer};
use toml;

fn deserialize_duration_from_string<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    humantime::parse_duration(&s).map_err(serde::de::Error::custom)
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct UserDefaults {
    #[serde(deserialize_with = "deserialize_duration_from_string")]
    pub validity: Duration,
    pub principals: Vec<String>,
    pub extensions: Vec<String>,
    pub critical_options: HashMap<String, String>,
}

#[allow(dead_code)]
pub fn read_user_defaults(file_path: &str) -> Result<UserDefaults> {
    let mut config_file = File::open(file_path)?;
    let mut config_text = String::new();
    config_file.read_to_string(&mut config_text)?;

    let config: UserDefaults = toml::from_str(&config_text)?;

    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_user_defaults_test() {
        let config = read_user_defaults("./config/user_default.toml").unwrap();
        assert_eq!(config.validity.as_secs(), 7 * 24 * 60 * 60);
        println!("{:?}", config.validity);
    }
}
