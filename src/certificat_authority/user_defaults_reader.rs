//! # User Defaults Reader
//!
//! This module is responsible for reading and parsing user-specific certificate templates.
//! It uses a combination of TOML and Jinja2 templates to allow for dynamic generation
//! of certificate parameters based on the user.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use log::error;
use minijinja::{Environment, context};
use serde::Deserialize;

use crate::certificat_authority::config;

/// Represents the user-specific certificate parameters.
#[derive(Deserialize, Debug)]
pub struct UserDefaults {
    /// The validity period of the certificate in days.
    pub validity_in_days: u16,
    /// A list of principals (e.g., usernames) to be included in the certificate.
    pub principals: Vec<String>,
    /// A list of extensions to be included in the certificate.
    pub extensions: Vec<String>,
}
#[derive(Deserialize, Debug)]
struct UserList {
    pub users: HashMap<String, PathBuf>,
}

/// Reads and parses the user-specific certificate template for a given user.
///
/// It first reads the user list file to find the template for the specified user.
/// If no specific template is found, it uses the default template.
/// It then uses Jinja2 to render the template with the username and parses the
/// result as a `UserDefaults` struct.
///
/// # Arguments
///
/// * `user` - The username for which to read the defaults.
/// * `config` - The CA configuration containing the paths to the user list and default template.
///
/// # Returns
///
/// A `Result` containing the `UserDefaults` for the user or an error.
pub fn read_user_defaults(user: &str, config: &config::Ca) -> Result<UserDefaults> {
    let mut user_list_file = File::open(config.user_list_file.clone()).map_err(|e| {
        error!(
            "failed to open user list, {:?}: {}",
            &config.user_list_file, e
        );
        e
    })?;
    let mut user_list = String::new();
    let _ = user_list_file.read_to_string(&mut user_list).map_err(|e| {
        error!(
            "failed to read user list, {:?}: {}",
            &config.user_list_file, e
        );
        e
    })?;
    let user_file_map: UserList = toml::from_str(&user_list).map_err(|e| {
        error!("failed to parse user list form toml: {}", e);
        e
    })?;

    // use specified config for user or defaut if user has no defaults defined
    let template_path = match user_file_map.users.get(user) {
        Some(path) => {
            println!("{:?}", path);
            if path.is_relative() {
                let user_file_path = config.user_list_file.to_path_buf();
                let template_path = match user_file_path.parent() {
                    None => panic!("user list file does not have parent: {:?}", user_file_path),
                    Some(path) => path,
                };
                template_path.join(path)
            } else {
                path.to_path_buf()
            }
        }
        None => config.default_user_template.clone(),
    };

    let mut template_file = File::open(&template_path).map_err(|e| {
        error!("failed to open user template, {:?}: {}", &template_path, e);
        e
    })?;
    let mut template_text = String::new();
    let _ = template_file
        .read_to_string(&mut template_text)
        .map_err(|e| {
            error!("failed to read user template, {:?}: {}", &template_path, e);
            e
        })?;
    let mut jinja_env = Environment::new();
    jinja_env.add_template(user, &template_text)?;
    let user_template = jinja_env.get_template(user)?;
    let user_defaults = user_template.render(context!(user_name => user))?;

    let template: UserDefaults = toml::from_str(&user_defaults)?;

    Ok(template)
}

#[cfg(test)]
mod test {
    use super::*;
    use ssh_key::Algorithm;
    use ssh_key::private::PrivateKey;
    use ssh_key::rand_core::OsRng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn read_user_defaults_test() {
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut ca_key_file = NamedTempFile::new().unwrap();
        ca_key_file.write_all(ca_key_openssh.as_bytes()).unwrap();
        ca_key_file.flush().unwrap();
        let ca_key_path = ca_key_file.path();
        let ca_config = config::Ca {
            user_list_file: PathBuf::from("./config/user.toml"),
            default_user_template: PathBuf::from("./config/user_default.toml"),
            ca_key: ca_key_path.to_path_buf(),
            host_inventory: PathBuf::from("./config/hosts"),
        };
        let config = read_user_defaults("test", &ca_config).unwrap();
        println!("{:?}", config.validity_in_days);
    }
}
