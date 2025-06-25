use anyhow::Result;
use ssh_key::PublicKey;

use log::error;
use serde::Deserialize;
use thiserror::Error;

pub(super) mod pam_auth;

#[derive(Deserialize, Debug)]
pub(crate) struct IndentityHanderConfig {
    pub user_authenticators: Vec<String>,
}

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("user {0} is forbidden from logging in")]
    ForbiddenUser(String),
    #[error("Credential type {0} not supported by {1}")]
    CredentialNotSupported(String, String),
}
#[derive(Clone)]
pub(crate) enum Credential<'a> {
    Password(&'a str),
    PublicKey(&'a PublicKey),
}

fn credentinal_type_name(credential: Credential) -> &str {
    match credential {
        Credential::Password(_) => "Password",
        Credential::PublicKey(_) => "PublicKey",
    }
}

pub(crate) trait UserAuthenticator: Send + Sync {
    fn authenticate(&self, username: &str, credential: Credential) -> Result<bool>;
    fn clone_box(&self) -> Box<dyn UserAuthenticator + Send + Sync>;
}
impl Clone for Box<dyn UserAuthenticator + Send + Sync> {
    fn clone(&self) -> Box<dyn UserAuthenticator + Send + Sync> {
        self.clone_box()
    }
}

pub(crate) fn setup_user_authenticators(
    enabled_authenticators: Vec<String>,
) -> Result<Vec<Box<dyn UserAuthenticator + Send + Sync>>> {
    let mut authenticators: Vec<Box<dyn UserAuthenticator + Send + Sync>> = Vec::new();
    for authenticator in enabled_authenticators {
        match authenticator.as_str() {
            "pam" => authenticators.push(Box::new(pam_auth::PamAuthenticator {})),
            other => {
                error!("unknown user authenticator: {}", other);
                panic!("unknown user authenticator: {}", other);
            }
        }
    }
    Ok(authenticators)
}
