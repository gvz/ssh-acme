//! # Identity Handlers
//!
//! This module provides a pluggable authentication framework for the SSH server.
//! It defines the `UserAuthenticator` trait, which can be implemented by different
//! authentication methods (e.g., PAM).
use anyhow::Result;

use log::error;
use serde::Deserialize;
use thiserror::Error;

pub(super) mod pam_auth;

/// Configuration for the identity handlers.
#[derive(Deserialize, Debug)]
pub(crate) struct IndentityHanderConfig {
    /// A list of enabled user authenticators.
    pub user_authenticators: Vec<String>,
}

/// An error that can occur during authentication.
#[derive(Error, Debug)]
pub(crate) enum Error {
    /// The user is forbidden from logging in.
    #[error("user {0} is forbidden from logging in")]
    ForbiddenUser(String),
}

/// A credential used for authentication.
#[derive(Clone)]
pub(crate) enum Credential<'a> {
    /// A password credential.
    Password(&'a str),
}

/// A trait for authenticating users.
pub(crate) trait UserAuthenticator: Send + Sync {
    /// Authenticates a user with the given credential.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to authenticate.
    /// * `credential` - The credential to use for authentication.
    ///
    /// # Returns
    ///
    /// A `Result` containing `true` if the user is authenticated, `false` otherwise, or an error.
    fn authenticate(&self, username: &str, credential: Credential) -> Result<bool>;
    /// Clones the `UserAuthenticator` into a `Box`.
    fn clone_box(&self) -> Box<dyn UserAuthenticator + Send + Sync>;
}
impl Clone for Box<dyn UserAuthenticator + Send + Sync> {
    fn clone(&self) -> Box<dyn UserAuthenticator + Send + Sync> {
        self.clone_box()
    }
}

/// Sets up the user authenticators based on the configuration.
///
/// # Arguments
///
/// * `enabled_authenticators` - A list of enabled authenticator names.
///
/// # Returns
///
/// A `Result` containing a vector of `UserAuthenticator` instances or an error.
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
