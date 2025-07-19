use anyhow::Result;
use log::warn;
use pam::Client;

use crate::identiy_handlers::{Credential, Error, UserAuthenticator, credentinal_type_name};

/// A `UserAuthenticator` that uses PAM to authenticate users.
#[derive(Clone)]
pub(super) struct PamAuthenticator {}
impl UserAuthenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, credential: Credential) -> Result<bool> {
        match credential {
            Credential::Password(password) => pam_authenticate_user(username, password),
            other => Err(Error::CredentialNotSupported(
                credentinal_type_name(other).to_string(),
                "PamAuthenticator".to_string(),
            )
            .into()),
        }
    }
    fn clone_box(&self) -> Box<dyn UserAuthenticator + Send + Sync> {
        Box::new(self.clone())
    }
}

/// Authenticates a user using PAM.
///
/// # Arguments
///
/// * `user` - The username to authenticate.
/// * `password` - The password to use for authentication.
///
/// # Returns
///
/// A `Result` containing `true` if the user is authenticated, `false` otherwise, or an error.
pub fn pam_authenticate_user(user: &str, password: &str) -> Result<bool> {
    let forbidden_users = vec!["root"];
    for bad_user in forbidden_users {
        if user == bad_user {
            warn!("forbidden user was provided: {}", user);
            return Err(Error::ForbiddenUser(user.to_string()).into());
        }
    }

    let mut auth = Client::with_password("login")?;
    auth.conversation_mut().set_credentials(user, password);

    auth.authenticate()?;
    auth.open_session()?;
    Ok(true)
}
