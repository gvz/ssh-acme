use log::{debug, error, info, warn};
use pam::Client;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PamError {
    #[error("User {0} is forbidden from logging in")]
    ForbiddenUser(String),
}

pub fn pam_authenticate_user(
    user: &str,
    password: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let forbidden_users = vec!["root"];
    for bad_user in forbidden_users {
        if user == bad_user {
            warn!("forbidden user was provided: {}", user);
            return Err(PamError::ForbiddenUser(user.to_string()).into());
        }
    }

    let mut auth = Client::with_password("login")?;
    auth.conversation_mut().set_credentials(user, password);

    match auth.authenticate() {
        Ok(_) => Ok(true),
        Err(e) => Err(Box::new(e)),
    }
}
