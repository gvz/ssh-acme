use log::{debug, error, info, warn};
use std::io::Write;
use std::process::{Command, Stdio};
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
    let mut child = Command::new("sudo")
        .args(&["-S", "-u", user, "echo", "SUCCESS"]) // -S for stdin password, -u for user
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        writeln!(stdin, "{}", password)?;
    }

    let output = child.wait_with_output()?;
    info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    info!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim() == "SUCCESS" {
        info!("found success marker");
        Ok(true)
    } else {
        info!("NOT found success marker");
        Ok(false)
    }
}
