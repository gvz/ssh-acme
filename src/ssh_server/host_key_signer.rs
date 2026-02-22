//! # Host Key Signer
//!
//! This module handles the `sign_host_key` command, which is used to sign host keys.
use crate::certificat_authority::{CaRequest, CaResponse};
use crate::ssh_server::ConnectionHandler;
use anyhow::Result;
#[cfg(feature = "test_auth")]
use log::warn;
use log::{error, info};
use russh::ChannelId;
use russh::client::{self, Config};
use russh::keys::PublicKey as RusshPublicKey;
use russh::server::Session;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};

pub struct ClientHandler {
    sender: Arc<Mutex<Option<oneshot::Sender<RusshPublicKey>>>>,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &RusshPublicKey,
    ) -> Result<bool, Self::Error> {
        let sender_option = self.sender.lock().await.take();
        if let Some(sender) = sender_option {
            let _ = sender.send(server_public_key.clone());
        }
        Ok(true)
    }
}

/// Handles the `sign_host_key` command.
///
/// This function takes the public key from the command arguments, sends it to the CA to be signed,
/// and returns the signed certificate to the user.
///
/// # Arguments
///
/// * `handler` - The connection handler.
/// * `channel` - The channel ID.
/// * `args` - The command arguments.
/// * `session` - The SSH session.
pub async fn handle_sign_host_key(
    handler: &mut ConnectionHandler,
    channel: ChannelId,
    args: Vec<&str>,
    session: &mut Session,
) -> Result<(), russh::Error> {
    if args.len() < 2 {
        let error_message = "Usage: sign_host_key <host_name> <public_key>";
        error!("{}: {:?}", &error_message, args);
        let _ = session.disconnect(russh::Disconnect::ByApplication, error_message, "en");
        return Ok(());
    }
    let host_name = args[0].to_string();
    let ssh_key = args[1..].join(" ");
    let public_key = match crate::certificat_authority::key_from_openssh(&ssh_key) {
        Err(e) => {
            let error_message = format!("failed to read openssh public key: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Ok(key) => key,
    };

    // Convert ssh_key::PublicKey to russh::keys::PublicKey for comparison
    let public_key_russh = RusshPublicKey::from_openssh(&public_key.to_openssh().unwrap()).unwrap();

    // Proof of concept: Connect to the host and verify the public key
    let (sender, receiver) = oneshot::channel();
    let client_config = Config::default();
    let sh = ClientHandler {
        sender: Arc::new(tokio::sync::Mutex::new(Some(sender))),
    };

    #[cfg(feature = "test_auth")]
    let host_port = format!("localhost:2225",);
    #[cfg(feature = "test_auth")]
    warn!("test host verification");

    info!(
        "host {} requested signing of host key for host: {}",
        handler.username.as_ref().unwrap(),
        host_name
    );

    let cert = match handler
        .server
        .ca_client
        .send_request(&CaRequest::SignHostCertificate {
            host_name: host_name.clone(),
            public_key: public_key.clone(),
        })
        .await
    {
        Ok(CaResponse::SignedCertificate(cert)) => cert,
        Ok(CaResponse::Error(e)) => {
            let error_message = format!("CA server error: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Err(e) => {
            let error_message = format!("Failed to send request to CA server: {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
        Ok(CaResponse::KeyFound(_)) => {
            panic!("Signing request replied with KeyFound, which must not happen")
        }
    };
    let openssh_cert = match cert.to_openssh() {
        Ok(cert) => cert,
        Err(e) => {
            let error_message = format!("failed to concert cert to openssh format : {}", e);
            error!("{}", &error_message);
            let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
            return Ok(());
        }
    };

    //send data back and close connection
    let _ = session.data(channel, openssh_cert.into());
    let _ = session.exit_status_request(channel, 0);
    let _ = session.eof(channel);
    let _ = session.close(channel);
    Ok(())
}
