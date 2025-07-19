//! # SSH ACME Server
//!
//! This module provides the core SSH server implementation.
//! It handles client connections, authentication, and the process of
//! receiving a public key, forwarding it to the CA for signing, and
//! returning the signed certificate to the user.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use log::{debug, error, info, warn};
use russh::{
    Channel, ChannelId,
    server::{Auth, Handler, Msg, Server, Session},
};
use tokio::sync::Mutex;

use crate::certificat_authority::{self, CaRequest, CaResponse, ca_client::CaClient};
use crate::identiy_handlers::{Credential, UserAuthenticator};

pub(crate) mod config;
use config::SshServerConfig;

/// The main SSH ACME server struct.
///
/// This struct holds the state for the SSH server, including connected clients,
/// the CA client, the server configuration, and the list of user authenticators.
#[derive(Clone)]
pub struct SshAcmeServer {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    client_ids: usize,
    ca_client: CaClient,
    config: SshServerConfig,
    user_authenticators: Vec<Box<dyn UserAuthenticator + Send + Sync>>,
}

/// A handler for a single client connection.
///
/// This struct holds the state for a single client connection, including a
/// reference to the main server, the username (once authenticated), and a
/// unique ID for the connection.
pub struct ConnectionHandler {
    server: Arc<SshAcmeServer>,
    username: Option<String>,
    id: usize,
}

impl SshAcmeServer {
    /// Creates a new `SshAcmeServer`.
    ///
    /// # Arguments
    ///
    /// * `config` - The SSH server configuration.
    /// * `ca_client` - A client for communicating with the CA server.
    /// * `user_authenticators` - A list of authenticators to use for user authentication.
    pub fn new(
        config: SshServerConfig,
        ca_client: CaClient,
        user_authenticators: Vec<Box<dyn UserAuthenticator + Send + Sync>>,
    ) -> Self {
        SshAcmeServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            client_ids: 0,
            ca_client,
            config,
            user_authenticators,
        }
    }

    /// Runs the SSH server.
    ///
    /// This function loads the server's private key, configures the SSH server,
    /// and starts listening for incoming connections.
    pub async fn run(&mut self) {
        let server_private_key_path = PathBuf::from(&self.config.private_key);
        let server_private_key = russh::keys::load_secret_key(&server_private_key_path, None)
            .unwrap_or_else(|e| {
                error!("failed to load private keys: {}", e);
                panic!("failed")
            });
        info!(
            "loaded private key: {}",
            &server_private_key_path.to_str().unwrap()
        );

        // allow password authentication only
        let mut auth_methods = russh::MethodSet::empty();
        auth_methods.push(russh::MethodKind::Password);

        let ssh_config = russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            max_auth_attempts: 1,
            methods: auth_methods,
            keys: vec![server_private_key],
            preferred: russh::Preferred {
                ..russh::Preferred::default()
            },
            ..Default::default()
        };
        info!(
            "starting ssh server at {}:{}",
            &self.config.bind, self.config.port
        );
        let ssh_config = Arc::new(ssh_config);
        self.run_on_address(ssh_config, (self.config.bind.clone(), self.config.port))
            .await
            .unwrap();
    }
}

impl Server for SshAcmeServer {
    type Handler = ConnectionHandler;

    /// Creates a new `ConnectionHandler` for a new client connection.
    fn new_client(&mut self, socket_addr: Option<std::net::SocketAddr>) -> ConnectionHandler {
        self.client_ids += 1;
        let s = ConnectionHandler {
            id: self.client_ids,
            username: None,
            server: Arc::new(self.clone()),
        };

        let client_address = match socket_addr {
            None => "Unknown".to_string(),
            Some(socket) => {
                let ip = socket.ip();
                let port = socket.port();
                format!("{}:{}", ip, port)
            }
        };
        debug!("new client: {}", client_address);
        s
    }

    /// Handles a session error.
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        error!("Session error: {:#?}", _error);
    }
}

impl Handler for ConnectionHandler {
    type Error = russh::Error;

    /// Authenticates a user with a password.
    ///
    /// This function iterates through the enabled authenticators and tries to
    /// authenticate the user with the given password.
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        //TODO: block certain users
        #[cfg(feature = "test_auth")]
        {
            warn!("Test Authenticate: {}, {}", user, password);
            if user == "test" && password == "test" {
                warn!("Authenticate test user");
                self.username = Some(user.to_string());
                return Ok(Auth::Accept);
            } else {
                error!("Reject test user");
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
        }
        for authenticator in &self.server.user_authenticators {
            match authenticator.authenticate(user, Credential::Password(password)) {
                Ok(true) => {
                    debug!("login for user: {} ACCEPTED", user);
                    self.username = Some(user.to_string());
                    return Ok(Auth::Accept);
                }
                Ok(false) => {
                    debug!("login for user: {} FAILED ", user);
                }
                Err(e) => {
                    warn!("pam auth error: {}", e);
                }
            }
        }
        Err(russh::Error::RequestDenied)
    }

    /// Handles a new session channel.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.server.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        Ok(true)
    }

    /// Handles incoming data on a channel.
    ///
    /// This function receives the user's public key, sends it to the CA for signing,
    /// and returns the signed certificate to the user.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let username = self.username.clone().expect("user not set");
        let openssh_key = String::from_utf8_lossy(data).to_string();
        let public_key = match certificat_authority::key_from_openssh(&openssh_key) {
            Err(e) => {
                let error_message = format!("failed to read openssh public key: {}", e);
                error!("{}", &error_message);
                let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
                return Ok(());
            }
            Ok(key) => key,
        };

        info!(
            "user {} requested signing of key: {}",
            username, openssh_key
        );
        let cert = match self
            .server
            .ca_client
            .send_request(&CaRequest::SignCertificate {
                user: username.clone(),
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
        let _ = session.eof(channel);
        let _ = session.close(channel);
        Ok(())
    }
}

impl Drop for ConnectionHandler {
    /// Removes the client from the server's list of clients when the connection is dropped.
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.server.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}
