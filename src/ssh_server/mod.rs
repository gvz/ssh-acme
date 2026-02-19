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
    keys::PublicKey,
    server::{Auth, Handler, Msg, Server, Session},
};
use tokio::sync::Mutex;

use crate::certificat_authority::ca_client::CaClient;
use crate::certificat_authority::{CaRequest, CaResponse};
use crate::identiy_handlers::{Credential, UserAuthenticator};

pub(crate) mod config;
pub(crate) mod host_key_signer;
pub(crate) mod user_key_signer;
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
pub enum AuthMethod {
    Password,
    PublicKey,
}

pub struct ConnectionHandler {
    server: Arc<SshAcmeServer>,
    username: Option<String>,
    id: usize,
    auth_method: Option<AuthMethod>,
    public_key: Option<PublicKey>,
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

        let mut auth_methods = russh::MethodSet::empty();
        auth_methods.push(russh::MethodKind::Password);
        auth_methods.push(russh::MethodKind::PublicKey);

        let ssh_config = match &self.config.certificate {
            // build ssh server config to use public key
            None => russh::server::Config {
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
            },
            // build ssh server config to use certificate
            Some(server_certificate_path_str) => {
                let server_certificate_path = PathBuf::from(server_certificate_path_str);
                let server_certificate = russh::keys::load_openssh_certificate(
                    &server_certificate_path,
                )
                .unwrap_or_else(|e| {
                    error!("failed to load certificate: {}", e);
                    panic!("failed")
                });
                russh::server::Config {
                    inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
                    auth_rejection_time: std::time::Duration::from_secs(3),
                    auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                    max_auth_attempts: 1,
                    methods: auth_methods,
                    keys: vec![server_private_key],
                    certificates: vec![server_certificate],
                    preferred: russh::Preferred {
                        ..russh::Preferred::default()
                    },
                    ..Default::default()
                }
            }
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
            auth_method: None,
            public_key: None,
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
                self.auth_method = Some(AuthMethod::Password);
                return Ok(Auth::Accept);
            } else {
                error!("Reject test user");
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
        }
        #[allow(unreachable_code)]
        for authenticator in &self.server.user_authenticators {
            match authenticator.authenticate(user, Credential::Password(password)) {
                Ok(true) => {
                    debug!("login for user: {} ACCEPTED", user);
                    self.username = Some(user.to_string());
                    self.auth_method = Some(AuthMethod::Password);
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

    // Check if the key in authorized for this host
    //fn auth_publickey_offered(
    //    &mut self,
    //    user: &str,
    //    public_key: &PublicKey,
    //) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
    //}

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Accept any host who's public key is in a host config
        // Russh verifies that the host is in possession of the private key
        info!("Public key authentication accepted for user/host: {}", user);
        let key_found = match self
            .server
            .ca_client
            .send_request(&&CaRequest::CheckPublicKey {
                public_key: ssh_key::PublicKey::from_openssh(&public_key.to_openssh().unwrap())
                    .unwrap(),
            })
            .await
        {
            Ok(CaResponse::KeyFound(found)) => found,
            Ok(CaResponse::Error(e)) => {
                let error_message = format!("CA server error: {}", e);
                error!("{}", &error_message);
                false
            }
            Err(e) => {
                let error_message = format!("Failed to send request to CA server: {}", e);
                error!("{}", &error_message);
                false
            }
            Ok(CaResponse::SignedCertificate(_)) => {
                panic!("Key check reploed with signed cert, which must not happen")
            }
        };
        if !key_found {
            // key not in any config, reject host
            return Ok(Auth::Reject {
                partial_success: false,
                proceed_with_methods: None,
            });
        }

        self.username = Some(user.to_string());
        self.auth_method = Some(AuthMethod::PublicKey);
        self.public_key = Some(public_key.clone());
        Ok(Auth::Accept)
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
            debug!("new client connected");
        }
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!("user key signing found");
        user_key_signer::handler_sign_user_key(self, channel, data, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        let mut parts = command.split_whitespace();
        let command_name = parts.next().unwrap_or("");
        let pub_key = self.public_key.clone().unwrap().to_openssh().unwrap();
        let hostname = self.username.clone().unwrap();
        let args: Vec<&str> = vec![&hostname, &pub_key];

        match command_name {
            "sign_host_key" => {
                debug!("found host key signing command");
                host_key_signer::handle_sign_host_key(self, channel, args, session).await
            }
            _ => {
                let error_message = format!("Unknown command: {}", command_name);
                error!("{}", &error_message);
                let _ = session.disconnect(russh::Disconnect::ByApplication, &error_message, "en");
                Ok(())
            }
        }
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
