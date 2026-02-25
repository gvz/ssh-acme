//! # CA Server
//!
//! This module provides a server for the Certificate Authority (CA) that listens for requests
//! on a Unix socket. It handles requests for signing SSH certificates.
//!
//! Every request must be wrapped in an [`AuthenticatedRequest`] envelope that
//! carries a bearer token and a monotonic counter. The server verifies the token
//! using constant-time comparison and rejects any counter value that is not
//! strictly greater than the previously accepted one (replay protection).
use anyhow::Result;
use log::{debug, error, info};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;

use super::{AuthenticatedRequest, CaRequest, CaResponse, CertificateAuthority};

/// A server for the Certificate Authority.
pub struct CaServer {
    socket_path: String,
    ca: CertificateAuthority,
    /// Shared secret token used to authenticate IPC requests.
    auth_token: String,
    /// The last accepted monotonic counter value; used for replay protection.
    last_counter: u64,
}

impl CaServer {
    /// Creates a new `CaServer`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - The path to the Unix socket to listen on.
    /// * `ca` - The `CertificateAuthority` instance to use for signing certificates.
    /// * `auth_token` - The shared secret token for authenticating IPC requests.
    pub fn new(socket_path: String, ca: CertificateAuthority, auth_token: String) -> Self {
        CaServer {
            socket_path,
            ca,
            auth_token,
            last_counter: 0,
        }
    }

    /// Runs the CA server.
    ///
    /// This function binds to the specified Unix socket and enters a loop to accept
    /// and handle incoming connections. Each request is authenticated via a shared
    /// bearer token and a monotonic counter before being dispatched.
    pub async fn run(&mut self) -> Result<()> {
        // Clean up old socket if it exists
        if fs::metadata(&self.socket_path).is_ok() {
            fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        // Restrict socket permissions to owner-only (0o600) to prevent
        // other local users from connecting to the CA service.
        fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600))?;
        let server_uid = nix::unistd::getuid();
        info!("CA server listening on {}", self.socket_path);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("New connection to CA server");
                    // Verify the connecting process belongs to the same user
                    // as the CA server (SO_PEERCRED check).
                    match stream.peer_cred() {
                        Ok(cred) => {
                            if cred.uid() != server_uid.as_raw() {
                                error!(
                                    "Rejected CA connection from UID {}, expected {}",
                                    cred.uid(),
                                    server_uid
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            error!("Failed to get peer credentials: {}", e);
                            continue;
                        }
                    }
                    stream.readable().await.unwrap();
                    let mut buf = Vec::with_capacity(4096);
                    if let Err(e) = stream.try_read_buf(&mut buf) {
                        error!("Failed to read request: {}", e);
                        continue;
                    }
                    let request_json = String::from_utf8(buf).unwrap();
                    debug!("got request (length={})", request_json.len());
                    let response = match serde_json::from_str::<AuthenticatedRequest>(&request_json)
                    {
                        Ok(auth_req) => {
                            // Verify the bearer token using constant-time comparison
                            // to prevent timing side-channel attacks.
                            let token_valid: bool = auth_req
                                .token
                                .as_bytes()
                                .ct_eq(self.auth_token.as_bytes())
                                .into();
                            if !token_valid {
                                error!("Rejected CA request: invalid authentication token");
                                CaResponse::Error("authentication failed".to_string())
                            } else if auth_req.counter <= self.last_counter {
                                // Reject replayed or out-of-order requests.
                                error!(
                                    "Rejected CA request: counter {} is not greater than last accepted {}",
                                    auth_req.counter, self.last_counter
                                );
                                CaResponse::Error("authentication failed".to_string())
                            } else {
                                self.last_counter = auth_req.counter;
                                match self.handle_request(auth_req.request) {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        error!("Error handling CA request: {}", e);
                                        CaResponse::Error(e.to_string())
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to deserialize request: {}", e);
                            CaResponse::Error(format!("Invalid request format: {}", e))
                        }
                    };

                    let response_json = serde_json::to_string(&response)?;
                    if let Err(e) = stream.try_write(response_json.as_bytes()) {
                        error!("Failed to write response: {}", e);
                    }
                }
                Err(e) => error!("connection failed: {:?}", e),
            }
        }
    }

    /// Dispatches a [`CaRequest`] to the appropriate CA operation and returns
    /// the resulting [`CaResponse`].
    pub fn handle_request(&self, request: CaRequest) -> Result<CaResponse> {
        match request {
            CaRequest::SignCertificate { user, public_key } => {
                debug!("signing user certificate");
                let signed_cert = self.ca.sign_certificate(&user, &public_key)?;
                Ok(CaResponse::SignedCertificate(signed_cert))
            }
            CaRequest::SignHostCertificate {
                host_name,
                public_key,
            } => {
                debug!("signing host certificate");
                let signed_cert = self.ca.sign_host_certificate(&host_name, &public_key)?;
                Ok(CaResponse::SignedCertificate(signed_cert))
            }
            CaRequest::CheckPublicKey { public_key } => {
                debug!("checking public key");
                let str_key = match public_key.to_openssh() {
                    Ok(key) => {
                        debug!("public key as openssh {} ", key);
                        key
                    }
                    Err(_) => {
                        debug!("public key ist not convertable to openssh");
                        return Ok(CaResponse::KeyFound(None));
                    }
                };
                Ok(CaResponse::KeyFound(self.ca.check_public_key(&str_key)))
            }
        }
    }
}
