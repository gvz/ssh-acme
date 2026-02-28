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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::{AuthenticatedRequest, CaRequest, CaResponse, CertificateAuthority, MAX_MESSAGE_SIZE};

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
                    let mut stream = stream;
                    // Read the 4-byte big-endian length prefix.
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = stream.read_exact(&mut len_buf).await {
                        error!("Failed to read message length: {}", e);
                        continue;
                    }
                    let msg_len = u32::from_be_bytes(len_buf);
                    if msg_len > MAX_MESSAGE_SIZE {
                        error!(
                            "Rejected CA request: message size {} exceeds maximum {}",
                            msg_len, MAX_MESSAGE_SIZE
                        );
                        continue;
                    }
                    // Allocate exactly the declared size and read the full payload.
                    let mut buf = vec![0u8; msg_len as usize];
                    if let Err(e) = stream.read_exact(&mut buf).await {
                        error!("Failed to read request payload: {}", e);
                        continue;
                    }
                    let request_json = match String::from_utf8(buf) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Request is not valid UTF-8: {}", e);
                            continue;
                        }
                    };
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
                    let response_bytes = response_json.as_bytes();
                    let response_len = response_bytes.len() as u32;
                    if let Err(e) = stream.write_all(&response_len.to_be_bytes()).await {
                        error!("Failed to write response length: {}", e);
                        continue;
                    }
                    if let Err(e) = stream.write_all(response_bytes).await {
                        error!("Failed to write response payload: {}", e);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificat_authority::config;
    use ssh_key::{Algorithm, private::PrivateKey, rand_core::OsRng};
    use std::fs;
    use tempfile::TempDir;

    /// Helper function to create a test CA server with minimal configuration.
    fn create_test_ca_server() -> (CaServer, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create CA private key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let ca_key_path = base_path.join("ca_key");
        fs::write(&ca_key_path, ca_key_openssh.as_bytes()).unwrap();

        // Create minimal user list
        let user_list = r#"
[users]
"#;
        let user_list_path = base_path.join("user.toml");
        fs::write(&user_list_path, user_list).unwrap();

        // Create default user template
        let user_template = r#"
validity_in_days = 1
principals = ["{{ user_name }}"]
extensions = ["permit-pty"]
"#;
        let user_template_path = base_path.join("user_default.toml");
        fs::write(&user_template_path, user_template).unwrap();

        // Create host inventory directory
        let host_inventory = base_path.join("hosts");
        fs::create_dir(&host_inventory).unwrap();

        let ca_config = config::Ca {
            user_list_file: user_list_path,
            ca_key: ca_key_path,
            default_user_template: user_template_path,
            host_inventory,
        };

        let ca = CertificateAuthority::new(&ca_config).unwrap();
        let server = CaServer::new(
            base_path.join("ca.sock").to_str().unwrap().to_string(),
            ca,
            "test-token-12345".to_string(),
        );

        (server, temp_dir)
    }

    /// Tests that `handle_request` successfully signs a user certificate.
    #[test]
    fn test_handle_request_sign_certificate() {
        let (server, _temp_dir) = create_test_ca_server();

        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user_public_key = user_key.public_key().clone();

        let request = CaRequest::SignCertificate {
            user: "testuser".to_string(),
            public_key: user_public_key.clone(),
        };

        let response = server.handle_request(request);
        assert!(
            response.is_ok(),
            "Should successfully sign user certificate"
        );

        match response.unwrap() {
            CaResponse::SignedCertificate(cert) => {
                assert_eq!(cert.public_key(), user_public_key.key_data());
                assert!(cert.key_id().starts_with("user-testuser-"));
            }
            _ => panic!("Expected SignedCertificate response"),
        }
    }

    /// Tests that `handle_request` handles CheckPublicKey requests.
    #[test]
    fn test_handle_request_check_public_key() {
        let (server, _temp_dir) = create_test_ca_server();

        let test_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let test_public_key = test_key.public_key().clone();

        let request = CaRequest::CheckPublicKey {
            public_key: test_public_key,
        };

        let response = server.handle_request(request);
        assert!(response.is_ok(), "Should handle check public key request");

        match response.unwrap() {
            CaResponse::KeyFound(None) => {
                // Expected: key not found since we didn't set up any host configs
            }
            _ => panic!("Expected KeyFound(None) response"),
        }
    }

    /// Tests that `handle_request` successfully signs a host certificate when the key matches.
    #[test]
    fn test_handle_request_sign_host_certificate() {
        let (server, temp_dir) = create_test_ca_server();

        // Create a host config file
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let host_public_key = host_key.public_key().clone();
        let host_public_key_str = host_public_key.to_openssh().unwrap();

        let host_config = format!(
            r#"
public_key = "{}"
validity_in_days = 30
hostnames = ["testhost.example.com"]
extensions = []
"#,
            host_public_key_str
        );

        let config_file = temp_dir.path().join("hosts").join("testhost.toml");
        fs::write(&config_file, host_config).unwrap();

        let request = CaRequest::SignHostCertificate {
            host_name: "testhost".to_string(),
            public_key: host_public_key.clone(),
        };

        let response = server.handle_request(request);
        assert!(
            response.is_ok(),
            "Should successfully sign host certificate"
        );

        match response.unwrap() {
            CaResponse::SignedCertificate(cert) => {
                assert_eq!(cert.public_key(), host_public_key.key_data());
                assert!(cert.key_id().starts_with("host-testhost-"));
            }
            _ => panic!("Expected SignedCertificate response"),
        }
    }

    /// Tests that `handle_request` rejects host certificate signing when the key doesn't match.
    #[test]
    fn test_handle_request_sign_host_certificate_wrong_key() {
        let (server, temp_dir) = create_test_ca_server();

        // Create a host config file with one key
        let config_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let config_public_key_str = config_key.public_key().to_openssh().unwrap();

        let host_config = format!(
            r#"
public_key = "{}"
validity_in_days = 30
hostnames = ["testhost.example.com"]
extensions = []
"#,
            config_public_key_str
        );

        let config_file = temp_dir.path().join("hosts").join("testhost.toml");
        fs::write(&config_file, host_config).unwrap();

        // Try to sign with a different key
        let different_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let different_public_key = different_key.public_key().clone();

        let request = CaRequest::SignHostCertificate {
            host_name: "testhost".to_string(),
            public_key: different_public_key,
        };

        let response = server.handle_request(request);
        assert!(response.is_err(), "Should reject mismatched host key");
        assert!(
            response
                .unwrap_err()
                .to_string()
                .contains("wrong public key"),
            "Error should indicate wrong public key"
        );
    }
}
