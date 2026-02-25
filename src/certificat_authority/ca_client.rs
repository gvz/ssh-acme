//! # CA Client
//!
//! This module provides a client for interacting with the Certificate Authority (CA) server
//! over a Unix socket. Each request is wrapped in an [`AuthenticatedRequest`] envelope
//! that carries a shared bearer token and a monotonic counter for replay protection.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{AuthenticatedRequest, CaRequest, CaResponse};

/// A client for the Certificate Authority.
#[derive(Clone)]
pub struct CaClient {
    socket_path: String,
    /// Shared secret token for authenticating requests to the CA server.
    auth_token: String,
    /// Monotonic counter shared across all clones of this client, used for replay protection.
    counter: Arc<AtomicU64>,
}

impl CaClient {
    /// Creates a new `CaClient`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - The path to the Unix socket for communication with the CA server.
    /// * `auth_token` - The shared secret token for authenticating IPC requests.
    pub fn new(socket_path: String, auth_token: String) -> Self {
        CaClient {
            socket_path,
            auth_token,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Sends a request to the CA server and returns the response.
    ///
    /// The request is wrapped in an [`AuthenticatedRequest`] envelope containing
    /// the bearer token and a monotonically increasing counter value.
    ///
    /// # Arguments
    ///
    /// * `request` - The request to send to the CA server.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `CaResponse` from the server or an error.
    pub async fn send_request(&self, request: CaRequest) -> Result<CaResponse> {
        debug!("connection to: {}", self.socket_path);
        let mut stream = UnixStream::connect(&self.socket_path).await?;

        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let auth_request = AuthenticatedRequest {
            token: self.auth_token.clone(),
            counter,
            request,
        };

        let request_json = serde_json::to_string(&auth_request)?;
        stream.write_all(request_json.as_bytes()).await?;
        debug!("wrote to: {}", self.socket_path);

        let mut response_json = String::new();
        stream.read_to_string(&mut response_json).await?;
        debug!("read from: {}, {}", self.socket_path, response_json);
        let response: CaResponse = serde_json::from_str(&response_json)?;
        Ok(response)
    }
}
