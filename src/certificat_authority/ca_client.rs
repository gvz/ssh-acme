//! # CA Client
//!
//! This module provides a client for interacting with the Certificate Authority (CA) server
//! over a Unix socket.
use anyhow::Result;
use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{CaRequest, CaResponse};

/// A client for the Certificate Authority.
#[derive(Clone)]
pub struct CaClient {
    socket_path: String,
}

impl CaClient {
    /// Creates a new `CaClient`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - The path to the Unix socket for communication with the CA server.
    pub fn new(socket_path: String) -> Self {
        CaClient { socket_path }
    }

    /// Sends a request to the CA server and returns the response.
    ///
    /// # Arguments
    ///
    /// * `request` - The request to send to the CA server.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `CaResponse` from the server or an error.
    pub async fn send_request(&self, request: &CaRequest) -> Result<CaResponse> {
        debug!("connection to: {}", self.socket_path);
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let request_json = serde_json::to_string(request)?;
        stream.write_all(request_json.as_bytes()).await?;
        debug!("wrote to: {}", self.socket_path);

        let mut response_json = String::new();
        stream.read_to_string(&mut response_json).await?;
        debug!("red from: {}, {}", self.socket_path, response_json);
        let response: CaResponse = serde_json::from_str(&response_json)?;
        Ok(response)
    }
}
