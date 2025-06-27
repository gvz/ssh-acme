use std::os::unix::net::UnixStream;
use std::io::{self, Read, Write};
use serde::{Serialize, Deserialize};
use anyhow::Result;

use super::{CaRequest, CaResponse};

#[derive(Clone)]
pub struct CaClient {
    socket_path: String,
}

impl CaClient {
    pub fn new(socket_path: String) -> Self {
        CaClient { socket_path }
    }

    pub fn send_request(&self, request: &CaRequest) -> Result<CaResponse> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let request_json = serde_json::to_string(request)?;
        stream.write_all(request_json.as_bytes())?;
        stream.shutdown(std::net::Shutdown::Write)?; // Signal end of request

        let mut response_json = String::new();
        stream.read_to_string(&mut response_json)?;
        let response: CaResponse = serde_json::from_str(&response_json)?;
        Ok(response)
    }
}
