//use std::os::unix::net::UnixListener;
use anyhow::Result;
use log::{debug, error, info};
use std::fs;
use std::io::{Read, Write};
use tokio::net::UnixListener;

use super::{CaRequest, CaResponse, CertificateAuthority};

pub struct CaServer {
    socket_path: String,
    ca: CertificateAuthority,
}

impl CaServer {
    pub fn new(socket_path: String, ca: CertificateAuthority) -> Self {
        CaServer { socket_path, ca }
    }

    pub async fn run(&self) -> Result<()> {
        // Clean up old socket if it exists
        if fs::metadata(&self.socket_path).is_ok() {
            fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("CA server listening on {}", self.socket_path);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("New connection to CA server");
                    stream.readable().await.unwrap();
                    let mut buf = Vec::with_capacity(4096);
                    if let Err(e) = stream.try_read_buf(&mut buf) {
                        error!("Failed to read request: {}", e);
                        continue;
                    }
                    let request_json = String::from_utf8(buf).unwrap();
                    debug!("got request: {}", request_json);
                    let response = match serde_json::from_str::<CaRequest>(&request_json) {
                        Ok(request) => match self.handle_request(request) {
                            Ok(resp) => resp,
                            Err(e) => {
                                error!("Error handling CA request: {}", e);
                                CaResponse::Error(e.to_string())
                            }
                        },
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

    fn handle_request(&self, request: CaRequest) -> Result<CaResponse> {
        match request {
            CaRequest::SignCertificate { user, public_key } => {
                let signed_cert = self.ca.sign_certificate(&user, &public_key)?;
                Ok(CaResponse::SignedCertificate(signed_cert))
            }
        }
    }
}
