use std::os::unix::net::UnixListener;
use std::io::{self, Read, Write};
use std::fs;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use log::{info, error};

use super::{CaRequest, CaResponse, CertificateAuthority};

pub struct CaServer {
    socket_path: String,
    ca: CertificateAuthority,
}

impl CaServer {
    pub fn new(socket_path: String, ca: CertificateAuthority) -> Self {
        CaServer { socket_path, ca }
    }

    pub fn run(&self) -> Result<()> {
        // Clean up old socket if it exists
        if fs::metadata(&self.socket_path).is_ok() {
            fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("CA server listening on {}", self.socket_path);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    info!("New connection to CA server");
                    let mut request_json = String::new();
                    if let Err(e) = stream.read_to_string(&mut request_json) {
                        error!("Failed to read request: {}", e);
                        continue;
                    }

                    let response = match serde_json::from_str::<CaRequest>(&request_json) {
                        Ok(request) => {
                            match self.handle_request(request) {
                                Ok(resp) => resp,
                                Err(e) => {
                                    error!("Error handling CA request: {}", e);
                                    CaResponse::Error(e.to_string())
                                }
                            }
                        },
                        Err(e) => {
                            error!("Failed to deserialize request: {}", e);
                            CaResponse::Error(format!("Invalid request format: {}", e))
                        }
                    };

                    let response_json = serde_json::to_string(&response)?;
                    if let Err(e) = stream.write_all(response_json.as_bytes()) {
                        error!("Failed to write response: {}", e);
                    }
                },
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
        Ok(())
    }

    fn handle_request(&self, request: CaRequest) -> Result<CaResponse> {
        match request {
            CaRequest::SignCertificate { public_key, principals, valid_before, valid_after } => {
                let signed_cert = self.ca.sign_certificate(
                    &public_key,
                    &principals,
                    valid_before,
                    valid_after,
                )?;
                Ok(CaResponse::SignedCertificate(signed_cert))
            }
        }
    }
}
