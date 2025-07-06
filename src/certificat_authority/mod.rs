use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use ssh_key::rand_core::OsRng;
use ssh_key::{
    PublicKey,
    certificate::{Builder as CertBuilder, CertType, Certificate},
    private::PrivateKey,
};

pub mod config;
pub mod ca_client;
pub mod ca_server;
mod user_defaults_reader;

#[derive(Clone)]
pub struct CertificateAuthority {
    private_key: PrivateKey,
}

impl CertificateAuthority {
    pub fn new(private_key_path: &str) -> Result<Self> {
        let key_path = PathBuf::from(private_key_path);
        let mut key_file = File::open(key_path)?;
        let mut key_buffer: Vec<u8> = Vec::new();
        key_file.read_to_end(&mut key_buffer)?;

        let private_key = PrivateKey::from_openssh(key_buffer)?;
        Ok(CertificateAuthority { private_key })
    }

    pub fn sign_certificate(
        &self,
        public_key: &PublicKey,
        principals: &[String],
        valid_after: u64,
        valid_before: u64,
    ) -> Result<Certificate> {
        // Initialize certificate builder
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(42)?; // Optional: serial number chosen by the CA
        cert_builder.key_id("nobody-cert-02")?; // Optional: CA-specific key identifier
        cert_builder.cert_type(CertType::User)?; // User or host certificate
        for principal in principals {
            cert_builder.valid_principal(principal)?; // Unix username or hostname
        }
        cert_builder.comment("nobody@example.com")?; // Comment (typically an email address)
        cert_builder.extension("test".to_string(), "test_data".to_string())?;

        // Sign and return the `Certificate` for `subject_public_key`
        let cert = cert_builder.sign(&self.private_key)?;
        Ok(cert)
    }
}

pub fn key_from_openssh(openssh_key: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_openssh(openssh_key)?)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CaRequest {
    SignCertificate {
        public_key: PublicKey,
        principals: Vec<String>,
        valid_after: u64,
        valid_before: u64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CaResponse {
    SignedCertificate(Certificate),
    Error(String),
}

#[cfg(test)]
mod test {
    use super::*;

    use ssh_key::{
        Algorithm,
        private::{Ed25519Keypair, PrivateKey},
    };

    #[test]
    fn sign_certificate() {
        // Generate the certificate authority's private key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

        // Generate a "subject" key to be signed by the certificate authority.
        // Normally a user or host would do this locally and give the certificate
        // authority the public key.
        let subject_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_public_key = subject_private_key.public_key();

        let authority = CertificateAuthority {
            private_key: ca_key,
        };

        let valid_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let valid_before = valid_after + (365 * 86400); // e.g. 1 year

        let cert = authority.sign_certificate(
            subject_public_key,
            &vec!["nobody".to_string()],
            valid_after,
            valid_before,
        ).unwrap();

        println!("cert: {:?}", cert.extensions());
    }
}
