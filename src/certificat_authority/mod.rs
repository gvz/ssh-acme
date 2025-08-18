//! # Certificate Authority
//!
//! This module provides the core functionality for the Certificate Authority (CA).
//! It is responsible for signing SSH certificates based on user requests.
use std::fs::File;
use std::io::Read;

use anyhow::Result;
#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use ssh_key::rand_core::OsRng;
use ssh_key::{
    PublicKey,
    certificate::{Builder as CertBuilder, CertType, Certificate},
    private::PrivateKey,
};

pub mod ca_client;
pub mod ca_server;
pub mod config;
mod host_defaults_reader;
mod user_defaults_reader;

/// Represents the Certificate Authority.
#[derive(Clone)]
pub struct CertificateAuthority {
    private_key: PrivateKey,
    config: config::Ca,
}

impl CertificateAuthority {
    /// Creates a new `CertificateAuthority` instance.
    ///
    /// # Arguments
    ///
    /// * `ca_config` - The configuration for the CA.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `CertificateAuthority` instance or an error.
    pub fn new(ca_config: &config::Ca) -> Result<Self> {
        let mut key_file = File::open(ca_config.ca_key.clone())?;
        let mut key_buffer: Vec<u8> = Vec::new();
        key_file.read_to_end(&mut key_buffer)?;

        let private_key = PrivateKey::from_openssh(key_buffer)?;
        Ok(CertificateAuthority {
            private_key,
            config: ca_config.clone(),
        })
    }

    /// Signs an SSH public key and returns a certificate.
    ///
    /// # Arguments
    ///
    /// * `user` - The username associated with the public key.
    /// * `public_key` - The public key to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signed `Certificate` or an error.
    pub fn sign_certificate(&self, user: &str, public_key: &PublicKey) -> Result<Certificate> {
        // Initialize certificate builder
        info!(
            "signing {} for {}",
            public_key
                .to_openssh()
                .unwrap_or_else(|_| "broken public key".to_string()),
            user
        );
        let user_defaults = user_defaults_reader::read_user_defaults(user, &self.config)?;
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (user_defaults.validity_in_days as u64 * 86400_u64);
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(42)?; // Optional: serial number chosen by the CA
        cert_builder.key_id("nobody-cert-02")?; // Optional: CA-specific key identifier
        cert_builder.cert_type(CertType::User)?; // User or host certificate
        for principal in user_defaults.principals {
            debug!("adding principal: {}", principal);
            let _ = cert_builder.valid_principal(principal); // Unix username or hostname
        }

        cert_builder.comment(public_key.comment())?; // Comment (typically an email address)
        for extension in user_defaults.extensions {
            cert_builder.extension(extension, "")?;
        }

        // Sign and return the `Certificate` for `subject_public_key`
        let cert = match cert_builder.sign(&self.private_key) {
            Ok(cert) => cert,
            Err(e) => {
                error!("singing failed: {}", e);
                return Err(e.into());
            }
        };
        Ok(cert)
    }

    /// Signs an SSH public key and returns a certificate.
    ///
    /// # Arguments
    ///
    /// * `host_name` - The hostname associated with the public key.
    /// * `public_key` - The public key to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signed `Certificate` or an error.
    pub fn sign_host_certificate(
        &self,
        host_name: &str,
        public_key: &PublicKey,
    ) -> Result<Certificate> {
        // Initialize certificate builder
        info!(
            "signing {} for {}",
            public_key
                .to_openssh()
                .unwrap_or_else(|_| "broken public key".to_string()),
            host_name
        );
        let host_defaults = host_defaults_reader::read_host_defaults(host_name, &self.config)?;
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (host_defaults.validity_in_days as u64 * 86400_u64);
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(42)?; // Optional: serial number chosen by the CA
        cert_builder.key_id("nobody-cert-02")?; // Optional: CA-specific key identifier
        cert_builder.cert_type(CertType::Host)?; // User or host certificate
        for principal in host_defaults.principals {
            debug!("adding principal: {}", principal);
            let _ = cert_builder.valid_principal(principal); // Unix username or hostname
        }

        cert_builder.comment(public_key.comment())?; // Comment (typically an email address)
        for extension in host_defaults.extensions {
            cert_builder.extension(extension, "")?;
        }

        // Sign and return the `Certificate` for `subject_public_key`
        let cert = match cert_builder.sign(&self.private_key) {
            Ok(cert) => cert,
            Err(e) => {
                error!("singing failed: {}", e);
                return Err(e.into());
            }
        };
        Ok(cert)
    }
}

/// Parses an OpenSSH public key string into a `PublicKey` object.
///
/// # Arguments
///
/// * `openssh_key` - The OpenSSH public key string.
///
/// # Returns
///
/// A `Result` containing the `PublicKey` or an error.
pub fn key_from_openssh(openssh_key: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_openssh(openssh_key)?)
}

/// Represents a request to the Certificate Authority.
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum CaRequest {
    /// A request to sign a certificate.
    SignCertificate {
        user: String,
        #[cfg_attr(feature = "arbitrary", arbitrary(with = arbitrary_public_key))]
        public_key: PublicKey,
    },
    SignHostCertificate {
        host_name: String,
        #[cfg_attr(feature = "arbitrary", arbitrary(with = arbitrary_public_key))]
        public_key: PublicKey,
    },
}
#[cfg(feature = "arbitrary")]
fn arbitrary_public_key(u: &mut Unstructured) -> arbitrary::Result<PublicKey> {
    // Replace this with however you want to generate a PublicKey
    // Examples:

    // Option 1: If PublicKey has a constructor from bytes
    let key_bytes: [u8; 32] = u.arbitrary()?; // 32 bytes should be enough for a Ed25519 keys
    PublicKey::from_bytes(&key_bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
}

/// Represents a response from the Certificate Authority.
#[derive(Serialize, Deserialize, Debug)]
pub enum CaResponse {
    /// A successfully signed certificate.
    SignedCertificate(Certificate),
    /// An error that occurred during processing.
    Error(String),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    use ssh_key::{Algorithm, private::PrivateKey};
    use tempfile::NamedTempFile;

    #[test]
    fn sign_certificate() {
        env_logger::init();

        // Generate the certificate authority's private key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca_key_openssh = ca_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut ca_key_file = NamedTempFile::new().unwrap();
        ca_key_file.write_all(ca_key_openssh.as_bytes()).unwrap();
        ca_key_file.flush().unwrap();
        let ca_key_path = ca_key_file.path();

        // Generate a "subject" key to be signed by the certificate authority.
        // Normally a user or host would do this locally and give the certificate
        // authority the public key.
        let subject_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let subject_public_key = subject_private_key.public_key();

        let ca_config = config::Ca {
            user_list_file: PathBuf::from("./config/user.toml"),
            ca_key: ca_key_path.to_path_buf(),
            default_user_template: PathBuf::from("./config/user_default.toml"),
            host_cert_template: PathBuf::from("./config/host_cert_template.toml"),
        };

        let authority = CertificateAuthority {
            private_key: ca_key,
            config: ca_config,
        };

        let cert = authority
            .sign_certificate("test", subject_public_key)
            .unwrap();

        println!("cert: {:?}", cert.extensions());
    }
}
