//! # Host Certificate Authority
//!
//! This module provides the functionality for signing host certificates.

use anyhow::Result;
use log::{debug, error, info};
use ssh_key::rand_core::OsRng;
use ssh_key::{
    PublicKey,
    certificate::{Builder as CertBuilder, CertType, Certificate},
    private::PrivateKey,
};

use crate::certificat_authority::config;
use crate::certificat_authority::host_defaults_reader;

/// Signs an SSH public key and returns a host certificate.
///
/// # Arguments
///
/// * `host_name` - The hostname associated with the public key.
/// * `public_key` - The public key to be signed.
/// * `private_key` - The private key of the CA.
/// * `config` - The CA configuration.
///
/// # Returns
///
/// A `Result` containing the signed `Certificate` or an error.
pub fn sign_host_certificate(
    host_name: &str,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    config: &config::Ca,
) -> Result<Certificate> {
    // Initialize certificate builder
    info!(
        "signing {} for {}",
        public_key
            .to_openssh()
            .unwrap_or_else(|_| "broken public key".to_string()),
        host_name
    );
    let host_defaults = host_defaults_reader::read_host_defaults(host_name, config)?;
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
    let cert = match cert_builder.sign(private_key) {
        Ok(cert) => cert,
        Err(e) => {
            error!("singing failed: {}", e);
            return Err(e.into());
        }
    };
    Ok(cert)
}
