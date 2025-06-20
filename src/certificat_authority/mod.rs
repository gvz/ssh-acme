use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use ssh_key::rand_core::OsRng;
use ssh_key::{
    PublicKey,
    certificate::{Builder as CertBuilder, CertType, Certificate},
    private::PrivateKey,
};

use std::time::{SystemTime, UNIX_EPOCH};
mod certificat_template_reader;
pub mod config;

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

    pub fn sign(&self, public_key: &PublicKey) -> Result<Certificate> {
        // Create certificate validity window
        let valid_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let valid_before = valid_after + (365 * 86400); // e.g. 1 year

        // Initialize certificate builder
        let mut cert_builder =
            CertBuilder::new_with_random_nonce(&mut OsRng, public_key, valid_after, valid_before)?;
        cert_builder.serial(42)?; // Optional: serial number chosen by the CA
        cert_builder.key_id("nobody-cert-02")?; // Optional: CA-specific key identifier
        cert_builder.cert_type(CertType::User)?; // User or host certificate
        cert_builder.valid_principal("nobody")?; // Unix username or hostname
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

        let cert = authority.sign(subject_public_key).unwrap();

        println!("cert: {:?}", cert.extensions());
    }
}
