//! # SSH ACME Server
//!
//! This is the main entry point for the SSH ACME server.
use clap::Parser;
use ssh_acme_server::{CliArgs, run_server};

/// The main function for the SSH ACME server.
///
/// This function parses the command-line arguments and calls the `run_server`
/// function to start the server.
#[tokio::main]
async fn main() {
    #[cfg(feature = "test_auth")]
    panic!("test_auth enabled in main binary");

    let args = CliArgs::parse();
    run_server(args).await;
}
