use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use log::{debug, error, info, warn};

mod ssh_server;
use crate::ssh_server::SshAcmeServer;

mod identiy_handlers;

mod certificat_authority;
use crate::certificat_authority::CertificateAuthority;

mod config;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// config file path
    #[arg(short = 'c', long)]
    config_file: String,
}

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        // this is unsafe as this programm is multi threaded, but at this time there is only on
        // thread
        unsafe { env::set_var("RUST_LOG", "info") }
    }
    env_logger::init();

    let args = Args::parse();
    let config = config::read_config(&args.config_file).unwrap();

    let user_authenticators =
        identiy_handlers::setup_user_authenticators(config.identity_handlers.user_authenticators)
            .unwrap();

    let mut server = SshAcmeServer::new(
        config.ssh,
        CertificateAuthority::new("test_data/test_key").unwrap(),
        user_authenticators,
    );
    info!("starting server");
    server.run().await;
}
