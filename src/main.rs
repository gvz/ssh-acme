use std::env;
use std::process::Command;
use std::fs;
use log::{info, error};
use clap::{Parser, Subcommand};

mod ssh_server;
use crate::ssh_server::SshAcmeServer;

mod identiy_handlers;

mod certificat_authority;
use crate::certificat_authority::{ca_client::CaClient, ca_server::CaServer, CertificateAuthority};

mod config;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// config file path
    #[arg(short = 'c', long)]
    config_file: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the CA server
    CaServer {
        #[arg(long)]
        socket_path: String,
    },
}

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        unsafe { env::set_var("RUST_LOG", "info"); }
    }
    env_logger::init();

    let args = Args::parse();
    let config = match config::read_config(&args.config_file) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read config file: {}", e);
            return;
        }
    };

    match args.command {
        Some(Commands::CaServer { socket_path }) => {
            info!("Starting CA server");
            let ca = CertificateAuthority::new(&config.ca.ca_key).unwrap();
            let ca_server = CaServer::new(socket_path, ca);
            ca_server.run().unwrap();
        },
        None => {
            info!("Starting SSH server");
            let socket_path = format!("/tmp/ssh_acme_ca.{}.sock", std::process::id());

            let mut ca_process = match Command::new(env::current_exe().unwrap())
                .arg("-c")
                .arg(&args.config_file)
                .arg("ca-server")
                .arg("--socket-path")
                .arg(&socket_path)
                .spawn() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to spawn CA server process: {}", e);
                        return;
                    }
                };

            // Wait for the CA server to start by checking for the socket file
            for _ in 0..10 {
                if std::path::Path::new(&socket_path).exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if !std::path::Path::new(&socket_path).exists() {
                error!("CA server did not start in time");
                let _ = ca_process.kill();
                return;
            }


            let user_authenticators =
                identiy_handlers::setup_user_authenticators(config.identity_handlers.user_authenticators)
                    .unwrap();

            let ca_client = CaClient::new(socket_path.clone());

            let mut server = SshAcmeServer::new(
                config.ssh,
                ca_client,
                user_authenticators,
            );
            info!("starting server");
            server.run().await;

            info!("Terminating CA process");
            let _ = ca_process.kill();
            let _ = ca_process.wait();

            info!("Removing CA socket file: {}", socket_path);
            let _ = fs::remove_file(&socket_path);
        }
    }
}