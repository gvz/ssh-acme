use clap::{Parser, Subcommand};
use log::{error, info};
use std::env;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod ssh_server;
use crate::ssh_server::SshAcmeServer;

mod identiy_handlers;

mod certificat_authority;
use crate::certificat_authority::{CertificateAuthority, ca_client::CaClient, ca_server::CaServer};

mod config;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// config file path
    #[arg(short = 'c', long)]
    config_file: String,
    /// CA mode
    #[arg(short = 'a', long, default_value_t = false)]
    certificate_authority: bool,
    /// socket path
    #[arg(short = 's', long)]
    socket_path: Option<String>,
    /// do not start CA
    #[arg(long, default_value_t = false)]
    disable_ca: bool,
}

pub async fn run_server(args: CliArgs) {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    let _ = env_logger::try_init();

    let config = match config::read_config(&args.config_file) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read config file: {}", e);
            return;
        }
    };

    match args.certificate_authority {
        true => {
            info!("Starting CA server");
            let socket_path = match args.socket_path {
                Some(path) => path,
                None => panic!("in CA mode the socket path in mandatory"),
            };
            let ca = CertificateAuthority::new(&config.ca).unwrap();
            let ca_server = CaServer::new(socket_path, ca);
            ca_server.run().await.unwrap();
        }
        false => {
            info!("Starting SSH server");
            let socket_path = match args.socket_path {
                Some(path) => path,
                None => {
                    let socket_name = format!("ssh_acme_ca.{}.sock", std::process::id());
                    let mut tmp_dir = tempdir().unwrap();
                    tmp_dir.disable_cleanup(true);
                    let mut socket_path = tmp_dir.path().to_path_buf();
                    socket_path.push(socket_name);
                    let path = socket_path.as_os_str().to_string_lossy();
                    path.to_string()
                }
            };
            let mut ca_process = if !args.disable_ca {
                info!("spawning CA");
                let mut ca_process = match Command::new(env::current_exe().unwrap())
                    .arg("-c")
                    .arg(&args.config_file)
                    .arg("-a")
                    .arg("-s")
                    .arg(&socket_path)
                    .spawn()
                {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to spawn CA server process: {}", e);
                        return;
                    }
                };
                info!("spawned CA");

                Some(ca_process)
            } else {
                info!("skip spawning CA");
                None
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
                if let Some(mut ca) = ca_process {
                    let _ = ca.kill();
                }
                return;
            }

            let user_authenticators = identiy_handlers::setup_user_authenticators(
                config.identity_handlers.user_authenticators,
            )
            .unwrap();

            let ca_client = CaClient::new(socket_path.clone());

            let mut server = SshAcmeServer::new(config.ssh, ca_client, user_authenticators);
            info!("starting server");
            server.run().await;

            info!("Terminating CA process");
            if let Some(mut ca) = ca_process {
                let _ = ca.kill();
                let _ = ca.wait();
            }

            info!("Removing CA socket file: {}", socket_path);
            let _ = fs::remove_file(&socket_path);
        }
    }
}
