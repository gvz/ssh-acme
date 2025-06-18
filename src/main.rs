use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};

use clap::Parser;
use log::{debug, error, info, warn};
use russh::{
    Channel, ChannelId,
    server::{Auth, Handler, Msg, Server, Session},
};
use tokio::sync::Mutex;

mod pam_auth;
use pam_auth::pam_authenticate_user;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// secret host key to be used
    #[arg(short = 's', long)]
    private_key: String,
    /// port to bind to
    #[arg(short, long, default_value_t = 2222u16)]
    port: u16,
    /// address to bind
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

#[derive(Clone)]
struct SshAcmeServer {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

impl Server for SshAcmeServer {
    type Handler = Self;
    fn new_client(&mut self, socket_addr: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        let client_address = match socket_addr {
            None => "Unknown".to_string(),
            Some(socket) => {
                let ip = socket.ip();
                let port = socket.port();
                format!("{}:{}", ip, port)
            }
        };
        info!("new client: {}", client_address);
        s
    }
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        error!("Session error: {:#?}", _error);
    }
}

impl Handler for SshAcmeServer {
    type Error = russh::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        //TODO: block certain users
        match pam_authenticate_user(user, password) {
            Ok(true) => {
                info!("login for user: {} ACCEPTED", user);
                Ok(Auth::Accept)
            }
            Ok(false) => {
                info!("login for user: {} FAILED ", user);
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
            Err(e) => {
                warn!("pam auth error: {}", e);
                Err(russh::Error::RequestDenied)
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let echo = format!("You said: {}\n", String::from_utf8_lossy(data));
        session.data(channel, echo.into());
        Ok(())
    }
}

impl Drop for SshAcmeServer {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        // this is unsafe as this programm is multi threaded, but at this time there is only on
        // thread
        unsafe { env::set_var("RUST_LOG", "info") }
    }
    env_logger::init();
    debug!("debug");

    let args = Args::parse();
    let server_private_key_path = PathBuf::from_str(&args.private_key).unwrap_or_else(|e| {
        error!("private key path can not be formated a path: {}", &e);
        panic!("failed");
    });
    let ssh_port = args.port;
    let ssh_bind = args.bind;

    let server_private_key = russh::keys::load_secret_key(&server_private_key_path, None)
        .unwrap_or_else(|e| {
            error!("failed to load private keys: {}", e);
            panic!("failed")
        });
    info!(
        "loaded private key: {}",
        &server_private_key_path.to_str().unwrap()
    );
    // allow password authentication only
    let mut auth_methods = russh::MethodSet::empty();
    auth_methods.push(russh::MethodKind::Password);
    let ssh_config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        max_auth_attempts: 1,
        methods: auth_methods,
        keys: vec![server_private_key],
        preferred: russh::Preferred {
            ..russh::Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(ssh_config);
    let mut server = SshAcmeServer {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    info!("starting server");
    server
        .run_on_address(config, (ssh_bind, ssh_port))
        .await
        .unwrap();
}
