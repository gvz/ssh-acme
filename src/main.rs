use clap::Parser;
use ssh_acme_server::{CliArgs, run_server};

#[tokio::main]
async fn main() {
    #[cfg(feature = "test_auth")]
    panic!("test_auth enabled in main binary");

    let args = CliArgs::parse();
    run_server(args).await;
}
