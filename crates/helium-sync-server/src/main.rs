use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use helium_sync_server::config::{ConfigOverrides, ServerConfig};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use secrecy::ExposeSecret as _;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "helium-sync-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(ServerArgs),
    Check(ServerArgs),
    GenerateDevCert {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long = "hostname", default_values_t = [String::from("localhost"), String::from("127.0.0.1")])]
        hostnames: Vec<String>,
    },
    Healthcheck {
        #[command(flatten)]
        server: ServerArgs,
        #[arg(
            long,
            env = "HELIUM_SYNC_HEALTH_URL",
            default_value = "https://localhost:7500/v1/status"
        )]
        url: String,
    },
}

#[derive(Debug, Clone, Args)]
struct ServerArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long)]
    unix_socket: Option<PathBuf>,
    #[arg(long)]
    unix_socket_group: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    tls_certificate: Option<PathBuf>,
    #[arg(long)]
    tls_private_key: Option<PathBuf>,
    #[arg(long)]
    database: Option<PathBuf>,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long)]
    token_file: Option<PathBuf>,
}

impl From<ServerArgs> for ConfigOverrides {
    fn from(value: ServerArgs) -> Self {
        Self {
            config: value.config,
            listen: value.listen,
            unix_socket: value.unix_socket,
            unix_socket_group: value.unix_socket_group,
            data_dir: value.data_dir,
            tls_certificate: value.tls_certificate,
            tls_private_key: value.tls_private_key,
            database: value.database,
            log_level: value.log_level,
            token_file: value.token_file,
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("helium-sync-server: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Cli::parse().command {
        Command::Serve(args) => {
            let config = ServerConfig::load(args.into())?;
            init_logging(&config.log_level);
            tracing::info!(config = ?config, "starting Helium Sync server");
            helium_sync_server::serve(config).await?;
        }
        Command::Check(args) => {
            let config = ServerConfig::load(args.into())?;
            println!("configuration is valid: {config:?}");
        }
        Command::GenerateDevCert {
            output_dir,
            hostnames,
        } => generate_dev_cert(&output_dir, hostnames)?,
        Command::Healthcheck { server, url } => {
            let config = ServerConfig::load(server.into())?;
            healthcheck(&config, &url).await?;
        }
    }
    Ok(())
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .init();
}

fn generate_dev_cert(
    output_dir: &std::path::Path,
    hostnames: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)?;
    let cert_path = output_dir.join("server.crt");
    let key_path = output_dir.join("server.key");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            println!("development certificate already exists; leaving it unchanged");
            return Ok(());
        }
        (true, false) | (false, true) => {
            return Err("refusing to replace a partial development certificate pair".into());
        }
        (false, false) => {}
    }
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(hostnames)?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;
    println!(
        "WARNING: generated an insecure development certificate at {}; use only for local testing",
        output_dir.display()
    );
    Ok(())
}

async fn healthcheck(config: &ServerConfig, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let certificate = reqwest::Certificate::from_pem(&std::fs::read(&config.tls_certificate)?)?;
    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .https_only(true)
        .build()?;
    let response = client
        .get(url)
        .bearer_auth(config.token.expose_secret())
        .header(helium_sync_common::PROTOCOL_HEADER, "1")
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("health endpoint returned {}", response.status()).into());
    }
    println!("healthy");
    Ok(())
}
