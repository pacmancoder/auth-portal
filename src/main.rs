use clap::{Parser as _, Subcommand};
use std::path::Path;

mod config;
mod server;
mod token;
mod utils;

use config::Config;
use server::Server;

const DEFAULT_SESSION_TTL: i64 = 25200;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Config file path
    #[clap(default_value = "auth-portal.toml", env = "AP_CONFIG")]
    config: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initializes empty config file, generates new jwt private key automatically
    Init {
        /// Session token TTL in seconds
        #[clap(long, default_value_t = DEFAULT_SESSION_TTL)]
        session_ttl: i64,
    },
    /// Updates password/totp key for a given user. If user does not exits - adds new entry to the
    /// config. This is suggested way to generate hashed password / set private totp key. Note that
    /// displayed prompts have no echo for security reasons.
    SetCredentials {
        /// Target service name
        #[clap(long)]
        service: String,
        /// Target user login
        #[clap(long)]
        login: String,
        /// Generate new TOTP key during for user
        #[clap(long)]
        enable_totp: bool,
    },
    Serve {
        /// Prefix path to serve on
        #[clap(long, default_value = "/", env = "AP_SERVE_PREFIX")]
        prefix: String,
        /// Disables `Secure` attribute on cookies, which allows to host auth portal on
        /// non-https web sites
        #[clap(long, env = "AP_ALLOW_HTTP")]
        allow_http: bool,
        /// Serve address
        #[clap(long, default_value = "0.0.0.0", env = "AP_ADDRESS")]
        /// Serve port
        address: String,
        #[clap(long, default_value = "8080", env = "AP_PORT")]
        port: u16,
    },
}

fn main() -> anyhow::Result<()> {
    let Args { config, command } = Args::parse();

    simple_logger::init_with_env().expect("BUG: Failed to init logger");

    let config_path = Path::new(&config);

    match command {
        Command::Init { session_ttl } => {
            if config_path.exists() {
                anyhow::bail!("Config file already exists");
            }

            let config = Config::new(session_ttl)?;
            config.save(config_path)?;
        }
        Command::SetCredentials {
            service,
            login,
            enable_totp,
        } => {
            let mut config = Config::load(config_path)?;

            let password = dialoguer::Password::new()
                .with_prompt("New password")
                .interact()?;

            let result = config.set_credentials(&service, &login, &password, enable_totp)?;

            if let Some(totp_key) = result.totp_key {
                println!("Scan the following QR code in your authenticator app:");
                let issuer = format!("auth-portal-{service}");
                let params = [
                    ("secret", totp_key),
                    ("issuer", issuer.clone()),
                    ("algorithm", "SHA1".to_owned()),
                    ("digits", "6".to_owned()),
                    ("period", "30".to_owned()),
                ]
                .map(|(name, value)| format!("{name}={value}"))
                .join("&");
                let qr_url = format!("otpauth://totp/{issuer}:{login}?{params}");
                qr2term::print_qr(qr_url).unwrap();
            }

            config.save(config_path)?;

            println!("Successfully changed credentials for `{login}`");
        }
        Command::Serve {
            prefix,
            address,
            port,
            allow_http,
        } => {
            let config = Config::load(config_path)?;
            Server::run(&config, format!("{address}:{port}"), prefix, !allow_http)?;
        }
    }

    Ok(())
}
