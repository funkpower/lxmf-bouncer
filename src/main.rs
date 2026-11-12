// SPDX-License-Identifier: LicenseRef-Reticulum
//! lxmf-bouncer: hold one LXMF identity for several LXMF apps.
//!
//! The bouncer is the only thing that announces the user's LXMF address, so
//! every message to the user reaches it. It keeps each one in a private
//! propagation node, encrypted for the user, and every app holding the
//! identity downloads its own copy from there.

mod bouncer;
mod config;
mod ratchets;
mod store;
mod upstream;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Hold one LXMF identity for several LXMF apps, like an IRC bouncer")]
struct Cli {
    /// The configuration file.
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/lxmf-bouncer/config.toml",
        env = "LXMF_BOUNCER_CONFIG"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the bouncer (the default).
    Run,
    /// Summarise what the running (or last run) bouncer holds.
    Status {
        /// Print the status file as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the identity's LXMF address and propagation node address, to
    /// set in the clients.
    Hashes,
}

fn log_filter(level: &str) -> String {
    match level {
        "error" | "warn" | "info" => format!(
            "{level},rns_runtime=warn,rns_transport=warn,rns_link=warn,rns_interface=warn,rns_identity=warn,lxmf_core=warn"
        ),
        other => other.to_string(),
    }
}

fn setup_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = std::env::var("RUST_LOG")
        .ok()
        .map_or_else(|| EnvFilter::new(log_filter(level)), EnvFilter::new);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false);
    // journald stamps each line itself.
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().with_ansi(false).init();
    } else {
        builder.init();
    }
}

fn ago(at: f64) -> String {
    let seconds = (bouncer::now() - at).max(0.0) as u64;
    match seconds {
        s if s < 120 => format!("{s} s ago"),
        s if s < 7200 => format!("{} min ago", s / 60),
        s if s < 172_800 => format!("{} h ago", s / 3600),
        s => format!("{} days ago", s / 86_400),
    }
}

fn status(settings: &config::Settings, json: bool) -> Result<(), String> {
    let path = settings.status_path();
    let data = std::fs::read(&path).map_err(|e| format!("{}: {e} (has the bouncer run yet?)", path.display()))?;
    if json {
        println!("{}", String::from_utf8_lossy(&data));
        return Ok(());
    }
    let s: bouncer::Status = serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
    let running = std::path::Path::new(&format!("/proc/{}", s.pid)).exists() && bouncer::now() - s.updated_at < 180.0;
    println!(
        "lxmf-bouncer status (updated {}{})",
        ago(s.updated_at),
        if running { "" } else { "; not running" }
    );
    println!("  identity           {}", s.identity_hash);
    println!("  LXMF address       {}", s.lxmf_address);
    println!("  propagation node   {}", s.propagation_node);
    println!("  last announce      {}", s.last_announce.map_or("never".into(), ago));
    println!(
        "  store              {} message(s), {} bytes, oldest {}, newest {}",
        s.store.messages,
        s.store.bytes,
        s.store.oldest.map_or("-".into(), ago),
        s.store.newest.map_or("-".into(), ago)
    );
    for (sender, count) in &s.store.by_sender {
        println!("    {sender}  {count}");
    }
    println!(
        "  since start        {} direct, {} from upstream, {} duplicate(s), {} dropped",
        s.received_direct, s.received_upstream, s.duplicates, s.dropped
    );
    println!(
        "  clients            {} message(s) served in {} sync(s), {} refused",
        s.messages_served, s.syncs_served, s.syncs_refused
    );
    match (&s.upstream, &s.last_upstream) {
        (None, _) => println!("  upstream           none"),
        (Some(node), None) => println!("  upstream           {node}, not fetched yet"),
        (Some(node), Some(last)) => println!(
            "  upstream           {node}, last fetch {}: {}",
            ago(last.at),
            last.error.clone().unwrap_or_else(|| format!("ok, {} new", last.stored))
        ),
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let settings = match config::Settings::load(&cli.config) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("lxmf-bouncer: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::Status { json } => status(&settings, json),
        Command::Hashes => bouncer::load_identity(&settings.identity).and_then(|identity| {
            let node = bouncer::load_or_create_node_identity(&settings.node_identity, &identity)?;
            println!("identity           {}", hex::encode(identity.hash));
            println!(
                "LXMF address       {}",
                hex::encode(bouncer::delivery_address(&identity.hash))
            );
            println!("propagation node   {}", hex::encode(bouncer::node_address(&node.hash)));
            Ok(())
        }),
        Command::Run => {
            setup_logging(&settings.log_level);
            let _ = bouncer::STARTED.set(bouncer::now());
            match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(bouncer::run(settings)),
                Err(e) => Err(format!("could not start the async runtime: {e}")),
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("lxmf-bouncer: {e}");
            ExitCode::FAILURE
        }
    }
}
