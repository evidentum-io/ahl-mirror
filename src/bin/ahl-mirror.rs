//! `ahl-mirror` server binary: load configuration, open the store, and serve the mirror's
//! HTTP API.

#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
// See ahl-core's Cargo.toml and this crate's lib.rs for the rationale: transitive deps pull
// both syn 2.x/3.x and thiserror 1.x/2.x. Not actionable from this binary.
#![allow(clippy::multiple_crate_versions)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahl_mirror::config::{Config, ConfigSpec};
use ahl_mirror::http::{router, AppState};
use ahl_mirror::store::Store;
use clap::Parser;

/// Command-line arguments for the `ahl-mirror` server.
#[derive(Parser, Debug)]
#[command(about = "Independent AHL log mirror for the ahl-adaptor-atl-v1 profile")]
struct Args {
    /// Path to a JSON configuration file (see README.md for the shape).
    #[arg(long)]
    config: PathBuf,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let raw = std::fs::read_to_string(&args.config)?;
    let spec: ConfigSpec = serde_json::from_str(&raw)?;
    let config = Config::resolve(&spec)?;
    let store = Store::open(Path::new(&config.store_path))?;

    let state = AppState { store: Arc::new(store), config: Arc::new(config) };
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, "ahl-mirror listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

/// Resolve once either Ctrl-C or, on Unix, SIGTERM is received, so the server can drain and
/// exit cleanly rather than dropping in-flight connections.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut signal) = signal {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
