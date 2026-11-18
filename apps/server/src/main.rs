use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use oiaf::Archive;
use sc_storage::Catalog;
use shallow_copy_server::{AppState, create_router};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,shallow_copy_server=debug".into()),
        )
        .init();

    let archive_path = env::var("ARCHIVE_PATH").unwrap_or_else(|_| "./data/archive".into());
    let catalog_path =
        env::var("CATALOG_PATH").unwrap_or_else(|_| "./data/state/catalog.sqlite".into());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let archive = match Archive::open(&archive_path) {
        Ok(a) => a,
        Err(_) => {
            info!("Archive not found at {archive_path}; initializing new archive...");
            if let Some(parent) = PathBuf::from(&archive_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            Archive::init(&archive_path)?
        }
    };

    if let Some(parent) = PathBuf::from(&catalog_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let catalog = Catalog::open(&catalog_path)?;

    let state = AppState::new(catalog, archive);
    let app = create_router(state);

    let host = env::var("BIND_ADDR")
        .or_else(|_| env::var("HOST"))
        .unwrap_or_else(|_| "127.0.0.1".into());
    let ip: std::net::IpAddr = host
        .parse()
        .unwrap_or_else(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    if !ip.is_loopback() {
        let token = env::var("BOOTSTRAP_TOKEN").unwrap_or_default();
        if token.trim().is_empty() {
            return Err(
                "non-loopback bind requires a non-empty BOOTSTRAP_TOKEN environment variable for secure first-run setup".into(),
            );
        }
    }
    let addr = SocketAddr::new(ip, port);
    info!("shallow-copy-server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
