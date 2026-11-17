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
            std::fs::create_dir_all(&archive_path)?;
            Archive::init(&archive_path)?
        }
    };

    if let Some(parent) = PathBuf::from(&catalog_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let catalog = Catalog::open(&catalog_path)?;

    let state = AppState::new(catalog, archive);
    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("shallow-copy-server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
