//! STARK Prove/Verify server with OAuth2 token-based API security.
//!
//! Environment configuration:
//!   STARK_STORE_DIR      — proof store directory (default: ./stark-proofs)
//!   STARK_PORT           — TCP port (default: 3000)
//!   STARK_AUTH_DB        — SQLite path for users + tokens (default: ./stark-auth.sqlite)
//!   STARK_ADMIN_USER     — bootstrap admin username (default: admin)
//!   STARK_ADMIN_PASSWORD — bootstrap admin password (default: random; printed to STDERR + saved to file)
//!   STARK_BOOTSTRAP_FILE — file path to write the initial bootstrap token
//!                          (default: ./stark-bootstrap.txt; mode 0600 if creatable)
//!
//! The bootstrap admin + initial bearer token are created **only on first
//! run** (idempotent — subsequent starts re-use the existing user / tokens).

use std::net::SocketAddr;
use std::path::PathBuf;

use rand::{rngs::OsRng, RngCore};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use api::{AppState, build_router};
use auth::AuthDb;
use proof_store::ProofStore;

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("stark_server=info".parse().unwrap())
            .add_directive("api=info".parse().unwrap())
            .add_directive("auth=info".parse().unwrap()))
        .init();

    // ── Configuration ─────────────────────────────────────────────────────
    let store_dir = std::env::var("STARK_STORE_DIR")
        .unwrap_or_else(|_| "./stark-proofs".into());
    let port: u16 = std::env::var("STARK_PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(3000);
    let auth_db_path: PathBuf = std::env::var("STARK_AUTH_DB")
        .unwrap_or_else(|_| "./stark-auth.sqlite".into()).into();
    let admin_username = std::env::var("STARK_ADMIN_USER")
        .unwrap_or_else(|_| "admin".into());
    let admin_password = std::env::var("STARK_ADMIN_PASSWORD")
        .unwrap_or_else(|_| generate_random_password());
    let bootstrap_file: PathBuf = std::env::var("STARK_BOOTSTRAP_FILE")
        .unwrap_or_else(|_| "./stark-bootstrap.txt".into()).into();

    // ── Auth DB + admin bootstrap ─────────────────────────────────────────
    let auth_db = AuthDb::open(&auth_db_path)
        .expect("failed to open auth database");
    info!("Auth database at: {}", auth_db_path.display());

    let bootstrap_token = match auth_db.bootstrap_admin(
        &admin_username, &admin_password, "bootstrap-token",
    ) {
        Ok((user, tok)) => {
            info!("Admin user: {} (id={}, is_admin={})", user.username, user.id, user.is_admin);
            tok
        }
        Err(e) => {
            eprintln!("auth bootstrap failed: {e}");
            std::process::exit(1);
        }
    };

    if let Some(tok) = bootstrap_token {
        // First-run bootstrap: write the bearer + admin password to a file
        // (mode 0600 on Unix) and log them to STDERR.
        let body = format!(
            "STARK API bootstrap credentials\n\
             ===============================\n\
             admin username:   {}\n\
             admin password:   {}\n\
             bearer token:     {}\n\
             token id:         {}\n\
             scope:            {}\n\n\
             USE the bearer token in API requests:\n  \
             curl -H 'Authorization: Bearer {}' http://<host>:{}/v1/security/profiles\n\n\
             LOG IN to the admin web UI:\n  \
             http://<host>:{}/admin/login\n",
            admin_username, admin_password, tok.bearer,
            tok.info.id, tok.info.scope, tok.bearer, port, port,
        );
        if let Err(e) = write_bootstrap_file(&bootstrap_file, &body) {
            warn!("could not write bootstrap file {}: {e}", bootstrap_file.display());
        }
        eprintln!("\n=================================================================");
        eprintln!("{body}");
        eprintln!("Bootstrap details also written to: {}", bootstrap_file.display());
        eprintln!("=================================================================\n");
    } else {
        info!("Admin already initialised; existing bearer tokens preserved.");
    }

    // ── Proof store ───────────────────────────────────────────────────────
    let store = ProofStore::new(&store_dir)
        .expect("failed to initialise proof store");
    info!("Proof store at: {store_dir}");

    // ── Router ────────────────────────────────────────────────────────────
    let state = AppState::new(store, auth_db);
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on http://{addr}");
    info!("Admin UI: http://{addr}/admin/login");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    axum::serve(listener, app).await.expect("server error");
}

fn generate_random_password() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn write_bootstrap_file(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() { std::fs::create_dir_all(parent)?; }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(body.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, body)?;
    }
    Ok(())
}
