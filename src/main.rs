//! ModelBrain free connectors: hosted, read-only MCP servers.
//! One process serves one connector (CONNECTOR=gsc for Search Console).

mod config;
mod crypto;
mod google;
mod gsc;
mod mcp;
mod oauth;
mod store;

use axum::{
    response::Html,
    routing::{get, post},
    Router,
};
use std::{sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;

pub struct AppState {
    pub cfg: config::Config,
    pub store: store::Store,
    pub http: reqwest::Client,
    pub google: google::Google,
    pub limiter: mcp::RateLimiter,
}

pub type Shared = Arc<AppState>;

fn landing_html(st: &AppState) -> String {
    let name = st.cfg.connector.display_name();
    let url = st.cfg.mcp_url();
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name} | free MCP connector</title>
<link rel="canonical" href="https://modelbrain.net/">
<style>
body{{margin:0;font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#0d0d0f;color:#e8e6e3}}
main{{max-width:640px;margin:10vh auto;padding:0 20px}}
h1{{font-size:1.6rem;color:#f5b041}}a{{color:#f5b041}}
code{{background:#1b1b1f;padding:2px 6px;border-radius:4px;word-break:break-all}}
</style></head><body><main>
<h1>{name}</h1>
<p>A free, read-only Google Search Console connector for Claude, ChatGPT and Cursor. Every property you own, the full 16 months, no setup.</p>
<p>Add this address as a custom connector in your app:</p>
<p><code>{url}</code></p>
<p>We keep your Google account ID and an encrypted sign-in token, nothing else. Search data passes straight through and is never stored.</p>
<p>Made by <a href="https://modelbrain.net/">ModelBrain</a>, the memory layer that gives your assistants one shared memory.</p>
</main></body></html>"#
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route(
            "/",
            get(|axum::extract::State(st): axum::extract::State<Shared>| async move { Html(landing_html(&st)) }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/mcp", post(mcp::handle).get(mcp::not_allowed).delete(mcp::not_allowed))
        .merge(oauth::routes())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    let store = match store::Store::open(&cfg.db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open database {}: {e}", cfg.db_path);
            std::process::exit(2);
        }
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("modelbrain-connectors/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client");

    let state: Shared = Arc::new(AppState {
        limiter: mcp::RateLimiter::new(cfg.calls_per_minute),
        cfg,
        store,
        http,
        google: google::Google::default(),
    });

    let purge = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            if let Err(e) = purge.store.purge_expired() {
                tracing::warn!("purge: {e}");
            }
            purge.limiter.purge();
            purge.google.purge();
        }
    });

    let bind = state.cfg.bind.clone();
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {bind}: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(
        connector = state.cfg.connector.server_name(),
        base_url = %state.cfg.base_url,
        "listening on {bind}"
    );
    if let Err(e) = axum::serve(listener, app(state)).with_graceful_shutdown(shutdown_signal()).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Shared {
        let cfg = config::Config::for_tests();
        Arc::new(AppState {
            limiter: mcp::RateLimiter::new(cfg.calls_per_minute),
            cfg,
            store: store::Store::open_in_memory().unwrap(),
            http: reqwest::Client::new(),
            google: google::Google::default(),
        })
    }

    #[test]
    fn router_builds_and_landing_has_no_em_dash() {
        let st = test_state();
        let html = landing_html(&st);
        assert!(html.contains("https://gsc.example.test/mcp"));
        assert!(!html.contains('\u{2014}'));
        let _router = app(st);
    }
}
