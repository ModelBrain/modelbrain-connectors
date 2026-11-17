//! Runtime configuration, read once from the environment at start-up.
//!
//! Secrets can be given directly or as `<NAME>_FILE` pointing at a file
//! (the Docker secrets pattern). The Google client can also be given as the
//! JSON file Google Cloud lets you download, via `GOOGLE_OAUTH_JSON_FILE`.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::{env, fs};

/// Which connector this process serves. One process serves one connector,
/// so each connector gets its own address and its own directory listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connector {
    SearchConsole,
}

impl Connector {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "gsc" | "search-console" | "searchconsole" => Some(Self::SearchConsole),
            _ => None,
        }
    }

    /// The single Google scope this connector asks for at sign-in.
    pub fn google_scope(self) -> &'static str {
        match self {
            Self::SearchConsole => "https://www.googleapis.com/auth/webmasters.readonly",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::SearchConsole => "ModelBrain Search Console",
        }
    }

    pub fn server_name(self) -> &'static str {
        match self {
            Self::SearchConsole => "modelbrain-search-console",
        }
    }

    /// The scope name we advertise to MCP clients for our own tokens.
    pub fn local_scope(self) -> &'static str {
        match self {
            Self::SearchConsole => "searchconsole.read",
        }
    }
}

pub struct Config {
    pub bind: String,
    pub base_url: String,
    pub db_path: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub token_key: [u8; 32],
    pub connector: Connector,
    pub extra_redirect_hosts: Vec<String>,
    pub calls_per_minute: u32,
}

fn var_or_file(name: &str) -> Result<Option<String>, String> {
    if let Ok(v) = env::var(name) {
        if !v.trim().is_empty() {
            return Ok(Some(v.trim().to_string()));
        }
    }
    let file_var = format!("{name}_FILE");
    if let Ok(path) = env::var(&file_var) {
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("{file_var}: cannot read {path}: {e}"))?;
        return Ok(Some(text.trim().to_string()));
    }
    Ok(None)
}

fn required(name: &str) -> Result<String, String> {
    var_or_file(name)?.ok_or_else(|| format!("{name} (or {name}_FILE) is not set"))
}

/// Reads the client ID and secret from the JSON Google Cloud downloads for a
/// web client: `{"web": {"client_id": "...", "client_secret": "...", ...}}`.
pub fn parse_google_json(text: &str) -> Result<(String, String), String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Google client JSON is not valid JSON: {e}"))?;
    let web = v.get("web").or_else(|| v.get("installed")).unwrap_or(&v);
    let id = web
        .get("client_id")
        .and_then(|x| x.as_str())
        .ok_or("Google client JSON has no client_id")?;
    let secret = web
        .get("client_secret")
        .and_then(|x| x.as_str())
        .ok_or("Google client JSON has no client_secret")?;
    Ok((id.to_string(), secret.to_string()))
}

pub fn parse_token_key(b64: &str) -> Result<[u8; 32], String> {
    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("TOKEN_KEY is not base64: {e}"))?;
    raw.try_into()
        .map_err(|_| "TOKEN_KEY must decode to exactly 32 bytes (openssl rand -base64 32)".to_string())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let connector = env::var("CONNECTOR").unwrap_or_else(|_| "gsc".into());
        let connector =
            Connector::parse(&connector).ok_or_else(|| format!("unknown CONNECTOR {connector:?}"))?;

        let (google_client_id, google_client_secret) =
            if let Ok(path) = env::var("GOOGLE_OAUTH_JSON_FILE") {
                let text = fs::read_to_string(&path)
                    .map_err(|e| format!("GOOGLE_OAUTH_JSON_FILE: cannot read {path}: {e}"))?;
                parse_google_json(&text)?
            } else {
                (required("GOOGLE_CLIENT_ID")?, required("GOOGLE_CLIENT_SECRET")?)
            };

        let base_url = required("BASE_URL")?.trim_end_matches('/').to_string();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://localhost")) {
            return Err("BASE_URL must be https:// (or http://localhost for testing)".into());
        }

        let extra_redirect_hosts = env::var("EXTRA_REDIRECT_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let calls_per_minute = env::var("CALLS_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Ok(Self {
            bind: env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8787".into()),
            base_url,
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "connectors.db".into()),
            google_client_id,
            google_client_secret,
            token_key: parse_token_key(&required("TOKEN_KEY")?)?,
            connector,
            extra_redirect_hosts,
            calls_per_minute,
        })
    }

    pub fn google_redirect_uri(&self) -> String {
        format!("{}/oauth/google/callback", self.base_url)
    }

    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url)
    }

    /// A config for unit tests; never reads the environment.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            bind: "127.0.0.1:0".into(),
            base_url: "https://gsc.example.test".into(),
            db_path: ":memory:".into(),
            google_client_id: "test-client.apps.googleusercontent.com".into(),
            google_client_secret: "test-secret".into(),
            token_key: [7u8; 32],
            connector: Connector::SearchConsole,
            extra_redirect_hosts: vec![],
            calls_per_minute: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_downloaded_google_json() {
        let json = r#"{"web":{"client_id":"abc.apps.googleusercontent.com","project_id":"p","client_secret":"s3cret","redirect_uris":[]}}"#;
        let (id, secret) = parse_google_json(json).unwrap();
        assert_eq!(id, "abc.apps.googleusercontent.com");
        assert_eq!(secret, "s3cret");
    }

    #[test]
    fn token_key_must_be_32_bytes() {
        assert!(parse_token_key(&STANDARD.encode([1u8; 32])).is_ok());
        assert!(parse_token_key(&STANDARD.encode([1u8; 16])).is_err());
        assert!(parse_token_key("not base64!").is_err());
    }

    #[test]
    fn connector_names() {
        assert_eq!(Connector::parse("gsc"), Some(Connector::SearchConsole));
        assert_eq!(Connector::parse("search-console"), Some(Connector::SearchConsole));
        assert_eq!(Connector::parse("ads"), None);
        assert!(Connector::SearchConsole.google_scope().ends_with("webmasters.readonly"));
    }
}
