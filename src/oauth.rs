//! OAuth 2.0 authorization server for MCP clients (Claude, ChatGPT, Cursor),
//! with Google as the identity and data provider behind it.
//!
//! Flow: the MCP client registers itself (/register), sends the person to
//! /authorize with a PKCE challenge, we send them on to Google asking for one
//! read-only scope, Google returns to /oauth/google/callback, we keep the
//! Google refresh token (sealed) and hand the client a one-time code, which
//! it swaps at /token for our own short-lived access token.

use crate::{
    crypto::{hash_token, pkce_matches, random_token, seal},
    store::{ClientRow, CodeRow, PendingAuth, TokenKind, ACCESS_TTL, REFRESH_TTL},
    Shared,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::Deserialize;
use serde_json::{json, Value};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/.well-known/openid-configuration", get(as_metadata))
        .route("/.well-known/oauth-protected-resource", get(pr_metadata))
        .route("/.well-known/oauth-protected-resource/mcp", get(pr_metadata))
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/oauth/google/callback", get(google_callback))
        .route("/token", post(token))
}

// ---------------------------------------------------------------------------
// Redirect allowlist
// ---------------------------------------------------------------------------

const ALLOWED_HTTPS_HOSTS: [&str; 7] = [
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "chatgpt.com",
    "openai.com",
    "cursor.com",
    "cursor.sh",
];

fn host_matches(host: &str, base: &str) -> bool {
    host == base || host.ends_with(&format!(".{base}"))
}

/// Which redirect URIs a client may register. Hosted apps must use https on
/// their own domains; local apps may use loopback http or their own scheme.
pub fn redirect_allowed(raw: &str, extra_hosts: &[String]) -> bool {
    let Ok(u) = url::Url::parse(raw) else {
        return false;
    };
    if u.fragment().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => {
            let Some(host) = u.host_str() else {
                return false;
            };
            let host = host.to_ascii_lowercase();
            ALLOWED_HTTPS_HOSTS
                .iter()
                .copied()
                .chain(extra_hosts.iter().map(String::as_str))
                .any(|base| host_matches(&host, base))
        }
        "http" => matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "cursor" | "vscode" | "vscode-insiders" | "windsurf" => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut res = (status, Json(json!({ "error": error, "error_description": description })))
        .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn server_error(e: impl std::fmt::Display) -> Response {
    tracing::error!("internal error: {e}");
    oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A small branded page for the few cases where we cannot hand the person
/// back to their app (bad request, expired sign-in, missing permission).
pub fn message_page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t} | ModelBrain</title>
<style>
body{{margin:0;font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#0d0d0f;color:#e8e6e3}}
main{{max-width:560px;margin:12vh auto;padding:0 20px}}
h1{{font-size:1.4rem;color:#f5b041}}a{{color:#f5b041}}
</style></head><body><main><h1>{t}</h1><p>{b}</p>
<p><a href="https://modelbrain.net/">ModelBrain</a></p></main></body></html>"#,
        t = escape_html(title),
        b = escape_html(body),
    );
    (status, Html(html)).into_response()
}

fn redirect_with(base: &str, pairs: &[(&str, &str)]) -> Response {
    match url::Url::parse(base) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in pairs {
                    q.append_pair(k, v);
                }
            }
            Redirect::to(u.as_str()).into_response()
        }
        Err(_) => message_page(StatusCode::BAD_REQUEST, "Sign-in failed", "The app's return address is not valid."),
    }
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

async fn as_metadata(State(st): State<Shared>) -> Json<Value> {
    let b = &st.cfg.base_url;
    Json(json!({
        "issuer": b,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/token"),
        "registration_endpoint": format!("{b}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [st.cfg.connector.local_scope()],
    }))
}

async fn pr_metadata(State(st): State<Shared>) -> Json<Value> {
    Json(json!({
        "resource": st.cfg.mcp_url(),
        "authorization_servers": [st.cfg.base_url],
        "scopes_supported": [st.cfg.connector.local_scope()],
        "bearer_methods_supported": ["header"],
        "resource_name": st.cfg.connector.display_name(),
    }))
}

/// The 401 every MCP request without a valid token gets, pointing the client
/// at our protected resource metadata so it can start sign-in.
pub fn unauthorized(st: &Shared) -> Response {
    let value = format!(
        r#"Bearer resource_metadata="{}/.well-known/oauth-protected-resource/mcp""#,
        st.cfg.base_url
    );
    let mut res = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid_token", "error_description": "Sign in to use this connector" })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterBody {
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
}

async fn register(State(st): State<Shared>, Json(body): Json<RegisterBody>) -> Response {
    if body.redirect_uris.is_empty() || body.redirect_uris.len() > 10 {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "Give between 1 and 10 redirect_uris");
    }
    if let Some(bad) = body
        .redirect_uris
        .iter()
        .find(|u| u.len() > 512 || !redirect_allowed(u, &st.cfg.extra_redirect_hosts))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("Redirect URI not allowed: {bad}"),
        );
    }
    let client_name: String = body
        .client_name
        .unwrap_or_else(|| "MCP client".into())
        .chars()
        .take(100)
        .collect();
    let row = ClientRow {
        client_id: format!("mbc_{}", random_token(18)),
        client_name,
        redirect_uris: body.redirect_uris,
    };
    if let Err(e) = st.store.insert_client(&row) {
        return server_error(e);
    }
    tracing::info!(event = "client_registered", client = %row.client_name);
    // Public clients only: PKCE protects the code, so no client secret is
    // issued even if one was asked for (RFC 7591 lets the server decide).
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": row.client_id,
            "client_id_issued_at": crate::store::now(),
            "client_name": row.client_name,
            "redirect_uris": row.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Authorization: hand the person to Google
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

async fn authorize(State(st): State<Shared>, Query(q): Query<AuthorizeQuery>) -> Response {
    let bad = |msg: &str| message_page(StatusCode::BAD_REQUEST, "Sign-in could not start", msg);

    let Some(client_id) = q.client_id.as_deref() else {
        return bad("The app did not say who it is (client_id is missing).");
    };
    let client = match st.store.client(client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return bad("This app is not registered here. Remove the connector in your app and add it again."),
        Err(e) => return server_error(e),
    };
    let Some(redirect_uri) = q.redirect_uri.clone() else {
        return bad("The app did not give a return address.");
    };
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return bad("The app's return address does not match the one it registered.");
    }
    if q.response_type.as_deref() != Some("code") {
        return redirect_with(&redirect_uri, &[("error", "unsupported_response_type")]);
    }
    let challenge = q.code_challenge.clone().unwrap_or_default();
    if q.code_challenge_method.as_deref() != Some("S256") || challenge.len() < 43 || challenge.len() > 128 {
        let mut pairs = vec![("error", "invalid_request"), ("error_description", "PKCE with S256 is required")];
        if let Some(s) = q.state.as_deref() {
            pairs.push(("state", s));
        }
        return redirect_with(&redirect_uri, &pairs);
    }

    let pending = PendingAuth {
        id: random_token(24),
        client_id: client.client_id,
        redirect_uri,
        code_challenge: challenge,
        client_state: q.state.map(|s| s.chars().take(1024).collect()),
    };
    if let Err(e) = st.store.insert_pending(&pending) {
        return server_error(e);
    }

    let scope = format!("openid {}", st.cfg.connector.google_scope());
    let google = url::Url::parse_with_params(
        GOOGLE_AUTH_URL,
        &[
            ("client_id", st.cfg.google_client_id.as_str()),
            ("redirect_uri", st.cfg.google_redirect_uri().as_str()),
            ("response_type", "code"),
            ("scope", scope.as_str()),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "false"),
            ("state", pending.id.as_str()),
        ],
    );
    match google {
        Ok(u) => Redirect::to(u.as_str()).into_response(),
        Err(e) => server_error(e),
    }
}

// ---------------------------------------------------------------------------
// Google callback
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    id_token: Option<String>,
}

/// Reads `sub` from a Google ID token received directly from Google's token
/// endpoint over TLS. OpenID Connect Core 3.1.3.7 allows skipping the
/// signature check in that case; audience, issuer and expiry are still checked.
pub fn sub_from_id_token(id_token: &str, client_id: &str, now: i64) -> Result<String, String> {
    let payload = id_token.split('.').nth(1).ok_or("ID token is malformed")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "ID token payload is not base64url")?;
    let claims: Value = serde_json::from_slice(&bytes).map_err(|_| "ID token payload is not JSON")?;
    let aud_ok = match &claims["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(list) => list.iter().any(|a| a.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err("ID token audience does not match".into());
    }
    let iss = claims["iss"].as_str().unwrap_or_default();
    if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
        return Err("ID token issuer is not Google".into());
    }
    if claims["exp"].as_i64().unwrap_or(0) < now {
        return Err("ID token has expired".into());
    }
    claims["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "ID token has no subject".into())
}

/// Google returns granted scopes space-separated, sometimes in short form.
pub fn scope_granted(granted: &str, wanted: &str) -> bool {
    granted.split_whitespace().any(|s| s == wanted)
}

async fn google_callback(State(st): State<Shared>, Query(q): Query<CallbackQuery>) -> Response {
    let pending = match q.state.as_deref() {
        Some(id) => match st.store.take_pending(id) {
            Ok(Some(p)) => p,
            Ok(None) => {
                return message_page(
                    StatusCode::BAD_REQUEST,
                    "Sign-in expired",
                    "This sign-in link has expired or was already used. Go back to your app and connect again.",
                )
            }
            Err(e) => return server_error(e),
        },
        None => return message_page(StatusCode::BAD_REQUEST, "Sign-in failed", "Google did not return a sign-in state."),
    };

    let back_with_error = |err: &str, desc: &str| {
        let mut pairs = vec![("error", err), ("error_description", desc)];
        if let Some(s) = pending.client_state.as_deref() {
            pairs.push(("state", s));
        }
        redirect_with(&pending.redirect_uri, &pairs)
    };

    if q.error.is_some() {
        return back_with_error("access_denied", "Google sign-in was cancelled");
    }
    let Some(code) = q.code else {
        return back_with_error("access_denied", "Google did not return a code");
    };

    let redirect = st.cfg.google_redirect_uri();
    let res = st
        .http
        .post(GOOGLE_TOKEN_URL)
        .form(&[
            ("code", code.as_str()),
            ("client_id", st.cfg.google_client_id.as_str()),
            ("client_secret", st.cfg.google_client_secret.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;
    let tok: GoogleTokenResponse = match res {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(t) => t,
            Err(e) => return server_error(format!("Google token response: {e}")),
        },
        Ok(r) => {
            tracing::warn!(event = "google_code_exchange_failed", status = %r.status());
            return back_with_error("server_error", "Google sign-in could not be completed");
        }
        Err(e) => return server_error(format!("Google token request: {e}")),
    };

    let wanted = st.cfg.connector.google_scope();
    if !scope_granted(&tok.scope, wanted) {
        return message_page(
            StatusCode::FORBIDDEN,
            "Search Console access was not granted",
            "The connector needs read-only access to Search Console. Go back to your app, connect again, and tick the Search Console box on Google's screen.",
        );
    }

    let sub = match tok
        .id_token
        .as_deref()
        .ok_or_else(|| "Google did not return an ID token".to_string())
        .and_then(|t| sub_from_id_token(t, &st.cfg.google_client_id, crate::store::now()))
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(event = "id_token_rejected", reason = %e);
            return back_with_error("server_error", "Google sign-in could not be verified");
        }
    };

    match tok.refresh_token.as_deref() {
        Some(rt) => {
            let sealed = match seal(&st.cfg.token_key, &sub, rt) {
                Ok(s) => s,
                Err(e) => return server_error(e),
            };
            if let Err(e) = st.store.upsert_account(&sub, &sealed, wanted) {
                return server_error(e);
            }
        }
        None => match st.store.account_exists(&sub) {
            Ok(true) => {}
            Ok(false) => return back_with_error("server_error", "Google did not return offline access"),
            Err(e) => return server_error(e),
        },
    }
    st.google.put(&sub, &tok.access_token, tok.expires_in);

    let our_code = random_token(32);
    let row = CodeRow {
        client_id: pending.client_id.clone(),
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge.clone(),
        sub,
    };
    if let Err(e) = st.store.insert_code(&hash_token(&our_code), &row) {
        return server_error(e);
    }
    tracing::info!(event = "signed_in");

    let mut pairs = vec![("code", our_code.as_str())];
    if let Some(s) = pending.client_state.as_deref() {
        pairs.push(("state", s));
    }
    redirect_with(&pending.redirect_uri, &pairs)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// client_id from the form, or from HTTP Basic if the client sends it there.
fn client_id_from(form: &TokenForm, headers: &HeaderMap) -> Option<String> {
    if let Some(id) = form.client_id.as_ref().filter(|s| !s.is_empty()) {
        return Some(id.clone());
    }
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = auth.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(b64.trim()).ok()?).ok()?;
    let id = decoded.split(':').next()?;
    let id = percent_encoding::percent_decode_str(id).decode_utf8().ok()?;
    Some(id.into_owned())
}

fn issue_tokens(st: &Shared, client_id: &str, sub: &str) -> Response {
    let access = random_token(32);
    let refresh = random_token(32);
    let r1 = st
        .store
        .insert_token(&hash_token(&access), TokenKind::Access, client_id, sub, ACCESS_TTL);
    let r2 = st
        .store
        .insert_token(&hash_token(&refresh), TokenKind::Refresh, client_id, sub, REFRESH_TTL);
    if let Err(e) = r1.and(r2) {
        return server_error(e);
    }
    let mut res = Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh,
        "scope": st.cfg.connector.local_scope(),
    }))
    .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

async fn token(State(st): State<Shared>, headers: HeaderMap, Form(form): Form<TokenForm>) -> Response {
    let client_id = client_id_from(&form, &headers);
    match form.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier)) = (form.code.as_deref(), form.code_verifier.as_deref()) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code and code_verifier are required");
            };
            let row = match st.store.take_code(&hash_token(code)) {
                Ok(Some(r)) => r,
                Ok(None) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Code is invalid or expired"),
                Err(e) => return server_error(e),
            };
            if client_id.as_deref() != Some(row.client_id.as_str()) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Code was issued to another client");
            }
            if form.redirect_uri.as_deref().is_some_and(|r| r != row.redirect_uri) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri does not match");
            }
            if !pkce_matches(verifier, &row.code_challenge) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
            }
            issue_tokens(&st, &row.client_id, &row.sub)
        }
        "refresh_token" => {
            let Some(rt) = form.refresh_token.as_deref() else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is required");
            };
            let hash = hash_token(rt);
            let (sub, owner) = match st.store.token(&hash, TokenKind::Refresh) {
                Ok(Some(v)) => v,
                Ok(None) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Refresh token is invalid or expired"),
                Err(e) => return server_error(e),
            };
            if client_id.as_deref().is_some_and(|c| c != owner) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Refresh token was issued to another client");
            }
            // Rotation: the old refresh token stops working now.
            if let Err(e) = st.store.delete_token(&hash) {
                return server_error(e);
            }
            match st.store.account_exists(&sub) {
                Ok(true) => issue_tokens(&st, &owner, &sub),
                Ok(false) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Google access was removed; sign in again"),
                Err(e) => server_error(e),
            }
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "Use authorization_code or refresh_token"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist() {
        let none: Vec<String> = vec![];
        assert!(redirect_allowed("https://claude.ai/api/mcp/auth_callback", &none));
        assert!(redirect_allowed("https://chatgpt.com/connector_platform_oauth_redirect", &none));
        assert!(redirect_allowed("https://www.cursor.com/cb", &none));
        assert!(redirect_allowed("http://localhost:6274/oauth/callback", &none));
        assert!(redirect_allowed("http://127.0.0.1:33418/cb", &none));
        assert!(redirect_allowed("http://[::1]:8080/cb", &none));
        assert!(redirect_allowed("cursor://anysphere.cursor-retrieval/oauth/callback", &none));
        assert!(redirect_allowed("vscode://cb", &none));

        assert!(!redirect_allowed("https://evil.com/cb", &none));
        assert!(!redirect_allowed("https://claude.ai.evil.com/cb", &none));
        assert!(!redirect_allowed("https://notclaude.ai/cb", &none));
        assert!(!redirect_allowed("http://claude.ai/cb", &none));
        assert!(!redirect_allowed("http://192.168.1.5/cb", &none));
        assert!(!redirect_allowed("https://claude.ai/cb#frag", &none));
        assert!(!redirect_allowed("javascript:alert(1)", &none));
        assert!(!redirect_allowed("not a url", &none));

        let extra = vec!["example.dev".to_string()];
        assert!(redirect_allowed("https://app.example.dev/cb", &extra));
    }

    fn fake_id_token(claims: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let p = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{h}.{p}.sig")
    }

    #[test]
    fn id_token_checks() {
        let now = 1_800_000_000;
        let good = fake_id_token(json!({"iss":"https://accounts.google.com","aud":"cid","sub":"1234","exp":now+600}));
        assert_eq!(sub_from_id_token(&good, "cid", now).unwrap(), "1234");

        let wrong_aud = fake_id_token(json!({"iss":"https://accounts.google.com","aud":"other","sub":"1","exp":now+600}));
        assert!(sub_from_id_token(&wrong_aud, "cid", now).is_err());

        let wrong_iss = fake_id_token(json!({"iss":"https://evil.example","aud":"cid","sub":"1","exp":now+600}));
        assert!(sub_from_id_token(&wrong_iss, "cid", now).is_err());

        let expired = fake_id_token(json!({"iss":"accounts.google.com","aud":"cid","sub":"1","exp":now-1}));
        assert!(sub_from_id_token(&expired, "cid", now).is_err());

        assert!(sub_from_id_token("garbage", "cid", now).is_err());
    }

    #[test]
    fn scope_check() {
        let w = "https://www.googleapis.com/auth/webmasters.readonly";
        assert!(scope_granted(&format!("openid {w}"), w));
        assert!(!scope_granted("openid", w));
        assert!(!scope_granted("https://www.googleapis.com/auth/webmasters.readonly.extra", w));
    }

    #[test]
    fn basic_auth_client_id() {
        let form = TokenForm {
            grant_type: "authorization_code".into(),
            code: None,
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            refresh_token: None,
        };
        let mut h = HeaderMap::new();
        let v = format!("Basic {}", STANDARD.encode("mbc_abc:"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(&v).unwrap());
        assert_eq!(client_id_from(&form, &h).as_deref(), Some("mbc_abc"));
        assert_eq!(client_id_from(&form, &HeaderMap::new()), None);
    }
}
