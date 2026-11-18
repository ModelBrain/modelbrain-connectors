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
        .route("/authorize/consent", post(consent))
        .route("/oauth/google/callback", get(google_callback))
        .route("/token", post(token))
}

// ---------------------------------------------------------------------------
// Redirect rule and known apps
// ---------------------------------------------------------------------------

/// Apps whose sign-in addresses are on these domains go straight to Google: Claude, ChatGPT and
/// Cursor, plus any host in EXTRA_REDIRECT_HOSTS. Any other app sees our consent page first. This
/// list decides that one step, never whether an app may connect.
const KNOWN_HTTPS_HOSTS: [&str; 7] = [
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

fn loopback(u: &url::Url) -> bool {
    u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Which redirect addresses a client may use. Any app may connect (MCP authorization: dynamic
/// registration and client metadata documents), so this is about the address's shape, not which
/// app it is: https on a DNS name with the default port and no query, loopback http on any port
/// (RFC 8252), or a desktop editor's own scheme. Never userinfo or a fragment.
pub fn redirect_allowed(raw: &str) -> bool {
    if raw.len() > 512 || raw.chars().any(|c| c.is_control() || c == ' ' || c == '\\') {
        return false;
    }
    let Ok(u) = url::Url::parse(raw) else {
        return false;
    };
    if u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => {
            matches!(u.host(), Some(url::Host::Domain(h)) if h.contains('.'))
                && u.port().is_none()
                && u.query().is_none()
                && u.path().len() > 1
        }
        "http" => loopback(&u),
        "cursor" | "vscode" | "vscode-insiders" | "windsurf" => true,
        _ => false,
    }
}

/// Whether a sign-in may go straight to Google, or shows our consent page first. A Google consent
/// screen names this connector, not the app that receives the access, so for an app that is not a
/// known one the person confirms the app here. Loopback and editor-scheme addresses come back to
/// the person's own computer, so they need no extra step.
pub fn needs_consent(redirect_uri: &str, client_id: &str, extra_hosts: &[String]) -> bool {
    let Ok(u) = url::Url::parse(redirect_uri) else {
        return true;
    };
    if u.scheme() != "https" {
        return false;
    }
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    let known = |h: &str| {
        KNOWN_HTTPS_HOSTS
            .iter()
            .copied()
            .chain(extra_hosts.iter().map(String::as_str))
            .any(|base| host_matches(h, base))
    };
    if known(&host) {
        return false;
    }
    // A metadata document app on a trusted domain is known too.
    !crate::client_meta::host_of(client_id).is_some_and(|h| known(&h))
}

/// Exact match, except that loopback addresses may use any port (RFC 8252
/// section 7.3): local apps such as the MCP Inspector pick a port each run.
pub fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(a), Ok(b)) = (url::Url::parse(registered), url::Url::parse(requested)) else {
        return false;
    };
    loopback(&a)
        && loopback(&b)
        && a.host_str() == b.host_str()
        && a.path() == b.path()
        && a.query() == b.query()
        && b.fragment().is_none()
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
        // An app may use an https URL as its client_id instead of registering.
        "client_id_metadata_document_supported": true,
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
        .find(|u| !redirect_allowed(u))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("Redirect URI not allowed: {bad}. Use https with the default port and no query, loopback http, or an editor's own scheme."),
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
    let client = match resolve_client(&st, client_id).await {
        Ok(Some(c)) => c,
        Ok(None) if crate::client_meta::is_document_url(client_id) => {
            return bad("This app's sign-in details could not be read from its website. Try again in a minute, or contact the app's makers.")
        }
        Ok(None) => return bad("This app is not registered here. Remove the connector in your app and add it again."),
        Err(e) => return server_error(e),
    };
    let Some(redirect_uri) = q.redirect_uri.clone() else {
        return bad("The app did not give a return address.");
    };
    if !client.redirect_uris.iter().any(|u| redirect_matches(u, &redirect_uri)) {
        tracing::warn!(
            event = "redirect_mismatch",
            client = %client.client_name,
            requested = %redirect_uri,
            registered = ?client.redirect_uris
        );
        return bad("The app's return address does not match the one it registered. Remove the connector in your app and add it again.");
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
    if needs_consent(&pending.redirect_uri, &pending.client_id, &st.cfg.extra_redirect_hosts) {
        return consent_page(&st, pending, &client.client_name);
    }
    if let Err(e) = st.store.insert_pending(&pending) {
        return server_error(e);
    }
    to_google(&st, &pending.id)
}

/// A client by the id the app presents: a registered one, or a metadata document URL, fetched and
/// checked on first use and again once the stored copy is an hour old. A copy up to a day old
/// stands in when the app's server does not answer.
async fn resolve_client(st: &Shared, client_id: &str) -> rusqlite::Result<Option<ClientRow>> {
    if !crate::client_meta::is_document_url(client_id) {
        return st.store.client(client_id);
    }
    let stored = st.store.client_with_age(client_id)?;
    let now = crate::store::now();
    if let Some((row, checked)) = &stored {
        if now - checked < crate::client_meta::FRESH_SECS {
            return Ok(Some(row.clone()));
        }
    }
    let Some(body) = crate::client_meta::fetch(client_id).await else {
        return Ok(stored.filter(|(_, checked)| now - checked < 24 * 3600).map(|(r, _)| r));
    };
    let Some((name, uris)) = crate::client_meta::parse_document(client_id, &body, redirect_allowed) else {
        tracing::info!(event = "client_metadata_invalid", host = ?crate::client_meta::host_of(client_id));
        return Ok(None);
    };
    let row = ClientRow { client_id: client_id.to_string(), client_name: name, redirect_uris: uris };
    st.store.upsert_client(&row)?;
    tracing::info!(event = "client_metadata_checked", host = ?crate::client_meta::host_of(client_id));
    Ok(Some(row))
}

const CONSENT_COOKIE: &str = "__Host-mbc_consent";

/// One cookie per sign-in, named by its id, so a second sign-in page opened in the same browser
/// (an app that loads the authorize address twice, or a retry while an old window is open) does
/// not overwrite the first page's cookie.
fn consent_cookie(id: &str) -> String {
    format!("{CONSENT_COOKIE}_{id}")
}
const CONSENT_TTL: i64 = 600;

/// A sign-in waiting for the person to confirm the app, held in memory (a restart only means
/// starting again). Nothing reaches the pending table, and so Google, until the person confirms
/// in the same browser: the cookie set with this page must come back with the form.
pub struct Consent {
    pending: PendingAuth,
    cookie_hash: String,
    expires: i64,
}

fn consent_page(st: &Shared, pending: PendingAuth, client_name: &str) -> Response {
    let cookie = random_token(24);
    let id = pending.id.clone();
    let host = url::Url::parse(&pending.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let verified = crate::client_meta::host_of(&pending.client_id);
    {
        let mut map = st.consents.lock().unwrap_or_else(|e| e.into_inner());
        let now = crate::store::now();
        map.retain(|_, c| c.expires > now);
        if map.len() > 5000 {
            return message_page(StatusCode::SERVICE_UNAVAILABLE, "Busy", "Too many sign-ins are waiting. Try again in a few minutes.");
        }
        map.insert(id.clone(), Consent { pending, cookie_hash: hash_token(&cookie), expires: now + CONSENT_TTL });
    }
    let who = match &verified {
        Some(v) if *v == host => format!("<strong>{}</strong> ({})", escape_html(client_name), escape_html(v)),
        Some(v) => format!(
            "<strong>{}</strong> ({}), which sends access to <strong>{}</strong>",
            escape_html(client_name),
            escape_html(v),
            escape_html(&host)
        ),
        None => format!(
            "An app calling itself <strong>{}</strong>, which sends access to <strong>{}</strong>. Anyone can give an app any name, so continue only if you started this yourself just now.",
            escape_html(client_name),
            escape_html(&host)
        ),
    };
    let name = escape_html(st.cfg.connector.display_name());
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Connect {name} | ModelBrain</title>
<style>
body{{margin:0;font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#0d0d0f;color:#e8e6e3}}
main{{max-width:560px;margin:12vh auto;padding:0 20px}}
h1{{font-size:1.4rem;color:#f5b041}}a{{color:#f5b041}}
button{{font:inherit;padding:10px 18px;border-radius:6px;border:1px solid #f5b041;margin-right:10px;cursor:pointer}}
.go{{background:#f5b041;color:#0d0d0f}}.no{{background:transparent;color:#e8e6e3}}
</style></head><body><main><h1>Connect {name}</h1>
<p>{who} wants read-only access to your Google Search Console data.</p>
<p>Next, Google asks you to choose an account and allow access.</p>
<form method="post" action="/authorize/consent">
<input type="hidden" name="id" value="{id}">
<button class="go" type="submit" name="action" value="allow">Continue with Google</button>
<button class="no" type="submit" name="action" value="deny">Cancel</button>
</form></main></body></html>"#,
        id = escape_html(&id),
    );
    let mut res = (StatusCode::OK, Html(html)).into_response();
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={CONSENT_TTL}",
        consent_cookie(&id)
    )) {
        h.insert(header::SET_COOKIE, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("frame-ancestors 'none'"));
    res
}

#[derive(Deserialize)]
struct ConsentForm {
    id: String,
    action: String,
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

async fn consent(State(st): State<Shared>, headers: HeaderMap, Form(f): Form<ConsentForm>) -> Response {
    let expired = || {
        message_page(
            StatusCode::BAD_REQUEST,
            "Sign-in expired",
            "This sign-in expired, was already used, or was opened in another browser. Go back to your app and connect again.",
        )
    };
    let cookie_hash = cookie_value(&headers, &consent_cookie(&f.id)).map(|c| hash_token(&c));
    let waiting = {
        let mut map = st.consents.lock().unwrap_or_else(|e| e.into_inner());
        // Taken whatever happens next: one answer per page.
        map.remove(&f.id)
    };
    let Some(c) = waiting else {
        return expired();
    };
    if c.expires <= crate::store::now() || cookie_hash.as_deref() != Some(c.cookie_hash.as_str()) {
        return expired();
    }
    if f.action != "allow" {
        let mut pairs = vec![("error", "access_denied"), ("error_description", "The person cancelled")];
        if let Some(s) = c.pending.client_state.as_deref() {
            pairs.push(("state", s));
        }
        return redirect_with(&c.pending.redirect_uri, &pairs);
    }
    if let Err(e) = st.store.insert_pending(&c.pending) {
        return server_error(e);
    }
    let mut res = to_google(&st, &c.pending.id);
    if let Ok(v) = HeaderValue::from_str(&format!("{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0", consent_cookie(&c.pending.id))) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

/// Sends the browser to Google for one read-only scope, carrying the pending sign-in's id.
fn to_google(st: &Shared, pending_id: &str) -> Response {
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
            ("state", pending_id),
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
    fn redirect_rule_is_about_shape() {
        for ok in [
            "https://claude.ai/api/mcp/auth_callback",
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://www.cursor.com/cb",
            "https://glama.ai/oauth/callback",
            "http://localhost:6274/oauth/callback",
            "http://127.0.0.1:33418/cb",
            "http://[::1]:8080/cb",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
            "vscode://cb",
        ] {
            assert!(redirect_allowed(ok), "{ok}");
        }
        for bad in [
            "http://claude.ai/cb",
            "http://192.168.1.5/cb",
            "https://claude.ai/cb#frag",
            "https://claude.ai/cb?next=x",
            "https://claude.ai:8443/cb",
            "https://10.0.0.1/cb",
            "https://localhost/cb",
            "https://user@claude.ai/cb",
            "https://claude.ai",
            "javascript:alert(1)",
            "not a url",
        ] {
            assert!(!redirect_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn known_apps_skip_the_consent_page_and_others_do_not() {
        let none: Vec<String> = vec![];
        assert!(!needs_consent("https://claude.ai/api/mcp/auth_callback", "mbc_x", &none));
        assert!(!needs_consent("https://chatgpt.com/connector_platform_oauth_redirect", "mbc_x", &none));
        assert!(!needs_consent("http://localhost:6274/oauth/callback", "mbc_x", &none));
        assert!(!needs_consent("cursor://anysphere.cursor-retrieval/oauth/callback", "mbc_x", &none));
        assert!(needs_consent("https://glama.ai/oauth/callback", "mbc_x", &none));
        assert!(needs_consent("https://claude.ai.evil.com/cb", "mbc_x", &none));
        // A metadata document proves the app's domain, but only a known domain skips the page.
        assert!(needs_consent("https://glama.ai/cb", "https://glama.ai/oauth/client.json", &none));
        let extra = vec!["glama.ai".to_string()];
        assert!(!needs_consent("https://glama.ai/cb", "mbc_x", &extra));
        assert!(!needs_consent("https://cb.example.com/cb", "https://glama.ai/oauth/client.json", &extra));
    }

    fn state() -> Shared {
        let cfg = crate::config::Config::for_tests();
        std::sync::Arc::new(crate::AppState {
            limiter: crate::mcp::RateLimiter::new(cfg.calls_per_minute),
            cfg,
            store: crate::store::Store::open_in_memory().unwrap(),
            http: reqwest::Client::new(),
            google: crate::google::Google::default(),
            consents: Default::default(),
        })
    }

    fn waiting(id: &str) -> PendingAuth {
        PendingAuth {
            id: id.into(),
            client_id: "mbc_test".into(),
            redirect_uri: "https://glama.ai/oauth/callback".into(),
            code_challenge: "c".repeat(43),
            client_state: Some("s1".into()),
        }
    }

    fn set_cookie(res: &Response) -> String {
        let v = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        v.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn the_consent_page_names_the_destination_and_needs_its_own_browser() {
        let st = state();
        let res = consent_page(&st, waiting("p1"), "Totally ChatGPT");
        let cookie = set_cookie(&res);
        assert!(cookie.starts_with("__Host-mbc_consent_p1="));
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
        // The form's answer is a redirect to Google or back to the app, so form-action must not
        // pin it to this host (browsers apply form-action to the redirect too).
        let csp = res.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && !csp.contains("form-action"), "{csp}");
        let body = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("glama.ai") && html.contains("Anyone can give an app any name"));
        // Nothing reaches Google's pending table before the person confirms.
        assert!(st.store.take_pending("p1").unwrap().is_none());

        // Another browser (no cookie) gets nothing, and the request is spent.
        let res = consent(State(st.clone()), HeaderMap::new(), Form(ConsentForm { id: "p1".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(st.store.take_pending("p1").unwrap().is_none());

        // The right browser goes on to Google.
        let res = consent_page(&st, waiting("p2"), "Glama");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&set_cookie(&res)).unwrap());
        let res = consent(State(st.clone()), h.clone(), Form(ConsentForm { id: "p2".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert!(res.headers().get(header::LOCATION).unwrap().to_str().unwrap().starts_with(GOOGLE_AUTH_URL));
        assert!(st.store.take_pending("p2").unwrap().is_some());
        // Used once.
        let res = consent(State(st.clone()), h, Form(ConsentForm { id: "p2".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Cancel goes back to the app with access_denied.
        let res = consent_page(&st, waiting("p3"), "Glama");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&set_cookie(&res)).unwrap());
        let res = consent(State(st.clone()), h, Form(ConsentForm { id: "p3".into(), action: "deny".into() })).await;
        let loc = res.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert!(loc.starts_with("https://glama.ai/oauth/callback?error=access_denied") && loc.contains("state=s1"));
        assert!(st.store.take_pending("p3").unwrap().is_none());
    }

    #[tokio::test]
    async fn two_sign_in_pages_in_one_browser_each_keep_their_cookie() {
        let st = state();
        let first = consent_page(&st, waiting("a1"), "Glama");
        let second = consent_page(&st, waiting("a2"), "Glama");
        // The browser now holds both cookies; answering the first page still works.
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{}; {}", set_cookie(&first), set_cookie(&second))).unwrap(),
        );
        let res = consent(State(st.clone()), h.clone(), Form(ConsentForm { id: "a1".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = consent(State(st.clone()), h, Form(ConsentForm { id: "a2".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        // One page's cookie does not answer another page.
        let third = consent_page(&st, waiting("a3"), "Glama");
        let _ = third;
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&set_cookie(&first).replace("_a1=", "_a3=")).unwrap());
        let res = consent(State(st.clone()), h, Form(ConsentForm { id: "a3".into(), action: "allow".into() })).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn loopback_ports_may_vary() {
        assert!(redirect_matches("https://claude.ai/cb", "https://claude.ai/cb"));
        assert!(!redirect_matches("https://claude.ai/cb", "https://claude.ai/other"));
        assert!(redirect_matches("http://localhost:6274/oauth/callback", "http://localhost:6277/oauth/callback"));
        assert!(redirect_matches("http://127.0.0.1/cb", "http://127.0.0.1:5000/cb"));
        assert!(!redirect_matches("http://localhost:6274/oauth/callback", "http://localhost:6274/evil"));
        assert!(!redirect_matches("http://localhost:6274/cb", "http://127.0.0.1:6274/cb"));
        assert!(!redirect_matches("https://claude.ai:443/cb", "https://claude.ai:8443/cb"));
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
