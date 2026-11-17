//! Calls to Google APIs on behalf of a signed-in account.
//!
//! Access tokens live only in memory and are refreshed from the sealed
//! refresh token when they are close to expiry. If Google says the refresh
//! token is no longer valid (the person removed access, or changed their
//! password), the account is marked revoked and every token we issued for it
//! is dropped, so the MCP client is asked to sign in again.

use crate::{crypto::open, store::now, AppState};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashMap, sync::Mutex};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const EXPIRY_MARGIN: i64 = 120;

pub const RECONNECT: &str = "Your Google sign-in for this connector has expired or was removed. \
Remove and add the connector again in your app (or use its Reconnect button) to continue.";

#[derive(Default)]
pub struct Google {
    cache: Mutex<HashMap<String, (String, i64)>>,
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
}

impl Google {
    pub fn put(&self, sub: &str, token: &str, expires_in: i64) {
        let expires = now() + expires_in.max(60);
        if let Ok(mut c) = self.cache.lock() {
            c.insert(sub.to_string(), (token.to_string(), expires));
        }
    }

    pub fn forget(&self, sub: &str) {
        if let Ok(mut c) = self.cache.lock() {
            c.remove(sub);
        }
    }

    fn cached(&self, sub: &str) -> Option<String> {
        let c = self.cache.lock().ok()?;
        c.get(sub)
            .filter(|(_, exp)| *exp - EXPIRY_MARGIN > now())
            .map(|(t, _)| t.clone())
    }

    pub fn purge(&self) {
        let t = now();
        if let Ok(mut c) = self.cache.lock() {
            c.retain(|_, (_, exp)| *exp > t);
        }
    }
}

async fn refresh(st: &AppState, sub: &str) -> Result<String, String> {
    let sealed = match st.store.account_refresh(sub) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(RECONNECT.into()),
        Err(e) => return Err(format!("Internal storage error: {e}")),
    };
    let refresh_token = open(&st.cfg.token_key, sub, &sealed).map_err(|_| RECONNECT.to_string())?;
    let res = st
        .http
        .post(TOKEN_URL)
        .form(&[
            ("client_id", st.cfg.google_client_id.as_str()),
            ("client_secret", st.cfg.google_client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|e| format!("Could not reach Google: {e}"))?;

    let status = res.status();
    if status.is_success() {
        let body: RefreshResponse = res
            .json()
            .await
            .map_err(|e| format!("Unexpected reply from Google: {e}"))?;
        st.google.put(sub, &body.access_token, body.expires_in);
        return Ok(body.access_token);
    }
    let body: Value = res.json().await.unwrap_or(Value::Null);
    if body["error"].as_str() == Some("invalid_grant") {
        tracing::info!(event = "google_access_revoked");
        st.google.forget(sub);
        if let Err(e) = st.store.revoke_account(sub) {
            tracing::error!("revoke_account: {e}");
        }
        return Err(RECONNECT.into());
    }
    Err(format!("Google refused to refresh access (HTTP {status})"))
}

async fn access_token(st: &AppState, sub: &str) -> Result<String, String> {
    match st.google.cached(sub) {
        Some(t) => Ok(t),
        None => refresh(st, sub).await,
    }
}

/// Turns a Google API error body into one plain sentence for the assistant.
pub fn describe_error(status: StatusCode, body: &Value) -> String {
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["error_description"].as_str())
        .unwrap_or("no details given");
    match status.as_u16() {
        403 => format!("Google denied access (HTTP 403): {msg}. Check that this Google account can see the property in Search Console."),
        404 => format!("Google could not find that (HTTP 404): {msg}. Use list_sites to see the exact property names."),
        429 => format!("Google's rate limit was reached (HTTP 429): {msg}. Wait a minute and try again."),
        _ => format!("Google returned HTTP {}: {msg}", status.as_u16()),
    }
}

/// One authorised call. Retries once with a fresh token if Google says the
/// cached access token is no longer accepted.
pub async fn call(
    st: &AppState,
    sub: &str,
    method: Method,
    url: &str,
    body: Option<&Value>,
) -> Result<Value, String> {
    let mut token = access_token(st, sub).await?;
    for attempt in 0..2 {
        let mut req = st.http.request(method.clone(), url).bearer_auth(&token);
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req
            .send()
            .await
            .map_err(|e| format!("Could not reach Google: {e}"))?;
        let status = res.status();
        if status == StatusCode::UNAUTHORIZED && attempt == 0 {
            st.google.forget(sub);
            token = refresh(st, sub).await?;
            continue;
        }
        let text = res
            .text()
            .await
            .map_err(|e| format!("Could not read Google's reply: {e}"))?;
        let value: Value = if text.trim().is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        if status.is_success() {
            return Ok(value);
        }
        return Err(describe_error(status, &value));
    }
    Err(RECONNECT.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_respects_margin() {
        let g = Google::default();
        g.put("a", "tok", 3600);
        assert_eq!(g.cached("a").as_deref(), Some("tok"));
        g.put("b", "tok", 60); // within the refresh margin, treated as stale
        assert_eq!(g.cached("b"), None);
        g.forget("a");
        assert_eq!(g.cached("a"), None);
    }

    #[test]
    fn error_text() {
        let body = json!({"error":{"code":403,"message":"User does not have sufficient permission for site"}});
        let s = describe_error(StatusCode::FORBIDDEN, &body);
        assert!(s.contains("sufficient permission"));
        assert!(s.contains("403"));
    }
}
