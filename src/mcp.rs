//! MCP Streamable HTTP endpoint (stateless, JSON responses only).
//!
//! Every request needs one of our Bearer tokens. Logs carry the method, tool
//! name, outcome and duration only: never arguments or results.

use crate::{config::Connector, crypto::hash_token, gsc, oauth, store::{now, TokenKind}, Shared};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Mutex, time::Instant};

pub const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_VERSION: &str = "2025-06-18";

pub struct RateLimiter {
    per_minute: u32,
    slots: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute: per_minute.max(1), slots: Mutex::new(HashMap::new()) }
    }

    /// Fixed one-minute window per account. True if the call may go ahead.
    pub fn check_at(&self, key: &str, unix_secs: i64) -> bool {
        let minute = unix_secs / 60;
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots.entry(key.to_string()).or_insert((minute, 0));
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        if slot.1 >= self.per_minute {
            return false;
        }
        slot.1 += 1;
        true
    }

    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, now())
    }

    pub fn purge(&self) {
        let minute = now() / 60;
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots.retain(|_, (m, _)| *m == minute);
    }
}

pub fn initialize_result(connector: Connector, requested: Option<&str>) -> Value {
    json!({
        "protocolVersion": negotiate_version(requested),
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": connector.server_name(),
            "title": connector.display_name(),
            "version": env!("CARGO_PKG_VERSION"),
            "websiteUrl": "https://modelbrain.net/connectors.html",
        },
        "instructions": "Read-only Google Search Console data for every property the signed-in Google account can see. Call list_sites first to get exact property names, then search_performance, compare_periods, inspect_url or list_sitemaps.",
    })
}

pub const HOSTED_ONLY: &str = "This copy only lists its tools. To read your Search Console data, add the hosted connector https://gsc.modelbrain.net/mcp in Claude, ChatGPT or Cursor and sign in with Google. Setup: https://modelbrain.net/connectors.html";

/// One line of JSON-RPC from stdin, for directory checks (Glama) that start
/// the server in a container with no secrets and ask what it offers. Lists
/// tools; real calls point to the hosted connector. Returns None for
/// notifications, which need no reply.
pub fn stdio_reply(line: &str) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }))
        }
    };
    let id = msg.get("id").cloned()?;
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match msg["method"].as_str().unwrap_or_default() {
        "initialize" => initialize_result(Connector::SearchConsole, params["protocolVersion"].as_str()),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": gsc::tools() }),
        "tools/call" => json!({ "content": [{ "type": "text", "text": HOSTED_ONLY }], "isError": true }),
        "resources/list" => json!({ "resources": [] }),
        "prompts/list" => json!({ "prompts": [] }),
        _ => {
            return Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Method not found" } }))
        }
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

pub fn negotiate_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|r| SUPPORTED_VERSIONS.iter().copied().find(|v| *v == r))
        .unwrap_or(DEFAULT_VERSION)
}

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim()).filter(|t| !t.is_empty())
}

pub async fn not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")], "Use POST for MCP requests").into_response()
}

pub async fn handle(State(st): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(token) = bearer(&headers) else {
        return oauth::unauthorized(&st);
    };
    let sub = match st.store.token(&hash_token(token), TokenKind::Access) {
        Ok(Some((sub, _client))) => sub,
        Ok(None) => return oauth::unauthorized(&st),
        Err(e) => {
            tracing::error!("token lookup: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return rpc_error(&Value::Null, -32700, "Parse error"),
    };
    if msg.is_array() {
        return rpc_error(&Value::Null, -32600, "Batching is not supported");
    }
    let method = msg["method"].as_str().unwrap_or_default().to_string();
    let Some(id) = msg.get("id").cloned() else {
        // Notifications and responses from the client need no reply.
        return StatusCode::ACCEPTED.into_response();
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let started = Instant::now();

    match method.as_str() {
        "initialize" => rpc_result(
            &id,
            initialize_result(st.cfg.connector, params["protocolVersion"].as_str()),
        ),
        "ping" => rpc_result(&id, json!({})),
        "tools/list" => rpc_result(&id, json!({ "tools": gsc::tools() })),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or_default().to_string();
            if !st.limiter.check(&sub) {
                tracing::info!(method = "tools/call", tool = %name, outcome = "rate_limited");
                return rpc_result(
                    &id,
                    json!({
                        "content": [{ "type": "text", "text": format!("Rate limit: at most {} calls a minute per account. Wait a moment and try again.", st.cfg.calls_per_minute) }],
                        "isError": true,
                    }),
                );
            }
            let args = match params.get("arguments") {
                Some(a) if a.is_object() => a.clone(),
                _ => json!({}),
            };
            let outcome = gsc::call(&st, &sub, &name, &args).await;
            let ms = started.elapsed().as_millis() as u64;
            match outcome {
                Ok(text) => {
                    tracing::info!(method = "tools/call", tool = %name, outcome = "ok", ms);
                    rpc_result(&id, json!({ "content": [{ "type": "text", "text": text }], "isError": false }))
                }
                Err(gsc::ToolFail::Message(text)) => {
                    tracing::info!(method = "tools/call", tool = %name, outcome = "tool_error", ms);
                    rpc_result(&id, json!({ "content": [{ "type": "text", "text": text }], "isError": true }))
                }
                Err(gsc::ToolFail::UnknownTool) => rpc_error(&id, -32602, &format!("Unknown tool: {name}")),
            }
        }
        "resources/list" => rpc_result(&id, json!({ "resources": [] })),
        "prompts/list" => rpc_result(&id, json!({ "prompts": [] })),
        _ => rpc_error(&id, -32601, "Method not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn rate_limit_window() {
        let rl = RateLimiter::new(3);
        let t = 1_800_000_020;
        assert!(rl.check_at("a", t));
        assert!(rl.check_at("a", t + 1));
        assert!(rl.check_at("a", t + 2));
        assert!(!rl.check_at("a", t + 3));
        assert!(rl.check_at("b", t + 3));
        assert!(rl.check_at("a", t + 60));
    }

    #[test]
    fn stdio_lists_tools_without_secrets() {
        let init = stdio_reply(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#).unwrap();
        assert_eq!(init["result"]["protocolVersion"], json!("2025-06-18"));
        assert_eq!(init["result"]["serverInfo"]["name"], json!("modelbrain-search-console"));
        assert!(stdio_reply(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        let list = stdio_reply(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 5);
        let call = stdio_reply(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_sites"}}"#).unwrap();
        assert_eq!(call["result"]["isError"], json!(true));
        assert_eq!(stdio_reply("not json").unwrap()["error"]["code"], json!(-32700));
        assert_eq!(stdio_reply(r#"{"jsonrpc":"2.0","id":4,"method":"x"}"#).unwrap()["error"]["code"], json!(-32601));
    }

    #[test]
    fn version_negotiation() {
        assert_eq!(negotiate_version(Some("2025-03-26")), "2025-03-26");
        assert_eq!(negotiate_version(Some("1999-01-01")), DEFAULT_VERSION);
        assert_eq!(negotiate_version(None), DEFAULT_VERSION);
    }

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer(&h), Some("abc"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("bearer   xyz"));
        assert_eq!(bearer(&h), Some("xyz"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&h), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
    }
}
