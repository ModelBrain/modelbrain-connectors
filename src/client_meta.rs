//! OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document), the MCP
//! authorization spec's preferred way for an app to say who it is. The app uses an https URL as
//! its client_id; the JSON at that URL names the app and lists its redirect addresses. Hosting the
//! document proves the app controls that domain, so the consent page can name the domain, and no
//! registration step is needed.

use serde_json::Value;
use std::net::IpAddr;
use std::time::Duration;

/// How long a fetched document is used before it is fetched again.
pub const FRESH_SECS: i64 = 3600;
/// The largest document read.
pub const MAX_BYTES: usize = 64 * 1024;
const MAX_URL: usize = 512;

/// A client_id that is a metadata document URL: https, a DNS name, the default port, a path other
/// than "/", and no userinfo, query, fragment, escapes, backslashes or dot segments. It must be
/// written the way it parses, so the stored id and the one presented later compare exactly.
pub fn is_document_url(id: &str) -> bool {
    if id.len() > MAX_URL || !id.starts_with("https://") {
        return false;
    }
    if id.contains(['#', '?', '\\', '%', '@', ' ']) || id.chars().any(char::is_control) {
        return false;
    }
    let Ok(u) = url::Url::parse(id) else {
        return false;
    };
    let Some(url::Host::Domain(host)) = u.host() else {
        return false;
    };
    let path = u.path();
    host.contains('.')
        && u.port().is_none()
        && path.len() > 1
        && !path.contains("//")
        && !path.split('/').any(|seg| seg == "." || seg == "..")
        && u.as_str() == id
}

/// The domain that proved it owns a metadata document client, lowercased.
pub fn host_of(id: &str) -> Option<String> {
    if !is_document_url(id) {
        return None;
    }
    url::Url::parse(id).ok()?.host_str().map(str::to_ascii_lowercase)
}

/// The app's name and redirect addresses from a fetched document, or None when the document does
/// not name itself with exactly this URL, lists no (or more than 10) acceptable redirects, or asks
/// for client authentication other than none (this server only serves public clients).
pub fn parse_document(url: &str, body: &str, redirect_ok: impl Fn(&str) -> bool) -> Option<(String, Vec<String>)> {
    if body.len() > MAX_BYTES {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    if v["client_id"].as_str() != Some(url) {
        return None;
    }
    let mut uris: Vec<String> = Vec::new();
    for u in v["redirect_uris"].as_array()? {
        let s = u.as_str()?;
        if s.len() > MAX_URL || !redirect_ok(s) {
            return None;
        }
        if !uris.iter().any(|x| x == s) {
            uris.push(s.to_string());
        }
    }
    if uris.is_empty() || uris.len() > 10 {
        return None;
    }
    if let Some(m) = v.get("token_endpoint_auth_method") {
        if m.as_str() != Some("none") {
            return None;
        }
    }
    let name: String = v["client_name"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .take(100)
        .collect::<String>()
        .trim()
        .to_string();
    let name = if name.is_empty() { host_of(url)? } else { name };
    Some((name, uris))
}

/// Bidirectional and zero-width characters that could disguise a name on the consent page.
fn is_format_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Whether an address is on the public internet (not loopback, private, link-local, shared,
/// documentation, benchmarking, multicast or reserved, and no IPv6 form that wraps one of those).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // Global unicast only (2000::/3), minus forms that carry an IPv4 address a gateway may
            // route anywhere: 6to4 2002::/16, Teredo 2001::/32, and the documentation range.
            (s[0] & 0xe000) == 0x2000 && s[0] != 0x2002 && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8))
        }
    }
}

/// Fetches a metadata document from public addresses only: the name is resolved here, every
/// address must be public, and the request goes to one of those exact addresses, so a DNS answer
/// cannot change between the check and the connection. No redirects, 5 seconds, 64 KB.
pub async fn fetch(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let host = u.host_str()?.to_string();
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host.as_str(), 443)))
        .await
        .ok()?
        .ok()?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| !is_public(a.ip())) {
        tracing::info!(event = "client_metadata_refused", reason = "address", host = %host);
        return None;
    }
    let client = reqwest::Client::builder()
        .resolve(&host, addrs[0])
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .user_agent(concat!("modelbrain-connectors/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    let mut resp = client.get(url).header("accept", "application/json").send().await.ok()?;
    if !resp.status().is_success() || resp.content_length().is_some_and(|n| n as usize > MAX_BYTES) {
        return None;
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BYTES {
            return None;
        }
    }
    String::from_utf8(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_urls_are_plain_https() {
        for ok in ["https://app.example.com/oauth/client.json", "https://glama.ai/oauth/client-metadata"] {
            assert!(is_document_url(ok), "{ok}");
        }
        for bad in [
            "https://app.example.com/",
            "https://app.example.com",
            "http://app.example.com/c.json",
            "https://app.example.com:8443/c.json",
            "https://127.0.0.1/c.json",
            "https://app.example.com/c.json?x=1",
            "https://app.example.com/a/../c.json",
            "https://APP.example.com/c.json",
            "https://user@app.example.com/c.json",
            "mbc_abcdef",
        ] {
            assert!(!is_document_url(bad), "{bad}");
        }
    }

    #[test]
    fn a_document_must_name_itself() {
        let url = "https://app.example.com/oauth/client.json";
        let ok = |_: &str| true;
        let doc = |id: &str, name: &str, uris: &[&str], auth: &str| {
            serde_json::json!({"client_id": id, "client_name": name, "redirect_uris": uris, "token_endpoint_auth_method": auth}).to_string()
        };
        assert_eq!(
            parse_document(url, &doc(url, "Example", &["https://app.example.com/cb"], "none"), ok),
            Some(("Example".into(), vec!["https://app.example.com/cb".into()]))
        );
        assert_eq!(parse_document(url, &doc(url, "\u{202e}", &["https://app.example.com/cb"], "none"), ok).unwrap().0, "app.example.com");
        assert!(parse_document(url, &doc("https://other.example.com/c.json", "X", &["https://app.example.com/cb"], "none"), ok).is_none());
        assert!(parse_document(url, &doc(url, "X", &[], "none"), ok).is_none());
        assert!(parse_document(url, &doc(url, "X", &["https://app.example.com/cb"], "client_secret_basic"), ok).is_none());
        assert!(parse_document(url, &doc(url, "X", &["https://app.example.com/cb"], "none"), |_| false).is_none());
        assert!(parse_document(url, "not json", ok).is_none());
    }

    #[test]
    fn only_public_addresses_are_fetched_from() {
        for bad in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "2002:a00:1::1", "2001::1"] {
            assert!(!is_public(bad.parse().unwrap()), "{bad}");
        }
        for ok in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
    }
}
