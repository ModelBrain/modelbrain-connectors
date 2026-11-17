//! The Search Console tools. All read-only.

use crate::{google, AppState};
use chrono::{Duration, NaiveDate, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::Method;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

const API: &str = "https://searchconsole.googleapis.com";
const DIMENSIONS: [&str; 6] = ["query", "page", "country", "device", "date", "searchAppearance"];
const SEARCH_TYPES: [&str; 6] = ["web", "image", "video", "news", "discover", "googleNews"];
const OPERATORS: [&str; 6] = ["equals", "notEquals", "contains", "notContains", "includingRegex", "excludingRegex"];
const MAX_ROWS: u64 = 25_000;

pub enum ToolFail {
    UnknownTool,
    Message(String),
}

impl From<String> for ToolFail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

fn annotations(title: &str) -> Value {
    json!({
        "title": title,
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": true,
    })
}

fn site_prop() -> Value {
    json!({
        "type": "string",
        "description": "The Search Console property, for example sc-domain:example.com or https://example.com/. A plain domain or page URL also works: it is matched to the right property."
    })
}

fn date_prop(what: &str) -> Value {
    json!({ "type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$", "description": what })
}

pub fn tools() -> Value {
    json!([
        {
            "name": "list_sites",
            "title": "List Search Console properties",
            "description": "List every Search Console property this Google account can see, with its permission level. Call this first to get exact property names.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": annotations("List Search Console properties"),
        },
        {
            "name": "search_performance",
            "title": "Search performance report",
            "description": "Clicks, impressions, CTR and average position from Google Search, grouped by any of query, page, country, device, date or searchAppearance, with optional filters. Covers up to 16 months. Defaults to the last 28 days of final data (ending 3 days ago) and 100 rows.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "site_url": site_prop(),
                    "start_date": date_prop("First day, YYYY-MM-DD. Default: 28 days before end_date."),
                    "end_date": date_prop("Last day, YYYY-MM-DD. Default: 3 days ago."),
                    "dimensions": {
                        "type": "array",
                        "items": { "type": "string", "enum": DIMENSIONS },
                        "description": "How to group rows. Empty gives one row of totals."
                    },
                    "filters": {
                        "type": "array",
                        "description": "All filters must match.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "dimension": { "type": "string", "enum": ["query", "page", "country", "device", "searchAppearance"] },
                                "operator": { "type": "string", "enum": OPERATORS },
                                "expression": { "type": "string" }
                            },
                            "required": ["dimension", "expression"]
                        }
                    },
                    "search_type": { "type": "string", "enum": SEARCH_TYPES, "description": "Default: web" },
                    "row_limit": { "type": "integer", "minimum": 1, "maximum": MAX_ROWS, "description": "Default: 100" },
                    "start_row": { "type": "integer", "minimum": 0, "description": "For paging. Default: 0" }
                },
                "required": ["site_url"],
                "additionalProperties": false
            },
            "annotations": annotations("Search performance report"),
        },
        {
            "name": "inspect_url",
            "title": "Inspect a URL",
            "description": "Google's index status for one URL in a property: whether it is indexed, coverage state, last crawl time, Google's chosen canonical, robots.txt state and rich result checks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "site_url": site_prop(),
                    "url": { "type": "string", "description": "The full URL to inspect. It must belong to site_url." },
                    "language_code": { "type": "string", "description": "Language for messages, for example en-US. Default: en-US" }
                },
                "required": ["site_url", "url"],
                "additionalProperties": false
            },
            "annotations": annotations("Inspect a URL"),
        },
        {
            "name": "list_sitemaps",
            "title": "List sitemaps",
            "description": "Sitemaps submitted for a property, with when Google last read them, errors, warnings and how many URLs each holds.",
            "inputSchema": {
                "type": "object",
                "properties": { "site_url": site_prop() },
                "required": ["site_url"],
                "additionalProperties": false
            },
            "annotations": annotations("List sitemaps"),
        },
        {
            "name": "compare_periods",
            "title": "Compare two periods",
            "description": "Totals for two date ranges side by side, plus the queries or pages that gained and lost the most clicks. Defaults to the last 28 days of final data against the 28 days before.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "site_url": site_prop(),
                    "current_start": date_prop("First day of the current period. Default: 28 days before current_end."),
                    "current_end": date_prop("Last day of the current period. Default: 3 days ago."),
                    "previous_start": date_prop("First day of the earlier period. Default: same length, just before the current period."),
                    "previous_end": date_prop("Last day of the earlier period. Default: the day before current_start."),
                    "dimension": { "type": "string", "enum": ["query", "page", "country", "device"], "description": "What to rank risers and fallers by. Default: query" },
                    "search_type": { "type": "string", "enum": SEARCH_TYPES, "description": "Default: web" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Risers and fallers to show. Default: 10" }
                },
                "required": ["site_url"],
                "additionalProperties": false
            },
            "annotations": annotations("Compare two periods"),
        }
    ])
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    str_arg(args, key).ok_or_else(|| format!("{key} is required"))
}

fn parse_date(s: &str, field: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| format!("{field} must be a date like 2026-11-01"))
}

/// Default range: 28 days ending 3 days before today (Search Console data is
/// final after about 2 to 3 days).
pub fn resolve_range(
    start: Option<&str>,
    end: Option<&str>,
    today: NaiveDate,
) -> Result<(NaiveDate, NaiveDate), String> {
    let end = match end {
        Some(s) => parse_date(s, "end date")?,
        None => today - Duration::days(3),
    };
    let start = match start {
        Some(s) => parse_date(s, "start date")?,
        None => end - Duration::days(27),
    };
    if start > end {
        return Err("The start date is after the end date".into());
    }
    Ok((start, end))
}

/// The period of equal length that ends the day before `start`.
pub fn previous_range(start: NaiveDate, end: NaiveDate) -> (NaiveDate, NaiveDate) {
    let days = (end - start).num_days();
    let prev_end = start - Duration::days(1);
    (prev_end - Duration::days(days), prev_end)
}

fn site_path(site: &str) -> String {
    utf8_percent_encode(site, NON_ALPHANUMERIC).to_string()
}

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

fn validated_search_type(args: &Value) -> Result<&str, String> {
    let t = str_arg(args, "search_type").unwrap_or("web");
    if SEARCH_TYPES.contains(&t) {
        Ok(t)
    } else {
        Err(format!("search_type must be one of {}", SEARCH_TYPES.join(", ")))
    }
}

fn build_filters(args: &Value) -> Result<Option<Value>, String> {
    let Some(list) = args.get("filters").and_then(Value::as_array) else {
        return Ok(None);
    };
    if list.is_empty() {
        return Ok(None);
    }
    let mut filters = Vec::with_capacity(list.len());
    for f in list {
        let dimension = required_str(f, "dimension")?;
        if !DIMENSIONS.contains(&dimension) || dimension == "date" {
            return Err(format!("Cannot filter by {dimension}"));
        }
        let operator = str_arg(f, "operator").unwrap_or("equals");
        if !OPERATORS.contains(&operator) {
            return Err(format!("operator must be one of {}", OPERATORS.join(", ")));
        }
        let expression = f
            .get("expression")
            .and_then(Value::as_str)
            .ok_or("Each filter needs an expression")?;
        filters.push(json!({ "dimension": dimension, "operator": operator, "expression": expression }));
    }
    Ok(Some(json!([{ "groupType": "and", "filters": filters }])))
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub keys: Vec<String>,
    pub clicks: f64,
    pub impressions: f64,
    pub ctr: f64,
    pub position: f64,
}

pub fn parse_rows(v: &Value) -> Vec<Row> {
    v.get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|r| Row {
                    keys: r["keys"]
                        .as_array()
                        .map(|k| k.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                        .unwrap_or_default(),
                    clicks: r["clicks"].as_f64().unwrap_or(0.0),
                    impressions: r["impressions"].as_f64().unwrap_or(0.0),
                    ctr: r["ctr"].as_f64().unwrap_or(0.0),
                    position: r["position"].as_f64().unwrap_or(0.0),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Most clicks first, then most impressions, then by key for a stable order.
pub fn rank_rows(rows: &mut [Row]) {
    rows.sort_by(|a, b| {
        b.clicks
            .total_cmp(&a.clicks)
            .then_with(|| b.impressions.total_cmp(&a.impressions))
            .then_with(|| a.keys.cmp(&b.keys))
    });
}

fn clean_cell(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// Tab-separated table: compact for the assistant to read, easy to paste.
pub fn format_rows(dimensions: &[String], rows: &[Row]) -> String {
    let mut out = String::new();
    for d in dimensions {
        out.push_str(d);
        out.push('\t');
    }
    out.push_str("clicks\timpressions\tctr_percent\tposition\n");
    for r in rows {
        for k in &r.keys {
            out.push_str(&clean_cell(k));
            out.push('\t');
        }
        out.push_str(&format!(
            "{}\t{}\t{:.2}\t{:.1}\n",
            r.clicks, r.impressions, r.ctr * 100.0, r.position
        ));
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    pub key: String,
    pub clicks_now: f64,
    pub clicks_before: f64,
    pub impressions_now: f64,
    pub impressions_before: f64,
    pub position_now: Option<f64>,
    pub position_before: Option<f64>,
}

impl Delta {
    pub fn change(&self) -> f64 {
        self.clicks_now - self.clicks_before
    }

    pub fn impressions_change(&self) -> f64 {
        self.impressions_now - self.impressions_before
    }
}

/// Joins two periods by key. Returns (risers, fallers), each sorted by the
/// size of the click change and cut to `limit`.
pub fn diff_rows(current: &[Row], previous: &[Row], limit: usize, by_impressions: bool) -> (Vec<Delta>, Vec<Delta>) {
    let mut map: HashMap<String, Delta> = HashMap::new();
    let blank = |key: &str| Delta {
        key: key.to_string(),
        clicks_now: 0.0,
        clicks_before: 0.0,
        impressions_now: 0.0,
        impressions_before: 0.0,
        position_now: None,
        position_before: None,
    };
    for r in current {
        let key = r.keys.join(" | ");
        let d = map.entry(key.clone()).or_insert_with(|| blank(&key));
        d.clicks_now = r.clicks;
        d.impressions_now = r.impressions;
        d.position_now = Some(r.position);
    }
    for r in previous {
        let key = r.keys.join(" | ");
        let d = map.entry(key.clone()).or_insert_with(|| blank(&key));
        d.clicks_before = r.clicks;
        d.impressions_before = r.impressions;
        d.position_before = Some(r.position);
    }
    let m = |d: &Delta| if by_impressions { d.impressions_change() } else { d.change() };
    let mut risers: Vec<Delta> = map.values().filter(|d| m(d) > 0.0).cloned().collect();
    let mut fallers: Vec<Delta> = map.values().filter(|d| m(d) < 0.0).cloned().collect();
    risers.sort_by(|a, b| m(b).total_cmp(&m(a)).then_with(|| a.key.cmp(&b.key)));
    fallers.sort_by(|a, b| m(a).total_cmp(&m(b)).then_with(|| a.key.cmp(&b.key)));
    risers.truncate(limit);
    fallers.truncate(limit);
    (risers, fallers)
}

fn fmt_pos(p: Option<f64>) -> String {
    p.map(|v| format!("{v:.1}")).unwrap_or_else(|| "-".into())
}

fn format_deltas(title: &str, dim: &str, list: &[Delta]) -> String {
    let mut out = format!("\n{title}\n{dim}\tclicks_now\tclicks_before\tclick_change\timpressions_now\timpressions_before\timpression_change\tposition_now\tposition_before\n");
    if list.is_empty() {
        out.push_str("(none)\n");
    }
    for d in list {
        out.push_str(&format!(
            "{}\t{}\t{}\t{:+}\t{}\t{}\t{:+}\t{}\t{}\n",
            clean_cell(&d.key),
            d.clicks_now,
            d.clicks_before,
            d.change(),
            d.impressions_now,
            d.impressions_before,
            d.impressions_change(),
            fmt_pos(d.position_now),
            fmt_pos(d.position_before)
        ));
    }
    out
}

fn pct_change(now: f64, before: f64) -> String {
    if before == 0.0 {
        if now == 0.0 { "0%".into() } else { "new".into() }
    } else {
        format!("{:+.1}%", (now - before) / before * 100.0)
    }
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

pub async fn call(st: &AppState, sub: &str, name: &str, args: &Value) -> Result<String, ToolFail> {
    match name {
        "list_sites" => list_sites(st, sub).await.map_err(Into::into),
        "search_performance" => search_performance(st, sub, args).await.map_err(Into::into),
        "inspect_url" => inspect_url(st, sub, args).await.map_err(Into::into),
        "list_sitemaps" => list_sitemaps(st, sub, args).await.map_err(Into::into),
        "compare_periods" => compare_periods(st, sub, args).await.map_err(Into::into),
        _ => Err(ToolFail::UnknownTool),
    }
}

/// The host a property or URL refers to, without "www.".
fn host_of(site: &str) -> Option<String> {
    let s = site.trim();
    if let Some(d) = s.strip_prefix("sc-domain:") {
        return Some(d.trim().trim_end_matches('/').to_ascii_lowercase());
    }
    let with_scheme = if s.contains("://") { s.to_string() } else { format!("https://{s}") };
    let u = url::Url::parse(&with_scheme).ok()?;
    u.host_str()
        .map(|h| h.strip_prefix("www.").unwrap_or(h).to_ascii_lowercase())
}

/// Maps what the assistant typed (a URL, a bare domain, a missing slash) to
/// the exact property name Search Console uses. Order: exact match, then the
/// domain property for that host or any parent domain, then a URL-prefix
/// property on the same host.
pub fn pick_site(input: &str, owned: &[String]) -> Option<String> {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    if let Some(exact) = owned.iter().find(|o| norm(o) == norm(input)) {
        return Some(exact.clone());
    }
    let host = host_of(input)?;
    let mut candidate = host.as_str();
    loop {
        let dom = format!("sc-domain:{candidate}");
        if let Some(found) = owned.iter().find(|o| o.eq_ignore_ascii_case(&dom)) {
            return Some(found.clone());
        }
        match candidate.split_once('.') {
            Some((_, rest)) if rest.contains('.') => candidate = rest,
            _ => break,
        }
    }
    owned
        .iter()
        .find(|o| !o.starts_with("sc-domain:") && host_of(o).as_deref() == Some(host.as_str()))
        .cloned()
}

async fn fetch_sites(st: &AppState, sub: &str) -> Result<Vec<(String, String)>, String> {
    let v = google::call(st, sub, Method::GET, &format!("{API}/webmasters/v3/sites"), None).await?;
    let sites = v["siteEntry"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|s| {
                    (
                        s["siteUrl"].as_str().unwrap_or_default().to_string(),
                        s["permissionLevel"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(sites)
}

/// Returns the property to query plus a note when it differs from the input.
async fn resolve_site(st: &AppState, sub: &str, input: &str) -> Result<(String, String), String> {
    if input.starts_with("sc-domain:") {
        return Ok((input.to_string(), String::new()));
    }
    let owned: Vec<String> = fetch_sites(st, sub).await?.into_iter().map(|(u, _)| u).collect();
    match pick_site(input, &owned) {
        Some(found) if found == input => Ok((found, String::new())),
        Some(found) => {
            let note = format!("(Using the property {found} for {input}.)\n");
            Ok((found, note))
        }
        None => Err(format!(
            "No Search Console property in this account matches {input}. Properties available: {}",
            if owned.is_empty() { "none".to_string() } else { owned.join(", ") }
        )),
    }
}

async fn list_sites(st: &AppState, sub: &str) -> Result<String, String> {
    let mut sites = fetch_sites(st, sub).await?;
    if sites.is_empty() {
        return Ok("This Google account has no Search Console properties. Add or verify a site at https://search.google.com/search-console first.".into());
    }
    sites.sort();
    let mut out = format!("{} properties\nsite_url\tpermission\n", sites.len());
    for (u, p) in sites {
        out.push_str(&format!("{u}\t{p}\n"));
    }
    Ok(out)
}

async fn query(st: &AppState, sub: &str, site: &str, body: &Value) -> Result<Value, String> {
    let url = format!("{API}/webmasters/v3/sites/{}/searchAnalytics/query", site_path(site));
    google::call(st, sub, Method::POST, &url, Some(body)).await
}

async fn search_performance(st: &AppState, sub: &str, args: &Value) -> Result<String, String> {
    let (site, note) = resolve_site(st, sub, required_str(args, "site_url")?).await?;
    let site = site.as_str();
    let (start, end) = resolve_range(str_arg(args, "start_date"), str_arg(args, "end_date"), today())?;
    let dimensions: Vec<String> = args
        .get("dimensions")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|d| d.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if let Some(bad) = dimensions.iter().find(|d| !DIMENSIONS.contains(&d.as_str())) {
        return Err(format!("Unknown dimension {bad}. Use {}", DIMENSIONS.join(", ")));
    }
    let search_type = validated_search_type(args)?;
    let row_limit = args.get("row_limit").and_then(Value::as_u64).unwrap_or(100).clamp(1, MAX_ROWS);
    let start_row = args.get("start_row").and_then(Value::as_u64).unwrap_or(0);

    let mut body = Map::new();
    body.insert("startDate".into(), json!(start.to_string()));
    body.insert("endDate".into(), json!(end.to_string()));
    body.insert("type".into(), json!(search_type));
    // Google sorts by clicks and breaks ties alphabetically, so on a site
    // where most rows have 0 clicks a small row_limit returns the
    // alphabetically first rows, not the most seen. On the first page,
    // fetch a wider set and rank it here by clicks, then impressions.
    let rank_locally = start_row == 0 && !dimensions.is_empty() && !dimensions.iter().any(|d| d == "date");
    let fetch_limit = if rank_locally { row_limit.clamp(5000, MAX_ROWS) } else { row_limit };
    body.insert("rowLimit".into(), json!(fetch_limit));
    body.insert("startRow".into(), json!(start_row));
    if !dimensions.is_empty() {
        body.insert("dimensions".into(), json!(dimensions));
    }
    if let Some(f) = build_filters(args)? {
        body.insert("dimensionFilterGroups".into(), f);
    }

    let v = query(st, sub, site, &Value::Object(body)).await?;
    let mut rows = parse_rows(&v);
    let fetched = rows.len() as u64;
    if rank_locally {
        rank_rows(&mut rows);
        rows.truncate(row_limit as usize);
    }
    let mut out = format!(
        "{note}{site}, {start} to {end}, {search_type} search, {} rows from row {start_row}\n",
        rows.len()
    );
    if rows.is_empty() {
        out.push_str("No data for this range and filter.\n");
        return Ok(out);
    }
    out.push_str(&format_rows(&dimensions, &rows));
    if rank_locally && fetched > row_limit {
        let more = if fetched == fetch_limit { "+" } else { "" };
        out.push_str(&format!(
            "Top {row_limit} of {fetched}{more} rows, ranked by clicks then impressions. Ask with a larger row_limit to see more.\n"
        ));
    } else if !rank_locally && rows.len() as u64 == row_limit {
        out.push_str(&format!(
            "More rows may exist: call again with start_row {}.\n",
            start_row + row_limit
        ));
    }
    Ok(out)
}

async fn inspect_url(st: &AppState, sub: &str, args: &Value) -> Result<String, String> {
    let (site, note) = resolve_site(st, sub, required_str(args, "site_url")?).await?;
    let site = site.as_str();
    let url = required_str(args, "url")?;
    let lang = str_arg(args, "language_code").unwrap_or("en-US");
    let body = json!({ "inspectionUrl": url, "siteUrl": site, "languageCode": lang });
    let v = google::call(st, sub, Method::POST, &format!("{API}/v1/urlInspection/index:inspect"), Some(&body)).await?;
    let mut result = v.get("inspectionResult").cloned().unwrap_or(v);
    if result["mobileUsabilityResult"]["verdict"].as_str() == Some("VERDICT_UNSPECIFIED") {
        if let Some(obj) = result.as_object_mut() {
            // Google retired the mobile usability report; the field is empty.
            obj.remove("mobileUsabilityResult");
        }
    }
    let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    Ok(format!("{note}{text}"))
}

async fn list_sitemaps(st: &AppState, sub: &str, args: &Value) -> Result<String, String> {
    let (site, note) = resolve_site(st, sub, required_str(args, "site_url")?).await?;
    let site = site.as_str();
    let url = format!("{API}/webmasters/v3/sites/{}/sitemaps", site_path(site));
    let v = google::call(st, sub, Method::GET, &url, None).await?;
    let mut v = v;
    if let Some(list) = v.get_mut("sitemap").and_then(Value::as_array_mut) {
        for sm in list.iter_mut() {
            if let Some(contents) = sm.get_mut("contents").and_then(Value::as_array_mut) {
                for c in contents.iter_mut() {
                    if let Some(obj) = c.as_object_mut() {
                        // Google stopped reporting this; it is always "0".
                        obj.remove("indexed");
                    }
                }
            }
        }
    }
    match v.get("sitemap").and_then(Value::as_array) {
        Some(list) if !list.is_empty() => serde_json::to_string_pretty(list)
            .map(|t| format!("{note}{t}"))
            .map_err(|e| e.to_string()),
        _ => Ok(format!("{note}No sitemaps are submitted for {site}.")),
    }
}

async fn totals_and_rows(
    st: &AppState,
    sub: &str,
    site: &str,
    range: (NaiveDate, NaiveDate),
    search_type: &str,
    dimension: &str,
) -> Result<(Option<Row>, Vec<Row>), String> {
    let base = |dims: Option<&str>, limit: u64| {
        let mut b = json!({
            "startDate": range.0.to_string(),
            "endDate": range.1.to_string(),
            "type": search_type,
            "rowLimit": limit,
        });
        if let Some(d) = dims {
            b["dimensions"] = json!([d]);
        }
        b
    };
    let (totals_body, rows_body) = (base(None, 1), base(Some(dimension), 5000));
    let (totals, rows) = tokio::try_join!(
        query(st, sub, site, &totals_body),
        query(st, sub, site, &rows_body)
    )?;
    Ok((parse_rows(&totals).into_iter().next(), parse_rows(&rows)))
}

async fn compare_periods(st: &AppState, sub: &str, args: &Value) -> Result<String, String> {
    let (site, note) = resolve_site(st, sub, required_str(args, "site_url")?).await?;
    let site = site.as_str();
    let current = resolve_range(str_arg(args, "current_start"), str_arg(args, "current_end"), today())?;
    let previous = match (str_arg(args, "previous_start"), str_arg(args, "previous_end")) {
        (None, None) => previous_range(current.0, current.1),
        (s, e) => {
            let default = previous_range(current.0, current.1);
            let start = s.map(|v| parse_date(v, "previous_start")).transpose()?.unwrap_or(default.0);
            let end = e.map(|v| parse_date(v, "previous_end")).transpose()?.unwrap_or(default.1);
            if start > end {
                return Err("previous_start is after previous_end".into());
            }
            (start, end)
        }
    };
    let dimension = str_arg(args, "dimension").unwrap_or("query");
    if !["query", "page", "country", "device"].contains(&dimension) {
        return Err("dimension must be query, page, country or device".into());
    }
    let search_type = validated_search_type(args)?;
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(10).clamp(1, 50) as usize;

    let ((cur_tot, cur_rows), (prev_tot, prev_rows)) = tokio::try_join!(
        totals_and_rows(st, sub, site, current, search_type, dimension),
        totals_and_rows(st, sub, site, previous, search_type, dimension)
    )?;

    let t = |r: &Option<Row>| r.clone().unwrap_or(Row { keys: vec![], clicks: 0.0, impressions: 0.0, ctr: 0.0, position: 0.0 });
    let (c, p) = (t(&cur_tot), t(&prev_tot));

    let mut out = format!(
        "{note}{site}, {search_type} search\ncurrent: {} to {}\nprevious: {} to {}\n\nmetric\tcurrent\tprevious\tchange\n",
        current.0, current.1, previous.0, previous.1
    );
    out.push_str(&format!("clicks\t{}\t{}\t{}\n", c.clicks, p.clicks, pct_change(c.clicks, p.clicks)));
    out.push_str(&format!(
        "impressions\t{}\t{}\t{}\n",
        c.impressions,
        p.impressions,
        pct_change(c.impressions, p.impressions)
    ));
    out.push_str(&format!("ctr_percent\t{:.2}\t{:.2}\t{:+.2} points\n", c.ctr * 100.0, p.ctr * 100.0, (c.ctr - p.ctr) * 100.0));
    out.push_str(&format!("position\t{:.1}\t{:.1}\t{:+.1}\n", c.position, p.position, c.position - p.position));

    let (mut risers, mut fallers) = diff_rows(&cur_rows, &prev_rows, limit, false);
    let mut metric = "clicks";
    if risers.is_empty() && fallers.is_empty() {
        (risers, fallers) = diff_rows(&cur_rows, &prev_rows, limit, true);
        metric = "impressions";
        out.push_str(&format!("\nNo {dimension} changed in clicks between the periods, so these are ranked by impressions.\n"));
    }
    out.push_str(&format_deltas(&format!("Biggest gains in {metric}"), dimension, &risers));
    out.push_str(&format_deltas(&format!("Biggest losses in {metric}"), dimension, &fallers));
    if cur_rows.len() >= 5000 || prev_rows.len() >= 5000 {
        out.push_str("\nRisers and fallers are drawn from the top 5,000 rows of each period.\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn default_range_is_28_days_ending_3_days_ago() {
        let (s, e) = resolve_range(None, None, d("2026-11-17")).unwrap();
        assert_eq!(e, d("2026-11-14"));
        assert_eq!(s, d("2026-10-18"));
        assert_eq!((e - s).num_days() + 1, 28);
    }

    #[test]
    fn explicit_and_bad_ranges() {
        let (s, e) = resolve_range(Some("2026-01-01"), Some("2026-01-31"), d("2026-11-17")).unwrap();
        assert_eq!((s, e), (d("2026-01-01"), d("2026-01-31")));
        assert!(resolve_range(Some("2026-02-01"), Some("2026-01-01"), d("2026-11-17")).is_err());
        assert!(resolve_range(Some("01/02/2026"), None, d("2026-11-17")).is_err());
    }

    #[test]
    fn previous_range_has_equal_length() {
        let (ps, pe) = previous_range(d("2026-10-18"), d("2026-11-14"));
        assert_eq!(pe, d("2026-10-17"));
        assert_eq!(ps, d("2026-09-20"));
        assert_eq!((pe - ps).num_days(), (d("2026-11-14") - d("2026-10-18")).num_days());
    }

    #[test]
    fn site_paths_are_encoded() {
        assert_eq!(site_path("sc-domain:example.com"), "sc%2Ddomain%3Aexample%2Ecom");
        assert_eq!(site_path("https://a.com/"), "https%3A%2F%2Fa%2Ecom%2F");
    }

    #[test]
    fn rows_parse_and_format() {
        let v = json!({"rows":[{"keys":["ai memory","https://x/"],"clicks":12.0,"impressions":300.0,"ctr":0.04,"position":7.34}]});
        let rows = parse_rows(&v);
        assert_eq!(rows.len(), 1);
        let text = format_rows(&["query".into(), "page".into()], &rows);
        assert_eq!(text, "query\tpage\tclicks\timpressions\tctr_percent\tposition\nai memory\thttps://x/\t12\t300\t4.00\t7.3\n");
        assert!(parse_rows(&json!({})).is_empty());
    }

    #[test]
    fn diff_finds_risers_and_fallers() {
        let row = |k: &str, c: f64| Row { keys: vec![k.into()], clicks: c, impressions: c * 10.0, ctr: 0.1, position: 5.0 };
        let cur = vec![row("a", 50.0), row("b", 5.0), row("new", 8.0)];
        let prev = vec![row("a", 20.0), row("b", 30.0), row("gone", 4.0)];
        let (up, down) = diff_rows(&cur, &prev, 10, false);
        assert_eq!(up.iter().map(|d| d.key.as_str()).collect::<Vec<_>>(), vec!["a", "new"]);
        assert_eq!(down.iter().map(|d| d.key.as_str()).collect::<Vec<_>>(), vec!["b", "gone"]);
        assert_eq!(up[1].position_before, None);
        let (up1, _) = diff_rows(&cur, &prev, 1, false);
        assert_eq!(up1.len(), 1);

        let flat = |k: &str, i: f64| Row { keys: vec![k.into()], clicks: 0.0, impressions: i, ctr: 0.0, position: 9.0 };
        let (c_up, c_down) = diff_rows(&[flat("x", 50.0)], &[flat("x", 5.0)], 10, false);
        assert!(c_up.is_empty() && c_down.is_empty());
        let (i_up, _) = diff_rows(&[flat("x", 50.0)], &[flat("x", 5.0)], 10, true);
        assert_eq!(i_up[0].impressions_change(), 45.0);
    }

    #[test]
    fn filters_validate() {
        let ok = json!({"filters":[{"dimension":"page","operator":"contains","expression":"/blog/"}]});
        assert!(build_filters(&ok).unwrap().is_some());
        let bad_dim = json!({"filters":[{"dimension":"date","expression":"x"}]});
        assert!(build_filters(&bad_dim).is_err());
        let bad_op = json!({"filters":[{"dimension":"query","operator":"like","expression":"x"}]});
        assert!(build_filters(&bad_op).is_err());
        assert!(build_filters(&json!({})).unwrap().is_none());
    }

    #[test]
    fn every_tool_is_read_only_and_titled() {
        let list = tools();
        let list = list.as_array().unwrap();
        assert_eq!(list.len(), 5);
        for t in list {
            assert!(t["title"].is_string());
            assert_eq!(t["annotations"]["readOnlyHint"], json!(true));
            assert_eq!(t["inputSchema"]["type"], json!("object"));
        }
    }

    #[test]
    fn picks_the_right_property() {
        let owned: Vec<String> = ["sc-domain:nexspark.com", "https://shop.example.org/", "sc-domain:modelbrain.net"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(pick_site("https://nexspark.com", &owned).as_deref(), Some("sc-domain:nexspark.com"));
        assert_eq!(pick_site("nexspark.com", &owned).as_deref(), Some("sc-domain:nexspark.com"));
        assert_eq!(pick_site("https://www.nexspark.com/blog/post", &owned).as_deref(), Some("sc-domain:nexspark.com"));
        assert_eq!(pick_site("https://blog.modelbrain.net/", &owned).as_deref(), Some("sc-domain:modelbrain.net"));
        assert_eq!(pick_site("https://shop.example.org", &owned).as_deref(), Some("https://shop.example.org/"));
        assert_eq!(pick_site("sc-domain:NEXSPARK.com", &owned).as_deref(), Some("sc-domain:nexspark.com"));
        assert_eq!(pick_site("https://unknown.com/", &owned), None);
        assert_eq!(pick_site("example.org", &owned), None);
    }

    #[test]
    fn ranks_by_clicks_then_impressions() {
        let row = |k: &str, c: f64, i: f64| Row { keys: vec![k.into()], clicks: c, impressions: i, ctr: 0.0, position: 1.0 };
        let mut rows = vec![row("a junk", 0.0, 1.0), row("b big", 0.0, 80.0), row("c click", 2.0, 5.0), row("d mid", 0.0, 18.0)];
        rank_rows(&mut rows);
        let order: Vec<&str> = rows.iter().map(|r| r.keys[0].as_str()).collect();
        assert_eq!(order, vec!["c click", "b big", "d mid", "a junk"]);
    }

    #[test]
    fn pct() {
        assert_eq!(pct_change(110.0, 100.0), "+10.0%");
        assert_eq!(pct_change(5.0, 0.0), "new");
        assert_eq!(pct_change(0.0, 0.0), "0%");
    }
}
