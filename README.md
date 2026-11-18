# ModelBrain free connectors

Hosted, read-only MCP connectors from [ModelBrain](https://modelbrain.net/). Free for every account and every property.

First connector: **ModelBrain Search Console** at `https://gsc.modelbrain.net/mcp`.

## Tools (Search Console)

| Tool | What it returns |
|---|---|
| `list_sites` | Every property the Google account can see, with permission level |
| `search_performance` | Clicks, impressions, CTR, position by query, page, country, device, date or search appearance, with filters and paging (up to 25,000 rows a call, 16 months) |
| `inspect_url` | Index status, coverage, last crawl, canonical, robots and rich results for one URL |
| `list_sitemaps` | Submitted sitemaps with last read, errors, warnings and URL counts |
| `compare_periods` | Two date ranges side by side, plus the biggest risers and fallers |

Every tool is marked `readOnlyHint: true`. The only Google scope requested is `webmasters.readonly`.

## How sign-in works

1. The AI app identifies itself, either with a client metadata document (an https URL as its `client_id`, which we fetch from public addresses only and check) or by registering (`/register`, RFC 7591). It sends the person to `/authorize` with a PKCE S256 challenge.
2. Claude, ChatGPT, Cursor and apps that call back to the person's own computer go straight on. Any other app first gets a consent page naming its verified domain, or the address it sends access to, because Google's own screen names this connector, not the app.
3. We send them to Google, asking for `openid` and the one read-only scope, with offline access.
4. Google returns to `/oauth/google/callback`. We read the account ID from the ID token, seal the Google refresh token with ChaCha20-Poly1305 and store it.
5. The app swaps a one-time code at `/token` for our own access token (1 hour) and refresh token (90 days, rotated on use).

## What is stored

- Google account ID and the sealed Google refresh token.
- SHA-256 hashes of our own codes and tokens.
- App names and redirect addresses, from registration or from their metadata documents.

Search data passes straight through and is never stored. Logs hold method, tool name, outcome and duration only. No email addresses are kept.

## Configuration

| Variable | Meaning |
|---|---|
| `CONNECTOR` | `gsc` (default) |
| `BASE_URL` | Public address, for example `https://gsc.modelbrain.net` |
| `BIND` | Listen address, default `0.0.0.0:8787` |
| `DB_PATH` | SQLite file, default `connectors.db` |
| `GOOGLE_OAUTH_JSON_FILE` | Path to the client JSON downloaded from Google Cloud (or set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, each also as `*_FILE`) |
| `TOKEN_KEY` / `TOKEN_KEY_FILE` | 32 random bytes, base64 (`openssl rand -base64 32`). Losing it signs everyone out. |
| `EXTRA_REDIRECT_HOSTS` | Comma-separated extra https hosts treated as known apps (no consent page). Any well-formed callback may connect either way. |
| `CALLS_PER_MINUTE` | Per-account tool call limit, default 60 |
| `RUST_LOG` | Log filter, default `info` |

## Local run

```sh
export BASE_URL=http://localhost:8787
export GOOGLE_OAUTH_JSON_FILE=$HOME/path/to/client_secret.json
export TOKEN_KEY=$(openssl rand -base64 32)
cargo run --release
```

Then add `http://localhost:8787/mcp` as a connector in an MCP client that allows localhost, or test with the MCP Inspector.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

## Security

- The code that handles your Google access is all here: sign-in in `src/oauth.rs`, token sealing in `src/crypto.rs`, storage in `src/store.rs`.
- The connector asks Google only for `webmasters.readonly`. It cannot change anything in Search Console.
- You can remove its access at any time at https://myaccount.google.com/permissions. The connector then drops every token it issued for your account.
- Report a security problem privately to security@modelbrain.net rather than in a public issue.

## License

MIT. See [LICENSE](LICENSE). "ModelBrain" is a trademark of Matthew Firth; the license covers the code, not the name or logo.
