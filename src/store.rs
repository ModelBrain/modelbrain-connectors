//! SQLite storage. Holds registered MCP clients, sign-ins in progress,
//! hashed codes and tokens, and one sealed Google refresh token per Google
//! account. No Search Console data and no email addresses are stored.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PENDING_TTL: i64 = 15 * 60;
pub const CODE_TTL: i64 = 10 * 60;
pub const ACCESS_TTL: i64 = 60 * 60;
pub const REFRESH_TTL: i64 = 90 * 24 * 60 * 60;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRow {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuth {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub client_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRow {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub sub: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
}

impl TokenKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS clients(
                client_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                created INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS pending(
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                client_state TEXT,
                created INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS codes(
                hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                sub TEXT NOT NULL,
                expires INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS tokens(
                hash TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                client_id TEXT NOT NULL,
                sub TEXT NOT NULL,
                expires INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS tokens_sub ON tokens(sub);
             CREATE TABLE IF NOT EXISTS accounts(
                sub TEXT PRIMARY KEY,
                refresh BLOB NOT NULL,
                scopes TEXT NOT NULL,
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert_client(&self, row: &ClientRow) -> rusqlite::Result<()> {
        let uris = serde_json::to_string(&row.redirect_uris).unwrap_or_else(|_| "[]".into());
        self.c().execute(
            "INSERT INTO clients(client_id, client_name, redirect_uris, created) VALUES(?1,?2,?3,?4)",
            params![row.client_id, row.client_name, uris, now()],
        )?;
        Ok(())
    }

    pub fn client(&self, client_id: &str) -> rusqlite::Result<Option<ClientRow>> {
        self.c()
            .query_row(
                "SELECT client_id, client_name, redirect_uris FROM clients WHERE client_id=?1",
                params![client_id],
                |r| {
                    let uris: String = r.get(2)?;
                    Ok(ClientRow {
                        client_id: r.get(0)?,
                        client_name: r.get(1)?,
                        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
                    })
                },
            )
            .optional()
    }

    /// Stores (or refreshes) a client that identified itself with a metadata document; its
    /// client_id is the document URL and `created` records when the document was last checked.
    pub fn upsert_client(&self, row: &ClientRow) -> rusqlite::Result<()> {
        let uris = serde_json::to_string(&row.redirect_uris).unwrap_or_else(|_| "[]".into());
        self.c().execute(
            "INSERT INTO clients(client_id, client_name, redirect_uris, created) VALUES(?1,?2,?3,?4)
             ON CONFLICT(client_id) DO UPDATE SET client_name=excluded.client_name,
               redirect_uris=excluded.redirect_uris, created=excluded.created",
            params![row.client_id, row.client_name, uris, now()],
        )?;
        Ok(())
    }

    /// A client and when it was stored (for a metadata document client: last checked).
    pub fn client_with_age(&self, client_id: &str) -> rusqlite::Result<Option<(ClientRow, i64)>> {
        self.c()
            .query_row(
                "SELECT client_id, client_name, redirect_uris, created FROM clients WHERE client_id=?1",
                params![client_id],
                |r| {
                    let uris: String = r.get(2)?;
                    Ok((
                        ClientRow {
                            client_id: r.get(0)?,
                            client_name: r.get(1)?,
                            redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
                        },
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
    }

    pub fn insert_pending(&self, p: &PendingAuth) -> rusqlite::Result<()> {
        self.c().execute(
            "INSERT INTO pending(id, client_id, redirect_uri, code_challenge, client_state, created)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![p.id, p.client_id, p.redirect_uri, p.code_challenge, p.client_state, now()],
        )?;
        Ok(())
    }

    /// Removes and returns a sign-in in progress, if it exists and is fresh.
    pub fn take_pending(&self, id: &str) -> rusqlite::Result<Option<PendingAuth>> {
        let conn = self.c();
        let row = conn
            .query_row(
                "SELECT id, client_id, redirect_uri, code_challenge, client_state, created
                 FROM pending WHERE id=?1",
                params![id],
                |r| {
                    Ok((
                        PendingAuth {
                            id: r.get(0)?,
                            client_id: r.get(1)?,
                            redirect_uri: r.get(2)?,
                            code_challenge: r.get(3)?,
                            client_state: r.get(4)?,
                        },
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        conn.execute("DELETE FROM pending WHERE id=?1", params![id])?;
        Ok(row.and_then(|(p, created)| (now() - created <= PENDING_TTL).then_some(p)))
    }

    pub fn insert_code(&self, hash: &str, row: &CodeRow) -> rusqlite::Result<()> {
        self.c().execute(
            "INSERT INTO codes(hash, client_id, redirect_uri, code_challenge, sub, expires)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![hash, row.client_id, row.redirect_uri, row.code_challenge, row.sub, now() + CODE_TTL],
        )?;
        Ok(())
    }

    /// Codes are single use: the row is deleted whether or not it is valid.
    pub fn take_code(&self, hash: &str) -> rusqlite::Result<Option<CodeRow>> {
        let conn = self.c();
        let row = conn
            .query_row(
                "SELECT client_id, redirect_uri, code_challenge, sub, expires FROM codes WHERE hash=?1",
                params![hash],
                |r| {
                    Ok((
                        CodeRow {
                            client_id: r.get(0)?,
                            redirect_uri: r.get(1)?,
                            code_challenge: r.get(2)?,
                            sub: r.get(3)?,
                        },
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        conn.execute("DELETE FROM codes WHERE hash=?1", params![hash])?;
        Ok(row.and_then(|(c, expires)| (expires > now()).then_some(c)))
    }

    pub fn insert_token(
        &self,
        hash: &str,
        kind: TokenKind,
        client_id: &str,
        sub: &str,
        ttl: i64,
    ) -> rusqlite::Result<()> {
        self.c().execute(
            "INSERT INTO tokens(hash, kind, client_id, sub, expires) VALUES(?1,?2,?3,?4,?5)",
            params![hash, kind.as_str(), client_id, sub, now() + ttl],
        )?;
        Ok(())
    }

    /// Returns (sub, client_id) for a live token of the given kind.
    pub fn token(&self, hash: &str, kind: TokenKind) -> rusqlite::Result<Option<(String, String)>> {
        self.c()
            .query_row(
                "SELECT sub, client_id FROM tokens WHERE hash=?1 AND kind=?2 AND expires>?3",
                params![hash, kind.as_str(), now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    pub fn delete_token(&self, hash: &str) -> rusqlite::Result<()> {
        self.c().execute("DELETE FROM tokens WHERE hash=?1", params![hash])?;
        Ok(())
    }

    pub fn upsert_account(&self, sub: &str, sealed_refresh: &[u8], scopes: &str) -> rusqlite::Result<()> {
        let t = now();
        self.c().execute(
            "INSERT INTO accounts(sub, refresh, scopes, created, updated, revoked)
             VALUES(?1,?2,?3,?4,?4,0)
             ON CONFLICT(sub) DO UPDATE SET refresh=excluded.refresh, scopes=excluded.scopes,
               updated=excluded.updated, revoked=0",
            params![sub, sealed_refresh, scopes, t],
        )?;
        Ok(())
    }

    pub fn account_exists(&self, sub: &str) -> rusqlite::Result<bool> {
        Ok(self
            .c()
            .query_row("SELECT 1 FROM accounts WHERE sub=?1 AND revoked=0", params![sub], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// The sealed Google refresh token for an account that has not been revoked.
    pub fn account_refresh(&self, sub: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        self.c()
            .query_row(
                "SELECT refresh FROM accounts WHERE sub=?1 AND revoked=0",
                params![sub],
                |r| r.get(0),
            )
            .optional()
    }

    /// Google said the refresh token is no longer valid: stop using it and
    /// drop every token we issued for that account, so the client signs in again.
    pub fn revoke_account(&self, sub: &str) -> rusqlite::Result<()> {
        let conn = self.c();
        // Delete outright: nothing about the account is kept once Google
        // access is gone. Signing in again creates a fresh row.
        conn.execute("DELETE FROM accounts WHERE sub=?1", params![sub])?;
        conn.execute("DELETE FROM tokens WHERE sub=?1", params![sub])?;
        conn.execute("DELETE FROM codes WHERE sub=?1", params![sub])?;
        Ok(())
    }

    pub fn purge_expired(&self) -> rusqlite::Result<()> {
        let t = now();
        let conn = self.c();
        conn.execute("DELETE FROM pending WHERE created < ?1", params![t - PENDING_TTL])?;
        conn.execute("DELETE FROM codes WHERE expires <= ?1", params![t])?;
        conn.execute("DELETE FROM tokens WHERE expires <= ?1", params![t])?;
        // An account nobody has used for the refresh lifetime has no tokens
        // left; delete it and its sealed Google token.
        conn.execute(
            "DELETE FROM accounts WHERE revoked=1
               OR (updated < ?1 AND sub NOT IN (SELECT sub FROM tokens))",
            params![t - REFRESH_TTL],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_round_trip() {
        let s = Store::open_in_memory().unwrap();
        let row = ClientRow {
            client_id: "mbc_1".into(),
            client_name: "Claude".into(),
            redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".into()],
        };
        s.insert_client(&row).unwrap();
        assert_eq!(s.client("mbc_1").unwrap(), Some(row));
        assert_eq!(s.client("nope").unwrap(), None);
    }

    #[test]
    fn codes_are_single_use() {
        let s = Store::open_in_memory().unwrap();
        let row = CodeRow {
            client_id: "c".into(),
            redirect_uri: "https://claude.ai/cb".into(),
            code_challenge: "x".into(),
            sub: "123".into(),
        };
        s.insert_code("h", &row).unwrap();
        assert_eq!(s.take_code("h").unwrap(), Some(row));
        assert_eq!(s.take_code("h").unwrap(), None);
    }

    #[test]
    fn pending_is_single_use() {
        let s = Store::open_in_memory().unwrap();
        let p = PendingAuth {
            id: "p1".into(),
            client_id: "c".into(),
            redirect_uri: "https://claude.ai/cb".into(),
            code_challenge: "x".into(),
            client_state: Some("st".into()),
        };
        s.insert_pending(&p).unwrap();
        assert_eq!(s.take_pending("p1").unwrap(), Some(p));
        assert_eq!(s.take_pending("p1").unwrap(), None);
    }

    #[test]
    fn tokens_by_kind_and_revocation() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_account("sub1", b"sealed-bytes-not-real", "scope").unwrap();
        s.insert_token("a", TokenKind::Access, "c", "sub1", 60).unwrap();
        s.insert_token("r", TokenKind::Refresh, "c", "sub1", 60).unwrap();
        assert_eq!(s.token("a", TokenKind::Access).unwrap(), Some(("sub1".into(), "c".into())));
        assert_eq!(s.token("a", TokenKind::Refresh).unwrap(), None);
        assert!(s.account_exists("sub1").unwrap());

        s.revoke_account("sub1").unwrap();
        assert_eq!(s.token("a", TokenKind::Access).unwrap(), None);
        assert_eq!(s.token("r", TokenKind::Refresh).unwrap(), None);
        assert_eq!(s.account_refresh("sub1").unwrap(), None);
        assert!(!s.account_exists("sub1").unwrap());

        // Signing in again restores the account.
        s.upsert_account("sub1", b"new-sealed", "scope").unwrap();
        assert_eq!(s.account_refresh("sub1").unwrap(), Some(b"new-sealed".to_vec()));
    }

    #[test]
    fn idle_accounts_are_purged() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_account("active", b"x", "scope").unwrap();
        s.upsert_account("idle", b"y", "scope").unwrap();
        s.c().execute("UPDATE accounts SET updated=?1", params![now() - REFRESH_TTL - 10]).unwrap();
        s.insert_token("t", TokenKind::Refresh, "c", "active", 60).unwrap();
        s.purge_expired().unwrap();
        assert!(s.account_exists("active").unwrap());
        assert!(!s.account_exists("idle").unwrap());
    }

    #[test]
    fn expired_tokens_are_not_returned() {
        let s = Store::open_in_memory().unwrap();
        s.insert_token("old", TokenKind::Access, "c", "sub1", -1).unwrap();
        assert_eq!(s.token("old", TokenKind::Access).unwrap(), None);
        s.purge_expired().unwrap();
    }
}
