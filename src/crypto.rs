//! Random tokens, token hashing, PKCE and at-rest encryption of Google
//! refresh tokens.
//!
//! Our own access tokens, refresh tokens and authorization codes are stored
//! only as SHA-256 hashes, so a copy of the database cannot be replayed.
//! Google refresh tokens must be usable, so they are sealed with
//! ChaCha20-Poly1305 under a server key, with the Google account ID as
//! associated data so a sealed token cannot be moved to another account row.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// RFC 7636 S256: BASE64URL(SHA256(verifier)) == challenge.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let len_ok = (43..=128).contains(&verifier.len());
    let charset_ok = verifier
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'));
    if !len_ok || !charset_ok {
        return false;
    }
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Returns nonce (12 bytes) followed by ciphertext.
pub fn seal(key: &[u8; 32], aad: &str, plaintext: &str) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext.as_bytes(), aad: aad.as_bytes() },
        )
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], aad: &str, sealed: &[u8]) -> Result<String, String> {
    if sealed.len() < 12 + 16 {
        return Err("sealed value too short".into());
    }
    let (nonce, ct) = sealed.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: aad.as_bytes() })
        .map_err(|_| "decryption failed".to_string())?;
    String::from_utf8(pt).map_err(|_| "decrypted value is not UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_rfc7636_example() {
        // The worked example from RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX"));
        assert!(!pkce_matches("short", challenge));
    }

    #[test]
    fn seal_round_trip_and_aad_binding() {
        let key = [9u8; 32];
        let sealed = seal(&key, "sub-1", "1//refresh-token").unwrap();
        assert_eq!(open(&key, "sub-1", &sealed).unwrap(), "1//refresh-token");
        assert!(open(&key, "sub-2", &sealed).is_err());
        assert!(open(&[8u8; 32], "sub-1", &sealed).is_err());
    }

    #[test]
    fn tokens_are_random_and_hash_is_stable() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(hash_token("x"), hash_token("x"));
        assert_ne!(hash_token("x"), hash_token("y"));
    }
}
