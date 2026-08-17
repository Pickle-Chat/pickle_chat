//! Passphrase encryption for the identity vault.
//!
//! The shape is deliberately boring: a memory-hard KDF over the passphrase into
//! an AEAD over the whole vault document. Nothing here is novel, because nothing
//! here should be — this file guards the only copy of a user's identity.
//!
//! **Argon2id** for the KDF. A passphrase is low entropy, so the only real
//! defence against someone who has stolen the file is making each guess
//! expensive; a memory-hard function is what stops that cost being bought back
//! with a GPU or an FPGA. Argon2id specifically, rather than Argon2i or Argon2d,
//! because it is the hybrid the RFC recommends for password hashing: resistant
//! to side channels in its first pass and to time-memory trade-offs afterwards.
//!
//! **XChaCha20-Poly1305** for the cipher. It is authenticated, so a corrupted or
//! tampered file is *detected* rather than decrypted into garbage that would
//! look like a valid-but-wrong key. Its 192-bit nonce is the reason to prefer it
//! over ChaCha20-Poly1305 or AES-GCM here: a nonce that wide can be drawn at
//! random for every save with no counter to keep and no risk of a repeat, which
//! matters because the vault is rewritten on every nickname edit. It is also
//! pure software — constant-time without needing AES hardware, and no C
//! toolchain to build.
//!
//! **The KDF parameters live in the file.** They are not compiled in, so raising
//! the cost later cannot orphan a vault written by an older build: the file says
//! how it was made, and this code re-derives with whatever it finds there.
//!
//! A sealed vault therefore looks like this, and nothing in it is a secret:
//!
//! ```json
//! {
//!   "version": 3,
//!   "kdf": {
//!     "algorithm": "argon2id",
//!     "version": 19,
//!     "memory_kib": 19456,
//!     "iterations": 2,
//!     "parallelism": 1,
//!     "salt": "iAGAopFjlO1utFTIl8Yyog=="
//!   },
//!   "cipher": "xchacha20poly1305",
//!   "nonce": "ubspbD5C6AQq/C9NpWBMYFuVsQUflMr8",
//!   "ciphertext": "R76x3uYBTC7KYoeq…"
//! }
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Version of the encrypted envelope, as written in the file's `version` field.
///
/// It continues the vault's own numbering rather than starting a second one, so
/// a single field answers "can this build read this file". An older build meets
/// a version it does not know and says so, instead of parsing a plaintext vault
/// out of a file that has none.
pub(crate) const SEALED_VERSION: u32 = 3;

const ARGON2ID: &str = "argon2id";
const XCHACHA20_POLY1305: &str = "xchacha20poly1305";

/// 16 bytes: Argon2's recommended salt length, and far past any birthday
/// concern for the number of vaults one user will ever own.
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Domain separator for the authenticated header, so this file's bytes can never
/// be replayed as some other structure Pickle authenticates.
const AAD_CONTEXT: &[u8] = b"pickle-vault-seal-v1";

/// Refuse a memory cost above 1 GiB.
///
/// The parameters come from the file, and the file may be corrupt. Without a
/// ceiling a single flipped digit turns "unlock the vault" into an allocation
/// the machine cannot serve, which the user experiences as the app hanging
/// rather than as the file being damaged. No honest parameter is anywhere near
/// this.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// The cost this build writes into new files.
///
/// 19 MiB / 2 passes / 1 lane is the OWASP baseline for Argon2id and the
/// `argon2` crate's own default. It costs well under a second on a desktop core
/// — the whole budget for unlocking is one user-visible pause — while forcing an
/// attacker to hold 19 MiB per guess in parallel, which is what actually blunts
/// GPU cracking. Raising it later is safe: the numbers are recorded per file.
const DEFAULT_MEMORY_KIB: u32 = 19 * 1024;
const DEFAULT_ITERATIONS: u32 = 2;
const DEFAULT_PARALLELISM: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The AEAD tag did not verify. Wrong passphrase and damaged file are the
    /// same event here, and that is by design: distinguishing them would mean
    /// trusting something in the file that was not authenticated.
    #[error("the passphrase is wrong, or the file has been damaged")]
    Unauthentic,
    #[error("unknown key-derivation function {0:?}")]
    UnsupportedKdf(String),
    #[error("unknown cipher {0:?}")]
    UnsupportedCipher(String),
    #[error("key-derivation parameters are out of range: {0}")]
    BadParams(String),
    #[error("the encrypted body is malformed")]
    BadEncoding,
}

/// How the key was derived, recorded alongside the ciphertext it protects.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct KdfHeader {
    /// Named rather than implied, so a future move to scrypt is a new value here
    /// and not a new file format.
    pub algorithm: String,
    /// Argon2's own version number; 19 is 0x13, the only one in current use.
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// Base64, freshly drawn per file. Its job is to make a precomputed table
    /// useless against this vault in particular.
    pub salt: String,
}

/// The encrypted vault as it sits on disk.
///
/// The plaintext inside is byte-for-byte the same document an unencrypted vault
/// stores. Encryption is a wrapper, not a second format, so there is exactly one
/// piece of code that understands what an identity looks like.
#[derive(Serialize, Deserialize)]
pub(crate) struct SealedVault {
    pub version: u32,
    pub kdf: KdfHeader,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// A derived key, kept for the life of the unlocked vault.
///
/// Cached deliberately: the vault is rewritten whenever a nickname or the active
/// identity changes, and re-running a deliberately slow KDF on each of those
/// would either make the app stutter or push us toward cheaper parameters. The
/// salt is reused across those saves, which is safe — the salt exists to stop
/// precomputation across *different* vaults, not to vary per write — while the
/// nonce is drawn fresh every time, which is what actually must not repeat.
pub(crate) struct VaultKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    header: KdfHeader,
}

impl VaultKey {
    /// Derive from a passphrase with a fresh salt and this build's parameters.
    pub(crate) fn fresh(passphrase: &str) -> Result<Self, SealError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let header = KdfHeader {
            algorithm: ARGON2ID.to_string(),
            version: Version::V0x13 as u32,
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt: BASE64.encode(&salt),
        };
        Self::derive(passphrase, &header)
    }

    /// Re-derive using the parameters a file recorded.
    pub(crate) fn derive(passphrase: &str, header: &KdfHeader) -> Result<Self, SealError> {
        if header.algorithm != ARGON2ID {
            return Err(SealError::UnsupportedKdf(header.algorithm.clone()));
        }
        if header.version != Version::V0x13 as u32 {
            return Err(SealError::BadParams(format!(
                "argon2 version {}",
                header.version
            )));
        }
        if header.memory_kib > MAX_MEMORY_KIB {
            return Err(SealError::BadParams(format!(
                "{} KiB of memory is beyond the {MAX_MEMORY_KIB} KiB this build will allocate",
                header.memory_kib
            )));
        }

        let salt = BASE64
            .decode(header.salt.as_bytes())
            .map_err(|_| SealError::BadEncoding)?;
        if salt.len() < argon2::MIN_SALT_LEN {
            return Err(SealError::BadParams(format!(
                "a {}-byte salt is too short",
                salt.len()
            )));
        }

        let params = Params::new(
            header.memory_kib,
            header.iterations,
            header.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|e| SealError::BadParams(e.to_string()))?;

        // Zeroizing from the start: this is the value that unlocks every key in
        // the file, so it must never be left behind in freed heap.
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut_slice())
            .map_err(|e| SealError::BadParams(e.to_string()))?;

        Ok(Self {
            key,
            header: header.clone(),
        })
    }

    /// Encrypt a vault document under a freshly drawn nonce.
    pub(crate) fn seal(&self, plaintext: &[u8]) -> Result<SealedVault, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let aad = associated_data(SEALED_VERSION, &self.header, XCHACHA20_POLY1305);
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            // Only reachable for a plaintext far larger than any vault; there is
            // nothing useful to say about it beyond "this did not encrypt".
            .map_err(|_| SealError::Unauthentic)?;

        Ok(SealedVault {
            version: SEALED_VERSION,
            kdf: self.header.clone(),
            cipher: XCHACHA20_POLY1305.to_string(),
            nonce: BASE64.encode(&nonce),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    /// Decrypt, or say why not.
    ///
    /// Returns the plaintext in a [`Zeroizing`]: it is the vault's JSON, secret
    /// keys and all, and the caller is expected to keep it that way.
    pub(crate) fn open(&self, sealed: &SealedVault) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if sealed.cipher != XCHACHA20_POLY1305 {
            return Err(SealError::UnsupportedCipher(sealed.cipher.clone()));
        }

        let nonce: [u8; NONCE_LEN] = BASE64
            .decode(sealed.nonce.as_bytes())
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or(SealError::BadEncoding)?;
        let ciphertext = BASE64
            .decode(sealed.ciphertext.as_bytes())
            .map_err(|_| SealError::BadEncoding)?;

        // The header is authenticated rather than merely read. Most of it
        // already is implicitly — change a KDF parameter and the derived key
        // simply comes out wrong — but the version and cipher name feed no
        // derivation, and binding them keeps an attacker from editing the file's
        // self-description without the tag noticing.
        let aad = associated_data(sealed.version, &sealed.kdf, &sealed.cipher);
        let plaintext = self
            .cipher()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Unauthentic)?;

        Ok(Zeroizing::new(plaintext))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        // `Key` is 32 bytes of copied key material, but `XChaCha20Poly1305`
        // zeroizes its round key on drop (the crate's `zeroize` feature), so the
        // copy does not outlive this call.
        XChaCha20Poly1305::new(&Key::from(*self.key))
    }
}

/// The bytes the AEAD authenticates but does not encrypt.
///
/// Every field is length-prefixed, so no combination of a longer algorithm name
/// and a shorter salt can produce the same byte string as some other header —
/// the same reason the login challenge in `lib.rs` length-prefixes the server
/// name.
fn associated_data(version: u32, kdf: &KdfHeader, cipher: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AAD_CONTEXT.len() + 64 + kdf.salt.len() + cipher.len());
    buf.extend_from_slice(AAD_CONTEXT);
    buf.extend_from_slice(&version.to_le_bytes());
    push_str(&mut buf, &kdf.algorithm);
    buf.extend_from_slice(&kdf.version.to_le_bytes());
    buf.extend_from_slice(&kdf.memory_kib.to_le_bytes());
    buf.extend_from_slice(&kdf.iterations.to_le_bytes());
    buf.extend_from_slice(&kdf.parallelism.to_le_bytes());
    push_str(&mut buf, &kdf.salt);
    push_str(&mut buf, cipher);
    buf
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_document_comes_back_under_the_same_passphrase() {
        let key = VaultKey::fresh("correct horse battery staple").unwrap();
        let sealed = key.seal(b"{\"secret\":true}").unwrap();

        // Re-derived from the file's own header, exactly as a fresh process
        // would, rather than reusing the cached key.
        let reopened = VaultKey::derive("correct horse battery staple", &sealed.kdf).unwrap();
        assert_eq!(&reopened.open(&sealed).unwrap()[..], b"{\"secret\":true}");
    }

    #[test]
    fn a_wrong_passphrase_fails_rather_than_returning_rubbish() {
        // The property that matters: a near miss must not decrypt to bytes the
        // caller might mistake for a key.
        let key = VaultKey::fresh("hunter2").unwrap();
        let sealed = key.seal(b"the vault").unwrap();

        let wrong = VaultKey::derive("hunter3", &sealed.kdf).unwrap();
        assert!(matches!(wrong.open(&sealed), Err(SealError::Unauthentic)));
    }

    #[test]
    fn every_save_draws_a_new_nonce() {
        // Reusing a nonce under one key would leak the XOR of two vaults.
        let key = VaultKey::fresh("hunter2").unwrap();
        let first = key.seal(b"the vault").unwrap();
        let second = key.seal(b"the vault").unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn two_vaults_with_the_same_passphrase_get_different_salts() {
        let first = VaultKey::fresh("hunter2").unwrap();
        let second = VaultKey::fresh("hunter2").unwrap();
        assert_ne!(first.header.salt, second.header.salt);
        assert_ne!(first.key.as_slice(), second.key.as_slice());
    }

    #[test]
    fn a_tampered_header_is_detected() {
        let key = VaultKey::fresh("hunter2").unwrap();
        let mut sealed = key.seal(b"the vault").unwrap();

        // Downgrading the recorded cost would be an attacker's way to make a
        // future re-derivation cheap to attack.
        sealed.kdf.iterations = 1;
        let rederived = VaultKey::derive("hunter2", &sealed.kdf).unwrap();
        assert!(matches!(
            rederived.open(&sealed),
            Err(SealError::Unauthentic)
        ));
    }

    #[test]
    fn a_truncated_ciphertext_is_reported() {
        let key = VaultKey::fresh("hunter2").unwrap();
        let mut sealed = key.seal(b"the vault").unwrap();
        sealed.ciphertext.truncate(4);

        assert!(key.open(&sealed).is_err());
    }

    #[test]
    fn an_unknown_algorithm_is_refused_rather_than_guessed() {
        let key = VaultKey::fresh("hunter2").unwrap();
        let mut header = key.header.clone();
        header.algorithm = "rot13".into();

        assert!(matches!(
            VaultKey::derive("hunter2", &header),
            Err(SealError::UnsupportedKdf(_))
        ));
    }

    #[test]
    fn an_absurd_memory_cost_is_refused_rather_than_allocated() {
        let key = VaultKey::fresh("hunter2").unwrap();
        let mut header = key.header.clone();
        header.memory_kib = u32::MAX;

        assert!(matches!(
            VaultKey::derive("hunter2", &header),
            Err(SealError::BadParams(_))
        ));
    }

    #[test]
    fn an_unknown_cipher_is_refused_rather_than_guessed() {
        let key = VaultKey::fresh("hunter2").unwrap();
        let mut sealed = key.seal(b"the vault").unwrap();
        sealed.cipher = "rot13".into();

        assert!(matches!(
            key.open(&sealed),
            Err(SealError::UnsupportedCipher(_))
        ));
    }
}
