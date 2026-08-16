//! Cryptographic identity for Pickle.
//!
//! There are no accounts and no login server. A user *is* an Ed25519 keypair
//! that lives on their machine, in the same spirit as a TeamSpeak 3 identity.
//! Servers recognise returning users by public key, and permissions are granted
//! to a key rather than to a username. Nicknames are cosmetic and unverified —
//! two people may share one, and the fingerprint is what actually distinguishes
//! them.
//!
//! Because identities are free to generate, an unqualified keypair is worthless
//! as a spam or ban-evasion deterrent. So, again following TeamSpeak, an
//! identity carries a *security level*: a proof of work over the public key.
//! Raising the level costs exponentially more CPU time, and a server can refuse
//! keys below a threshold. See [`security_level`].

mod keystore;
mod pow;

pub use keystore::{Keystore, KeystoreError};
pub use pow::{expected_hashes, mine, security_level, MineProgress, MineReport};

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Domain separator for the client's authentication signature.
const AUTH_CONTEXT: &[u8] = b"pickle-auth-v1";
/// Domain separator for the server's self-attestation in `ServerHello`.
const SERVER_HELLO_CONTEXT: &[u8] = b"pickle-server-hello-v1";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed public key")]
    MalformedKey,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("signature verification failed")]
    BadSignature,
    #[error("fingerprint is not valid base32")]
    BadFingerprint,
}

/// A stable, human-shareable name for a public key: `SHA-256(public_key)`.
///
/// Rendered as unpadded base32 in hyphenated groups so it can be read aloud or
/// compared by eye, which is how users will actually verify each other.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of(key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        Self(hasher.finalize().into())
    }

    /// The first 12 base32 characters, grouped — enough for UI lists and logs,
    /// never enough to authenticate against. Use the full value for that.
    pub fn short(&self) -> String {
        let full = BASE32_NOPAD.encode(&self.0).to_lowercase();
        let head = &full[..12];
        format!("{}-{}-{}", &head[0..4], &head[4..8], &head[8..12])
    }

    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .to_uppercase();
        let bytes = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| IdentityError::BadFingerprint)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::BadFingerprint)?;
        Ok(Self(arr))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = BASE32_NOPAD.encode(&self.0).to_lowercase();
        let groups: Vec<&str> = full
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        write!(f, "{}", groups.join("-"))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

/// The public half of an identity, as it travels on the wire.
///
/// `counter` is the proof-of-work witness: it is meaningless on its own, but
/// combined with `key` it lets anyone recompute the security level without
/// trusting the sender's claim about it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    #[serde(with = "key_bytes")]
    pub key: VerifyingKey,
    pub counter: u64,
}

impl PublicIdentity {
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.key)
    }

    /// Recompute the proof of work. Never trust a peer-supplied level.
    pub fn security_level(&self) -> u32 {
        security_level(self.key.as_bytes(), self.counter)
    }

    pub fn verify_auth(
        &self,
        nonce: &[u8; 32],
        server_cert_hash: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify(&auth_challenge(nonce, server_cert_hash), &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    pub fn verify_server_hello(
        &self,
        nonce: &[u8; 32],
        server_cert_hash: &[u8; 32],
        server_name: &str,
        signature: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify(
                &server_hello_challenge(nonce, server_cert_hash, server_name),
                &sig,
            )
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("fingerprint", &self.fingerprint().short())
            .field("level", &self.security_level())
            .finish()
    }
}

/// A full identity, private key included. Used by both clients and servers —
/// a server has exactly the same kind of identity as a user, which is what lets
/// a client pin a server across certificate rotations.
pub struct Identity {
    signing: SigningKey,
    counter: u64,
}

impl Identity {
    /// Generate a fresh identity at security level 0.
    ///
    /// Call [`Identity::mine`] afterwards to raise the level; servers that
    /// enforce a minimum will reject a level-0 key.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut csprng),
            counter: 0,
        }
    }

    pub fn from_secret_bytes(secret: &[u8; 32], counter: u64) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
            counter,
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            key: self.signing.verifying_key(),
            counter: self.counter,
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.signing.verifying_key())
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn security_level(&self) -> u32 {
        security_level(self.signing.verifying_key().as_bytes(), self.counter)
    }

    /// Search for a counter reaching `target_level`, keeping the result.
    ///
    /// The keypair is unchanged, so the fingerprint survives — only the witness
    /// improves. That means a user upgrades their identity without losing the
    /// permissions servers have granted them.
    pub fn mine(
        &mut self,
        target_level: u32,
        progress: &mut dyn FnMut(MineProgress) -> bool,
    ) -> MineReport {
        let report = mine(
            self.signing.verifying_key().as_bytes(),
            self.counter,
            target_level,
            progress,
        );
        if report.level > self.security_level() {
            self.counter = report.counter;
        }
        report
    }

    /// Sign a server's login challenge.
    ///
    /// The server's certificate hash is mixed in so the signature is only valid
    /// for the connection it was produced on. Without that binding, a hostile
    /// server could relay a client's response to a third server and log in as
    /// them.
    pub fn sign_auth(&self, nonce: &[u8; 32], server_cert_hash: &[u8; 32]) -> [u8; 64] {
        self.signing
            .sign(&auth_challenge(nonce, server_cert_hash))
            .to_bytes()
    }

    pub fn sign_server_hello(
        &self,
        nonce: &[u8; 32],
        server_cert_hash: &[u8; 32],
        server_name: &str,
    ) -> [u8; 64] {
        self.signing
            .sign(&server_hello_challenge(
                nonce,
                server_cert_hash,
                server_name,
            ))
            .to_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the secret.
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint().short())
            .field("level", &self.security_level())
            .finish()
    }
}

fn auth_challenge(nonce: &[u8; 32], server_cert_hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AUTH_CONTEXT.len() + 64);
    buf.extend_from_slice(AUTH_CONTEXT);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(server_cert_hash);
    buf
}

fn server_hello_challenge(
    nonce: &[u8; 32],
    server_cert_hash: &[u8; 32],
    server_name: &str,
) -> Vec<u8> {
    let name = server_name.as_bytes();
    let mut buf = Vec::with_capacity(SERVER_HELLO_CONTEXT.len() + 72 + name.len());
    buf.extend_from_slice(SERVER_HELLO_CONTEXT);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(server_cert_hash);
    // Length-prefixed so a name can't be shifted into the adjacent field.
    buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
    buf.extend_from_slice(name);
    buf
}

/// serde adapter: `VerifyingKey` as 32 raw bytes.
mod key_bytes {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(key.as_bytes(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let bytes = <[u8; 32] as serde::Deserialize>::deserialize(d)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_signature_roundtrips() {
        let id = Identity::generate();
        let nonce = [7u8; 32];
        let cert = [9u8; 32];
        let sig = id.sign_auth(&nonce, &cert);
        assert!(id.public().verify_auth(&nonce, &cert, &sig).is_ok());
    }

    #[test]
    fn auth_signature_is_bound_to_the_server_certificate() {
        // The property that stops a malicious server relaying a login elsewhere.
        let id = Identity::generate();
        let nonce = [7u8; 32];
        let sig = id.sign_auth(&nonce, &[9u8; 32]);
        assert!(id.public().verify_auth(&nonce, &[10u8; 32], &sig).is_err());
    }

    #[test]
    fn auth_signature_is_bound_to_the_nonce() {
        let id = Identity::generate();
        let cert = [9u8; 32];
        let sig = id.sign_auth(&[7u8; 32], &cert);
        assert!(id.public().verify_auth(&[8u8; 32], &cert, &sig).is_err());
    }

    #[test]
    fn another_identity_cannot_forge_a_login() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let (nonce, cert) = ([1u8; 32], [2u8; 32]);
        let sig = mallory.sign_auth(&nonce, &cert);
        assert!(alice.public().verify_auth(&nonce, &cert, &sig).is_err());
    }

    #[test]
    fn server_hello_covers_the_server_name() {
        let id = Identity::generate();
        let (nonce, cert) = ([1u8; 32], [2u8; 32]);
        let sig = id.sign_server_hello(&nonce, &cert, "Andy's Server");
        let pubid = id.public();
        assert!(pubid
            .verify_server_hello(&nonce, &cert, "Andy's Server", &sig)
            .is_ok());
        assert!(pubid
            .verify_server_hello(&nonce, &cert, "Evil Server", &sig)
            .is_err());
    }

    #[test]
    fn server_name_length_prefix_prevents_field_confusion() {
        let id = Identity::generate();
        let (nonce, cert) = ([1u8; 32], [2u8; 32]);
        let sig = id.sign_server_hello(&nonce, &cert, "ab");
        assert!(id
            .public()
            .verify_server_hello(&nonce, &cert, "a", &sig)
            .is_err());
    }

    #[test]
    fn fingerprint_display_roundtrips_through_parse() {
        let id = Identity::generate();
        let fp = id.fingerprint();
        assert_eq!(Fingerprint::parse(&fp.to_string()).unwrap(), fp);
        // Users will paste these with stray spacing.
        assert_eq!(Fingerprint::parse(&format!("  {}  ", fp)).unwrap(), fp);
    }

    #[test]
    fn fingerprint_is_derived_from_the_key_not_the_counter() {
        // Mining must not change identity, or upgrading would forfeit
        // every permission a server had granted.
        let mut id = Identity::generate();
        let before = id.fingerprint();
        id.mine(6, &mut |_| true);
        assert_eq!(id.fingerprint(), before);
        assert!(id.counter() > 0);
    }

    #[test]
    fn public_identity_serde_roundtrips() {
        let id = Identity::generate();
        let pubid = id.public();
        let json = serde_json::to_string(&pubid).unwrap();
        let back: PublicIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pubid);
    }
}
