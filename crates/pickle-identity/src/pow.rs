//! Proof of work over a public key, giving identities a *security level*.
//!
//! Generating an Ed25519 keypair is instant, so on its own a key proves nothing
//! about the effort behind it — a banned user simply makes another. Attaching a
//! proof of work puts a price on a *usable* identity while leaving key
//! generation itself free.
//!
//! The level is the number of leading zero bits in
//! `SHA-256(context || public_key || counter)`. Each additional level doubles
//! the expected search, so the cost curve is exponential: level 20 is roughly a
//! million hashes (seconds), level 30 is a billion (tens of minutes), level 40
//! is out of reach for casual abuse.
//!
//! The counter is a witness, not a secret. Anyone can recompute the level from
//! the public key alone, so a peer's claim about its own level is never trusted.

use sha2::{Digest, Sha256};

/// Domain separator. Keeps these hashes from colliding with any other use of
/// SHA-256 over a public key elsewhere in the protocol.
const POW_CONTEXT: &[u8] = b"pickle-identity-pow-v1";

/// How often [`mine`] pauses to report progress and check for cancellation.
const PROGRESS_INTERVAL: u64 = 1 << 16;

/// Number of leading zero bits in `SHA-256(context || public_key || counter)`.
pub fn security_level(public_key: &[u8; 32], counter: u64) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(POW_CONTEXT);
    hasher.update(public_key);
    hasher.update(counter.to_le_bytes());
    leading_zero_bits(&hasher.finalize())
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// A progress sample handed to the callback during [`mine`].
#[derive(Debug, Clone, Copy)]
pub struct MineProgress {
    /// Counter currently under test.
    pub counter: u64,
    /// Best level found so far, including the starting counter.
    pub best_level: u32,
    /// Hashes computed in this run.
    pub hashes: u64,
}

/// The outcome of a [`mine`] run.
#[derive(Debug, Clone, Copy)]
pub struct MineReport {
    /// Best counter found. Never worse than the one passed in.
    pub counter: u64,
    /// Level that counter achieves.
    pub level: u32,
    /// Hashes computed in this run.
    pub hashes: u64,
    /// True if the callback asked to stop before reaching the target.
    pub cancelled: bool,
}

/// Search for a counter reaching `target_level`.
///
/// Scanning resumes at `start_counter`, so repeated calls extend the previous
/// search rather than redoing it. `progress` is invoked every
/// [`PROGRESS_INTERVAL`] hashes and returns `false` to cancel; on cancellation
/// the best counter found so far is still returned, so partial work is kept.
///
/// This runs on the calling thread and will occupy it for a long time at high
/// target levels. Callers should give it a dedicated thread.
pub fn mine(
    public_key: &[u8; 32],
    start_counter: u64,
    target_level: u32,
    progress: &mut dyn FnMut(MineProgress) -> bool,
) -> MineReport {
    let mut best_counter = start_counter;
    let mut best_level = security_level(public_key, start_counter);
    let mut hashes = 0u64;
    let mut counter = start_counter;
    let mut cancelled = false;

    while best_level < target_level {
        counter = counter.wrapping_add(1);
        hashes += 1;

        let level = security_level(public_key, counter);
        if level > best_level {
            best_level = level;
            best_counter = counter;
        }

        if hashes % PROGRESS_INTERVAL == 0
            && !progress(MineProgress {
                counter,
                best_level,
                hashes,
            })
        {
            cancelled = true;
            break;
        }
    }

    MineReport {
        counter: best_counter,
        level: best_level,
        hashes,
        cancelled,
    }
}

/// Expected number of hashes to reach `level`, for showing users an estimate
/// before they commit to a long mine. Saturates rather than overflowing.
pub fn expected_hashes(level: u32) -> u64 {
    1u64.checked_shl(level).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0xff, 0x00]), 0);
        assert_eq!(leading_zero_bits(&[0x7f, 0x00]), 1);
        assert_eq!(leading_zero_bits(&[0x01, 0x00]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x00, 0x00]), 32);
    }

    #[test]
    fn security_level_is_deterministic() {
        let key = test_key();
        assert_eq!(security_level(&key, 12345), security_level(&key, 12345));
    }

    #[test]
    fn security_level_depends_on_both_key_and_counter() {
        assert_ne!(
            security_level(&test_key(), 1),
            security_level(&[0x43; 32], 1)
        );
    }

    #[test]
    fn mine_reaches_a_modest_target() {
        let key = test_key();
        let report = mine(&key, 0, 10, &mut |_| true);
        assert!(!report.cancelled);
        assert!(report.level >= 10);
        // The returned counter must actually be a valid witness.
        assert_eq!(security_level(&key, report.counter), report.level);
    }

    #[test]
    fn mine_never_returns_a_worse_counter_than_it_started_with() {
        let key = test_key();
        let good = mine(&key, 0, 12, &mut |_| true);
        // Ask for something already satisfied; the witness must survive.
        let again = mine(&key, good.counter, 4, &mut |_| true);
        assert_eq!(again.counter, good.counter);
        assert_eq!(again.hashes, 0);
    }

    #[test]
    fn cancellation_keeps_partial_work() {
        let key = test_key();
        // Target far out of reach so the run can only end by cancelling.
        let report = mine(&key, 0, 64, &mut |p| p.hashes < PROGRESS_INTERVAL * 2);
        assert!(report.cancelled);
        assert_eq!(security_level(&key, report.counter), report.level);
    }

    #[test]
    fn expected_hashes_saturates_instead_of_overflowing() {
        assert_eq!(expected_hashes(10), 1024);
        assert_eq!(expected_hashes(200), u64::MAX);
    }
}
