//! Single-use enforcement for signature nonces.
//!
//! A signature that verifies is still replayable until it expires, so a
//! captured request can be resent verbatim inside its window. Remembering
//! every nonce already accepted closes that, at the cost of state the verifier
//! has to hold.
//!
//! Same hygiene pattern as [`crate::ChallengeStore`]: `DashMap`-backed, hard
//! capacity cap, expired entries purged before anything live is evicted.
//! Note the direction of the relationship though. `ChallengeStore` *issues*
//! nonces and consumes them once; this guard never issues anything, it only
//! remembers what it has already honoured. When `Accept-Signature` server
//! nonces arrive, `ChallengeStore` is the store that should mint them.
//!
//! ## What the capacity bound costs
//!
//! At capacity, expired entries are purged first; if that frees nothing, the
//! entry with the least remaining life is evicted, which makes that one nonce
//! replayable again until its own `expires` passes. Bounded memory is the
//! deliberate trade: an unbounded map is a denial-of-service vector, and the
//! 24-hour cap on `expires - created` bounds how long an evicted nonce stays
//! useful. The exposure is also narrower than it looks, because callers
//! consult this guard only *after* a signature verifies (see
//! [`crate::http_sig::verify_request`]): filling it requires a stream of
//! genuinely valid signatures from a key the verifier already accepts, not
//! merely a stream of requests.

use super::HttpSigError;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// Default hard cap on remembered nonces. Override via
/// [`NonceReplayGuard::with_capacity`].
pub const MAX_SEEN_NONCES: usize = 8192;

/// Remembers the nonces of signatures already accepted, so each is honoured
/// at most once inside its validity window.
///
/// Cheap to share: put it behind an `Arc` and hand it to
/// [`crate::http_sig::VerifyOptions::with_replay_guard`].
#[derive(Debug)]
pub struct NonceReplayGuard {
    /// Nonce to the `expires` of the signature that carried it.
    seen: DashMap<String, i64>,
    /// Hard cap on remembered nonces (see [`MAX_SEEN_NONCES`]).
    capacity: usize,
}

impl NonceReplayGuard {
    /// A guard holding up to [`MAX_SEEN_NONCES`] nonces.
    pub fn new() -> Self {
        Self::with_capacity(MAX_SEEN_NONCES)
    }

    /// A guard with an explicit hard cap, overriding [`MAX_SEEN_NONCES`].
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: DashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Accept `nonce` if it has not been seen, remembering it until
    /// `expires_at` (UNIX seconds).
    ///
    /// # Errors
    ///
    /// [`HttpSigError::NonceReplayed`] if this nonce was already honoured.
    pub fn check_and_record(&self, nonce: &str, expires_at: i64) -> Result<(), HttpSigError> {
        self.check_and_record_at(nonce, expires_at, super::unix_now())
    }

    /// [`Self::check_and_record`] against an explicit clock.
    pub(crate) fn check_and_record_at(
        &self,
        nonce: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), HttpSigError> {
        // Look for the replay before making room. The other order lets a
        // capacity-triggered eviction remove the very entry that proves this
        // nonce is a replay, which would turn a full guard into no guard.
        if self.seen.contains_key(nonce) {
            return Err(HttpSigError::NonceReplayed);
        }

        if self.seen.len() >= self.capacity {
            self.cleanup_expired_at(now);
            if self.seen.len() >= self.capacity {
                self.evict_soonest_expiring();
            }
        }

        // One shard-locked operation, so two concurrent presentations of the
        // same nonce cannot both find it absent.
        match self.seen.entry(nonce.to_string()) {
            Entry::Occupied(_) => Err(HttpSigError::NonceReplayed),
            Entry::Vacant(slot) => {
                slot.insert(expires_at);
                Ok(())
            }
        }
    }

    /// Drop every nonce whose signature has expired.
    pub fn cleanup_expired(&self) {
        self.cleanup_expired_at(super::unix_now());
    }

    /// [`Self::cleanup_expired`] against an explicit clock. `expires` is
    /// exclusive, matching verification.
    pub(crate) fn cleanup_expired_at(&self, now: i64) {
        self.seen.retain(|_, expires_at| *expires_at > now);
    }

    /// Evict the entry with the least remaining life, breaking ties by nonce
    /// so eviction never depends on `DashMap` iteration order.
    fn evict_soonest_expiring(&self) {
        let victim = self
            .seen
            .iter()
            .min_by(|a, b| {
                a.value()
                    .cmp(b.value())
                    .then_with(|| a.key().cmp(b.key()))
            })
            .map(|entry| entry.key().clone());
        if let Some(nonce) = victim {
            self.seen.remove(&nonce);
        }
    }

    /// Number of remembered nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The configured hard cap.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for NonceReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::HttpSigError;
    use super::*;

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn a_fresh_nonce_is_accepted_once() {
        let guard = NonceReplayGuard::new();
        assert!(guard.check_and_record_at("nonce-a", NOW + 300, NOW).is_ok());
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn the_same_nonce_twice_is_rejected() {
        let guard = NonceReplayGuard::new();
        guard.check_and_record_at("nonce-a", NOW + 300, NOW).unwrap();
        let err = guard
            .check_and_record_at("nonce-a", NOW + 300, NOW + 1)
            .unwrap_err();
        assert!(matches!(err, HttpSigError::NonceReplayed));
        assert_eq!(guard.len(), 1, "a replay must not add an entry");
    }

    #[test]
    fn distinct_nonces_are_independent() {
        let guard = NonceReplayGuard::new();
        for i in 0..10 {
            guard
                .check_and_record_at(&format!("nonce-{i}"), NOW + 300, NOW)
                .unwrap();
        }
        assert_eq!(guard.len(), 10);
    }

    #[test]
    fn an_empty_guard_reports_empty() {
        let guard = NonceReplayGuard::new();
        assert!(guard.is_empty());
        guard.check_and_record_at("nonce-a", NOW + 300, NOW).unwrap();
        assert!(!guard.is_empty());
    }

    #[test]
    fn cleanup_drops_entries_past_their_expiry() {
        let guard = NonceReplayGuard::new();
        guard.check_and_record_at("short", NOW + 10, NOW).unwrap();
        guard.check_and_record_at("long", NOW + 1000, NOW).unwrap();
        assert_eq!(guard.len(), 2);

        guard.cleanup_expired_at(NOW + 11);
        assert_eq!(guard.len(), 1);
        // The surviving entry is still enforced.
        assert!(guard
            .check_and_record_at("long", NOW + 1000, NOW + 11)
            .is_err());
    }

    #[test]
    fn expiry_is_exclusive_in_the_guard_too() {
        let guard = NonceReplayGuard::new();
        guard.check_and_record_at("n", NOW + 10, NOW).unwrap();
        guard.cleanup_expired_at(NOW + 10);
        assert_eq!(guard.len(), 0, "an entry at its expiry second is gone");
    }

    #[test]
    fn default_capacity_matches_the_constant() {
        assert_eq!(NonceReplayGuard::new().capacity(), MAX_SEEN_NONCES);
    }

    #[test]
    fn capacity_is_never_exceeded() {
        let guard = NonceReplayGuard::with_capacity(4);
        for i in 0..100 {
            guard
                .check_and_record_at(&format!("nonce-{i}"), NOW + 300, NOW)
                .unwrap();
            assert!(guard.len() <= 4, "hard cap violated at iteration {i}");
        }
    }

    #[test]
    fn expired_entries_are_purged_before_anything_live_is_evicted() {
        let guard = NonceReplayGuard::with_capacity(2);
        guard.check_and_record_at("old-a", NOW + 10, NOW).unwrap();
        guard.check_and_record_at("old-b", NOW + 10, NOW).unwrap();

        // Both prior entries are past their expiry, so making room must reclaim
        // them rather than evict anything still live.
        guard
            .check_and_record_at("fresh", NOW + 1000, NOW + 20)
            .unwrap();
        assert_eq!(guard.len(), 1);
        assert!(guard
            .check_and_record_at("fresh", NOW + 1000, NOW + 20)
            .is_err());
    }

    #[test]
    fn the_soonest_expiring_entry_is_evicted_when_still_full() {
        let guard = NonceReplayGuard::with_capacity(2);
        guard.check_and_record_at("soonest", NOW + 100, NOW).unwrap();
        guard.check_and_record_at("later", NOW + 900, NOW).unwrap();

        // Nothing is expired at NOW, so a third entry must displace the one
        // with the least remaining life.
        guard.check_and_record_at("newest", NOW + 900, NOW).unwrap();
        assert_eq!(guard.len(), 2);

        // The retained entries are still enforced ...
        assert!(guard.check_and_record_at("later", NOW + 900, NOW).is_err());
        assert!(guard.check_and_record_at("newest", NOW + 900, NOW).is_err());
        // ... and the evicted one is replayable again, which is the documented
        // cost of a bounded guard.
        assert!(guard.check_and_record_at("soonest", NOW + 100, NOW).is_ok());
    }

    #[test]
    fn a_replay_is_detected_even_when_the_guard_is_full() {
        // Making room must never evict the entry that proves the replay.
        let guard = NonceReplayGuard::with_capacity(1);
        guard.check_and_record_at("only", NOW + 300, NOW).unwrap();
        assert!(matches!(
            guard.check_and_record_at("only", NOW + 300, NOW),
            Err(HttpSigError::NonceReplayed)
        ));
    }
}
