//! Related origins in an `AssertionPolicy`, through the public API only.
//!
//! A user whose passkey was registered under siwx-oidc's host RP ID (here
//! `dev.siwx.inblock.io`) signs in on an app on another host (here
//! `dev.aqua-node.inblock.io`, which does not sit within that RP ID) through a
//! WebAuthn Level 3 related origin request. The server must accept an
//! assertion whose `rpIdHash` is the siwx host and whose `clientDataJSON`
//! origin is the app, and recover the passkey's own `did:key`. `SoftPasskey`
//! stands in for browser and authenticator.

use aqua_auth::{
    verify_and_recover, AssertOpts, AssertionError, AssertionPolicy, ExpectedChallenge,
    PolicyError, SelectionError, SoftPasskey,
};
use aqua_auth::{PendingRecovery, Selection};

/// siwx-oidc's host RP ID: where the passkeys were registered.
const SIWX_RP: &str = "dev.siwx.inblock.io";
/// The shared RP ID of the other apps.
const SHARED_RP: &str = "inblock.io";
/// The explorer: not within `SIWX_RP`, published by the siwx host as a related origin.
const EXPLORER: &str = "https://dev.aqua-node.inblock.io";
/// An origin listed only under the shared RP ID.
const AQUAFIRE: &str = "https://aquafire.inblock.io";
const CHALLENGE: &[u8] = b"related origin test challenge..!";

/// Entry A: the shared RP ID, origins within it. Entry B: the siwx host RP ID,
/// the explorer as a related origin.
fn policy() -> AssertionPolicy {
    AssertionPolicy::builder()
        .rp(SHARED_RP, &[AQUAFIRE])
        .unwrap()
        .rp_with_related_origins(SIWX_RP, &[], &[EXPLORER])
        .unwrap()
        .build()
        .unwrap()
}

fn verify(
    pk: &SoftPasskey,
    origin: &str,
    challenge: &[u8],
) -> Result<aqua_auth::RecoveredAssertion, AssertionError> {
    let a = pk.assert(&AssertOpts::new(challenge, origin));
    verify_and_recover(&a, ExpectedChallenge::Exact(challenge), &policy())
}

#[test]
fn t2_legacy_rp_assertion_from_related_origin_recovers_the_signers_did() {
    let pk = SoftPasskey::new_seeded(7, SIWX_RP);
    let rec = verify(&pk, EXPLORER, CHALLENGE).expect("a listed related origin is accepted");
    assert_eq!(rec.rp_id, SIWX_RP);
    assert_eq!(rec.origin, EXPLORER);
    assert!(
        rec.candidate_dids().contains(&pk.did()),
        "the signer's did:key is one of the two recovered candidates"
    );

    // The full login: a second assertion from the same related origin picks
    // the signer, and the principal is the passkey's own did:key.
    let pending: PendingRecovery = match rec.select(&[], [false, false]) {
        Selection::NeedSecondAssertion(p) => p,
        other => panic!("nothing to choose by, got {other:?}"),
    };
    let second_challenge = b"related origin second challenge!";
    let rec2 = verify(&pk, EXPLORER, second_challenge).expect("second assertion verifies");
    let principal = pending
        .resolve(&rec2)
        .expect("one key both assertions recover");
    assert_eq!(principal.did(), pk.did());

    // Another passkey does not complete this login.
    let other = SoftPasskey {
        credential_id: pk.credential_id.clone(),
        ..SoftPasskey::new_seeded(8, SIWX_RP)
    };
    let rec_other = verify(&other, EXPLORER, second_challenge).unwrap();
    assert_eq!(
        pending.resolve(&rec_other),
        Err(SelectionError::NoCommonCandidate)
    );
}

#[test]
fn t3_origins_never_cross_entries() {
    // A's rpIdHash from B's related origin: refused.
    let on_shared = SoftPasskey::new_seeded(11, SHARED_RP);
    assert_eq!(
        verify(&on_shared, EXPLORER, CHALLENGE).err(),
        Some(AssertionError::OriginNotAllowed)
    );
    // B's rpIdHash from an origin only listed under A: refused.
    let on_siwx = SoftPasskey::new_seeded(12, SIWX_RP);
    assert_eq!(
        verify(&on_siwx, AQUAFIRE, CHALLENGE).err(),
        Some(AssertionError::OriginNotAllowed)
    );
    // Each pairing that the policy lists is accepted, so the refusals above
    // are about the pairing and not about the fixtures.
    verify(&on_shared, AQUAFIRE, CHALLENGE).expect("A from its own origin");
    verify(&on_siwx, EXPLORER, CHALLENGE).expect("B from its related origin");
}

#[test]
fn t4_unlisted_origin_for_the_related_origin_entry_is_refused() {
    let pk = SoftPasskey::new_seeded(13, SIWX_RP);
    for bad in [
        "https://evil.example.com",
        // The prod explorer is not listed under the dev entry.
        "https://aqua-node.inblock.io",
        // Lookalikes of the listed origin.
        "https://dev.aqua-node.inblock.io.evil.com",
        "https://evildev.aqua-node.inblock.io",
        "http://dev.aqua-node.inblock.io",
        "https://dev.aqua-node.inblock.io:8443",
        // The RP host itself is not listed either (no origins within it).
        "https://dev.siwx.inblock.io",
    ] {
        assert_eq!(
            verify(&pk, bad, CHALLENGE).err(),
            Some(AssertionError::OriginNotAllowed),
            "{bad}"
        );
    }
    // An RP ID the policy does not serve is still refused first.
    let stranger = SoftPasskey::new_seeded(14, "evil.example.com");
    assert_eq!(
        verify(&stranger, EXPLORER, CHALLENGE).err(),
        Some(AssertionError::RpIdNotAllowed)
    );
}

#[test]
fn t5_malformed_related_origins_are_refused_at_build() {
    for bad in [
        "http://dev.aqua-node.inblock.io",       // http outside localhost
        "https://dev.aqua-node.inblock.io/x",    // path
        "https://dev.aqua-node.inblock.io/?q=1", // query
        "https://dev.aqua-node.inblock.io/#f",   // fragment
        "https://user@dev.aqua-node.inblock.io", // user info
        "https://user:pw@dev.aqua-node.inblock.io",
        "https://*.inblock.io", // wildcard
        "ftp://dev.aqua-node.inblock.io",
        "https://203.0.113.5", // IP literal
        "https://[::1]",
        "not an origin",
        "",
    ] {
        let err = AssertionPolicy::builder()
            .rp_with_related_origins(SIWX_RP, &[], &[bad])
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must be refused as a related origin"));
        assert!(
            matches!(err, PolicyError::InvalidOrigin { .. }),
            "{bad:?}: {err}"
        );
    }
    // A malformed entry in either list refuses the whole RP, even beside a good one.
    assert!(AssertionPolicy::builder()
        .rp_with_related_origins(SIWX_RP, &[], &[EXPLORER, "https://x.example.com/p"])
        .is_err());
    assert!(AssertionPolicy::builder()
        .rp_with_related_origins(SIWX_RP, &["http://dev.siwx.inblock.io"], &[EXPLORER])
        .is_err());

    // `origins` keep today's rule: an outside origin there is still refused.
    assert!(matches!(
        AssertionPolicy::builder()
            .rp_with_related_origins(SIWX_RP, &[EXPLORER], &[])
            .err(),
        Some(PolicyError::OriginOutsideRpId { .. })
    ));
    // Both lists empty.
    assert!(matches!(
        AssertionPolicy::builder()
            .rp_with_related_origins(SIWX_RP, &[], &[])
            .err(),
        Some(PolicyError::NoOrigins { .. })
    ));
    // The same RP ID twice, across the two builder methods.
    assert!(matches!(
        AssertionPolicy::builder()
            .rp(SIWX_RP, &["https://dev.siwx.inblock.io"])
            .unwrap()
            .rp_with_related_origins(SIWX_RP, &[], &[EXPLORER])
            .err(),
        Some(PolicyError::DuplicateRpId { .. })
    ));
}

#[test]
fn rp_alone_still_refuses_an_origin_outside_its_rp() {
    // The fixed pairing of T2 through `rp()` must stay impossible.
    assert!(matches!(
        AssertionPolicy::builder().rp(SIWX_RP, &[EXPLORER]).err(),
        Some(PolicyError::OriginOutsideRpId { .. })
    ));
}
