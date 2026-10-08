//! The DID hint cookie: after a verified passkey login the app tells the
//! browser which `did:key` signed, so the next login on any service under the
//! same RP ID picks it in one prompt ([`crate::webauthn_select`] step 1).
//!
//! Wire format (one shape for every service):
//!
//! ```text
//! Set-Cookie: aqua_did_hint=did:key:zDn...; Domain=inblock.io; Path=/; Max-Age=34560000; Secure; SameSite=Lax
//! ```
//!
//! Deliberately not HttpOnly: a front end that talks to a credential-less
//! backend (aqua-explorer to aqua-node) writes and reads the same cookie from
//! script. The value is a public DID and only ever a candidate selector after
//! a verified assertion, so reading or tossing it can at worst cost a second
//! prompt. It is a separate cookie and never touches session cookies. Plain
//! `String` headers, so any HTTP framework can use them.

use crate::principal::Principal;
use crate::webauthn_select::DidHint;

/// The cookie name.
pub const HINT_COOKIE_NAME: &str = "aqua_did_hint";

/// 400 days, the longest lifetime browsers honour.
const HINT_MAX_AGE_SECS: u64 = 34_560_000;

/// Where the hint cookie is scoped and how long it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintCookieConfig {
    /// The `Domain` attribute; `None` makes a host-only cookie.
    pub domain: Option<String>,
    /// Whether to send the `Secure` attribute.
    pub secure: bool,
    /// The `Max-Age` attribute, in seconds.
    pub max_age_secs: u64,
}

impl HintCookieConfig {
    /// The cookie for every service under `rp_id`: `Domain=<rp_id>`, Secure,
    /// 400 days. `localhost` has no registrable domain, so its cookie is
    /// host-only.
    pub fn for_rp_id(rp_id: &str) -> Self {
        HintCookieConfig {
            domain: (rp_id != "localhost").then(|| rp_id.to_owned()),
            secure: true,
            max_age_secs: HINT_MAX_AGE_SECS,
        }
    }

    fn header(&self, value: &str, max_age_secs: u64) -> String {
        let mut h = format!("{HINT_COOKIE_NAME}={value}");
        if let Some(domain) = &self.domain {
            h.push_str("; Domain=");
            h.push_str(domain);
        }
        h.push_str(&format!("; Path=/; Max-Age={max_age_secs}"));
        if self.secure {
            h.push_str("; Secure");
        }
        h.push_str("; SameSite=Lax");
        h
    }
}

/// The `Set-Cookie` value naming `p` as the hint. Call it only after a
/// verified passkey login: readers keep P-256 `did:key` values only, so a
/// hint for any other principal would just overwrite a useful one.
pub fn hint_set_cookie(p: &Principal, cfg: &HintCookieConfig) -> String {
    cfg.header(p.did(), cfg.max_age_secs)
}

/// The `Set-Cookie` value that deletes the hint (same scope, `Max-Age=0`).
pub fn hint_clear_cookie(cfg: &HintCookieConfig) -> String {
    cfg.header("", 0)
}

/// Every hint in a `Cookie` request header value, in order. A browser sends
/// one value per matching cookie (a `Domain` one and a host-only one can
/// coexist), so all of them are returned; values that are not a canonical
/// P-256 `did:key` are dropped. For a request with several `Cookie` headers,
/// call it per header and concatenate.
pub fn hints_from_cookie_header(cookie_header: &str) -> Vec<DidHint> {
    cookie_header
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(name, _)| name.trim() == HINT_COOKIE_NAME)
        .filter_map(|(_, value)| {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            DidHint::parse(value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::p256_did_key_from_pubkey;
    use crate::webauthn_recover::test_support::key;

    fn did(seed: u64) -> String {
        let point = key(seed).verifying_key().to_encoded_point(true);
        p256_did_key_from_pubkey(point.as_bytes().try_into().unwrap())
    }

    fn principal(seed: u64) -> Principal {
        Principal::from_trusted_did(&did(seed)).unwrap()
    }

    fn strs(hints: &[DidHint]) -> Vec<&str> {
        hints.iter().map(DidHint::as_str).collect()
    }

    #[test]
    fn hint_cookie_roundtrip() {
        let p = principal(41);
        let set = hint_set_cookie(&p, &HintCookieConfig::for_rp_id("inblock.io"));
        // The browser sends back only `name=value`, among other cookies.
        let pair = set.split(';').next().unwrap();
        let header = format!("session=opaque; {pair}; theme=dark");
        assert_eq!(strs(&hints_from_cookie_header(&header)), [p.did()]);
    }

    #[test]
    fn set_cookie_attributes() {
        let p = principal(42);
        let cfg = HintCookieConfig::for_rp_id("inblock.io");
        assert_eq!(cfg.domain.as_deref(), Some("inblock.io"));
        assert!(cfg.secure);
        assert_eq!(cfg.max_age_secs, 34_560_000);
        assert_eq!(
            hint_set_cookie(&p, &cfg),
            format!(
                "aqua_did_hint={}; Domain=inblock.io; Path=/; Max-Age=34560000; Secure; SameSite=Lax",
                p.did()
            )
        );
        assert_eq!(HINT_COOKIE_NAME, "aqua_did_hint");
        assert!(!hint_set_cookie(&p, &cfg).contains("HttpOnly"));
    }

    #[test]
    fn localhost_rp_is_host_only() {
        let p = principal(43);
        let cfg = HintCookieConfig::for_rp_id("localhost");
        assert_eq!(cfg.domain, None);
        assert_eq!(
            hint_set_cookie(&p, &cfg),
            format!(
                "aqua_did_hint={}; Path=/; Max-Age=34560000; Secure; SameSite=Lax",
                p.did()
            )
        );
        // A config without Secure drops only that attribute.
        let plain = HintCookieConfig {
            secure: false,
            ..cfg
        };
        assert_eq!(
            hint_set_cookie(&p, &plain),
            format!(
                "aqua_did_hint={}; Path=/; Max-Age=34560000; SameSite=Lax",
                p.did()
            )
        );
    }

    #[test]
    fn parse_returns_all_values_for_duplicate_names() {
        // A Domain cookie and a host-only one (e.g. tossed from a sibling
        // host) arrive under the same name; selection needs both.
        let (a, b) = (did(44), did(45));
        let header = format!("aqua_did_hint={a}; other=1; aqua_did_hint={b}");
        assert_eq!(strs(&hints_from_cookie_header(&header)), [&a, &b]);
        // Quoted values (RFC 6265 cookie-value) and loose whitespace.
        let header = format!("aqua_did_hint=\"{b}\";aqua_did_hint={a}  ");
        assert_eq!(strs(&hints_from_cookie_header(&header)), [&b, &a]);
    }

    #[test]
    fn parse_drops_malformed_and_non_p256_values() {
        let good = did(46);
        let header = format!(
            "aqua_did_hint=garbage; \
             aqua_did_hint=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK; \
             aqua_did_hint=did:pkh:eip155:1:0x0000000000000000000000000000000000000000; \
             aqua_did_hint=; aqua_did_hint; =x; ; \
             aqua_did_hint_x={good}; Aqua_Did_Hint={good}; x_aqua_did_hint={good}; \
             aqua_did_hint={good}"
        );
        assert_eq!(strs(&hints_from_cookie_header(&header)), [&good]);
        assert!(hints_from_cookie_header("").is_empty());
    }

    #[test]
    fn clear_cookie_sets_max_age_0() {
        assert_eq!(
            hint_clear_cookie(&HintCookieConfig::for_rp_id("inblock.io")),
            "aqua_did_hint=; Domain=inblock.io; Path=/; Max-Age=0; Secure; SameSite=Lax"
        );
        assert_eq!(
            hint_clear_cookie(&HintCookieConfig::for_rp_id("localhost")),
            "aqua_did_hint=; Path=/; Max-Age=0; Secure; SameSite=Lax"
        );
    }
}
