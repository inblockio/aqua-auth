//! Relying-party policy for store-free passkey assertions.
//!
//! An [`AssertionPolicy`] answers the two questions a verifier must settle
//! before it looks at a signature: was this assertion made for an RP ID we
//! serve (by its `rpIdHash`), and was it made on a page whose origin we list
//! for that RP ID. It holds no credentials: the store-free login path recovers
//! the public key from the assertion itself.
//!
//! # RP IDs
//!
//! A bare, lowercase ASCII domain with at least two labels: no scheme, port,
//! path, user info, IP literal or wildcard. `localhost` is the one single-label
//! RP ID accepted (local test harnesses).
//!
//! # Origins
//!
//! Exact strings in the browser's `clientDataJSON.origin` form
//! (`scheme://host[:port]`, lowercase host, default port omitted, no trailing
//! slash); configured spellings are normalised to it once, here. Each origin's
//! host must equal the RP ID or be a subdomain of it on a label boundary
//! (`evilinblock.io` is not within `inblock.io`). `https` only, except `http`
//! on `localhost` and `*.localhost`.
//!
//! One origin may sit under several RP IDs (a host within both a shared RP ID
//! and its own legacy RP ID). Selection is by `rpIdHash` first; the origin must
//! then be listed under that entry.

use sha2::{Digest, Sha256};
use url::Url;

/// Why a policy could not be built. Configuration errors: they surface at
/// startup, never per request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The RP ID is not a bare domain (see the module docs).
    #[error("invalid WebAuthn RP ID {rp_id:?}: {reason}")]
    InvalidRpId { rp_id: String, reason: &'static str },
    /// The origin is not `scheme://host[:port]` with an allowed scheme.
    #[error("invalid WebAuthn origin {origin:?}: {reason}")]
    InvalidOrigin { origin: String, reason: String },
    /// The origin's host is neither the RP ID nor a subdomain of it.
    #[error("WebAuthn origin {origin} is not within RP ID {rp_id}")]
    OriginOutsideRpId { origin: String, rp_id: String },
    /// An RP ID was configured without any origin, so it could never verify.
    #[error("WebAuthn RP ID {rp_id} has no origins")]
    NoOrigins { rp_id: String },
    /// The same RP ID (after normalisation) was configured twice.
    #[error("WebAuthn RP ID {rp_id} is configured twice")]
    DuplicateRpId { rp_id: String },
    /// The policy lists no RP ID at all, so it would match nothing.
    #[error("a WebAuthn assertion policy needs at least one RP ID")]
    NoRp,
}

/// One relying party: its RP ID, the SHA-256 of that RP ID as it appears in
/// `authenticatorData`, and the origins allowed to assert for it.
///
/// Built only through [`AssertionPolicyBuilder::rp`], which normalises and
/// validates every field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpEntry {
    /// Normalised RP ID (lowercase, no trailing dot).
    pub rp_id: String,
    /// `SHA-256(rp_id)`, compared byte for byte with `authenticatorData[0..32]`.
    pub rp_id_hash: [u8; 32],
    /// Allowed origins in the browser's serialisation, deduplicated, in
    /// configuration order.
    pub origins: Vec<String>,
}

impl RpEntry {
    /// `origin` (as reported in `clientDataJSON`) is listed for this RP ID.
    /// Exact comparison: the configured side is already in the browser's form.
    pub fn allows_origin(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

/// The RP IDs and origins a store-free assertion may come from, plus whether
/// user verification is required. Build with [`AssertionPolicy::builder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionPolicy {
    entries: Vec<RpEntry>,
    require_uv: bool,
}

impl AssertionPolicy {
    /// Start a policy. User verification is required unless switched off.
    pub fn builder() -> AssertionPolicyBuilder {
        AssertionPolicyBuilder {
            entries: Vec::new(),
            require_uv: true,
        }
    }

    /// The entry whose `rp_id_hash` equals `h` (the first 32 bytes of
    /// `authenticatorData`), if this policy serves that RP ID.
    pub fn entry_for_rp_id_hash(&self, h: &[u8; 32]) -> Option<&RpEntry> {
        self.entries.iter().find(|e| &e.rp_id_hash == h)
    }

    /// Whether an assertion without the UV flag is refused.
    pub fn require_uv(&self) -> bool {
        self.require_uv
    }

    /// Every configured RP, in configuration order.
    pub fn entries(&self) -> &[RpEntry] {
        &self.entries
    }
}

/// Builder for [`AssertionPolicy`]; every RP is validated as it is added.
#[derive(Debug, Clone)]
pub struct AssertionPolicyBuilder {
    entries: Vec<RpEntry>,
    require_uv: bool,
}

impl AssertionPolicyBuilder {
    /// Add one RP ID with the origins allowed to assert for it. Origins are
    /// normalised to the browser's form and must sit within `rp_id`.
    pub fn rp(mut self, rp_id: &str, origins: &[&str]) -> Result<Self, PolicyError> {
        let rp_id = validate_rp_id(rp_id)?;
        if self.entries.iter().any(|e| e.rp_id == rp_id) {
            return Err(PolicyError::DuplicateRpId { rp_id });
        }
        if origins.is_empty() {
            return Err(PolicyError::NoOrigins { rp_id });
        }
        let mut normalised: Vec<String> = Vec::with_capacity(origins.len());
        for raw in origins {
            let (origin, host) = normalise_origin(raw)?;
            if !host_within_rp_id(&host, &rp_id) {
                return Err(PolicyError::OriginOutsideRpId { origin, rp_id });
            }
            if !normalised.contains(&origin) {
                normalised.push(origin);
            }
        }
        let rp_id_hash = Sha256::digest(rp_id.as_bytes()).into();
        self.entries.push(RpEntry {
            rp_id,
            rp_id_hash,
            origins: normalised,
        });
        Ok(self)
    }

    /// Require (the default) or waive the UV flag.
    pub fn require_uv(mut self, on: bool) -> Self {
        self.require_uv = on;
        self
    }

    /// Finish the policy; at least one RP is required.
    pub fn build(self) -> Result<AssertionPolicy, PolicyError> {
        if self.entries.is_empty() {
            return Err(PolicyError::NoRp);
        }
        Ok(AssertionPolicy {
            entries: self.entries,
            require_uv: self.require_uv,
        })
    }
}

/// A host is a plain ASCII hostname: letters, digits, `.` and `-` (an IDN
/// arrives here in its punycode form). Refuses wildcards, IPv6 brackets,
/// user info and anything else a domain cannot contain.
fn is_plain_hostname(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// `host` equals `rp_id` or is a subdomain of it on a label boundary.
fn host_within_rp_id(host: &str, rp_id: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

/// Validate and normalise an RP ID (see the module docs).
fn validate_rp_id(raw: &str) -> Result<String, PolicyError> {
    let invalid = |reason| PolicyError::InvalidRpId {
        rp_id: raw.to_string(),
        reason,
    };
    let r = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !is_plain_hostname(&r) {
        return Err(invalid(
            "must be a bare ASCII domain (no scheme, port, path, user info or wildcard)",
        ));
    }
    if r.starts_with('.') || r.split('.').any(|label| label.is_empty()) {
        return Err(invalid("empty DNS label"));
    }
    if r.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid("IP literals are not allowed"));
    }
    if !r.contains('.') && r != "localhost" {
        return Err(invalid(
            "single-label RP IDs other than localhost are refused",
        ));
    }
    Ok(r)
}

/// Normalise one configured origin to the browser's serialisation and return
/// it with its lowercase host.
fn normalise_origin(raw: &str) -> Result<(String, String), PolicyError> {
    let invalid = |reason: String| PolicyError::InvalidOrigin {
        origin: raw.to_string(),
        reason,
    };
    let trimmed = raw.trim().trim_end_matches('/');
    let url = Url::parse(trimmed).map_err(|e| invalid(e.to_string()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("user info is not part of an origin".into()));
    }
    if !(url.path().is_empty() || url.path() == "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("must be scheme://host[:port] only".into()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid("no host".into()))?
        .to_ascii_lowercase();
    // `Url` accepts `*` in a domain, so this check is not redundant.
    if !is_plain_hostname(&host) {
        return Err(invalid(
            "host must be a plain hostname (no wildcards or IP literals in brackets)".into(),
        ));
    }
    let local = host == "localhost" || host.ends_with(".localhost");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        other => {
            return Err(invalid(format!(
                "scheme {other} not allowed (https, or http on localhost)"
            )))
        }
    }
    // The browser reports an origin without a trailing slash and without the
    // scheme's default port; `Origin::ascii_serialization` gives exactly that.
    Ok((url.origin().ascii_serialization(), host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash(s: &str) -> [u8; 32] {
        Sha256::digest(s.as_bytes()).into()
    }

    #[test]
    fn policy_refuses_origin_outside_its_rp() {
        for bad in [
            "https://evilinblock.io",      // suffix without a label boundary
            "https://inblock.io.evil.com", // RP ID as a left-hand label
            "https://evil.example.com",
        ] {
            let err = AssertionPolicy::builder()
                .rp("inblock.io", &[bad])
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused under inblock.io"));
            assert!(
                matches!(err, PolicyError::OriginOutsideRpId { .. }),
                "{bad}: {err}"
            );
        }
        // The RP ID itself and a subdomain sit within it.
        AssertionPolicy::builder()
            .rp(
                "inblock.io",
                &["https://inblock.io", "https://a.b.inblock.io"],
            )
            .expect("the RP host and its subdomains are within the RP ID");
    }

    #[test]
    fn policy_refuses_wildcards_paths_and_http_except_localhost() {
        for bad in [
            "https://*.inblock.io",
            "https://a.inblock.io/x",
            "https://a.inblock.io/?q=1",
            "https://a.inblock.io/#f",
            "https://user@a.inblock.io",
            "http://a.inblock.io",
            "ftp://a.inblock.io",
            "not an origin",
        ] {
            let err = AssertionPolicy::builder()
                .rp("inblock.io", &[bad])
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert!(
                matches!(err, PolicyError::InvalidOrigin { .. }),
                "{bad}: {err}"
            );
        }
        // http is allowed on the localhost family only (local test harnesses).
        let p = AssertionPolicy::builder()
            .rp("localhost", &["http://localhost:8765"])
            .unwrap()
            .rp(
                "inblock.localhost",
                &["http://siwx.inblock.localhost:18200"],
            )
            .unwrap()
            .build()
            .unwrap();
        let e = p.entry_for_rp_id_hash(&hash("localhost")).unwrap();
        assert_eq!(e.origins, vec!["http://localhost:8765".to_string()]);
        assert!(e.allows_origin("http://localhost:8765"));
    }

    #[test]
    fn policy_refuses_ip_and_single_label_rp_ids_except_localhost() {
        for bad in [
            "127.0.0.1",
            "::1",
            "[::1]",
            "io",
            "",
            "*.inblock.io",
            "https://inblock.io",
            "inblock.io:443",
            "inblock.io/x",
            ".inblock.io",
            "a..inblock.io",
            "user@inblock.io",
            "in block.io",
            "inblöck.io",
        ] {
            let err = AssertionPolicy::builder()
                .rp(bad, &["https://inblock.io"])
                .err()
                .unwrap_or_else(|| panic!("RP ID {bad:?} must be refused"));
            assert!(
                matches!(err, PolicyError::InvalidRpId { .. }),
                "{bad:?}: {err}"
            );
        }
        AssertionPolicy::builder()
            .rp("localhost", &["http://localhost:3000"])
            .expect("localhost is the one single-label RP ID");
    }

    #[test]
    fn policy_normalises_case_and_trailing_slash_to_browser_origin_form() {
        let p = AssertionPolicy::builder()
            .rp(
                "InBlock.IO.",
                &[
                    "HTTPS://Siwx.InBlock.IO/",
                    "https://a.inblock.io:443",
                    "https://siwx.inblock.io", // duplicate after normalising
                ],
            )
            .unwrap()
            .build()
            .unwrap();
        let e = p.entry_for_rp_id_hash(&hash("inblock.io")).unwrap();
        assert_eq!(e.rp_id, "inblock.io");
        assert_eq!(e.rp_id_hash, hash("inblock.io"));
        assert_eq!(
            e.origins,
            vec![
                "https://siwx.inblock.io".to_string(),
                "https://a.inblock.io".to_string(),
            ]
        );
        // The comparison at verification time is exact, in the browser's form.
        assert!(e.allows_origin("https://siwx.inblock.io"));
        assert!(!e.allows_origin("https://siwx.inblock.io/"));
        assert!(!e.allows_origin("HTTPS://SIWX.INBLOCK.IO"));
        assert!(!e.allows_origin("https://a.inblock.io:443"));
    }

    #[test]
    fn policy_accepts_port_origins() {
        let p = AssertionPolicy::builder()
            .rp("inblock.io", &["https://aquafire.local.inblock.io:8443"])
            .unwrap()
            .build()
            .unwrap();
        let e = p.entry_for_rp_id_hash(&hash("inblock.io")).unwrap();
        assert_eq!(
            e.origins,
            vec!["https://aquafire.local.inblock.io:8443".to_string()]
        );
        assert!(e.allows_origin("https://aquafire.local.inblock.io:8443"));
        // A port is part of the origin: the same host on another port is not listed.
        assert!(!e.allows_origin("https://aquafire.local.inblock.io"));
        assert!(!e.allows_origin("https://aquafire.local.inblock.io:9443"));
    }

    #[test]
    fn policy_matches_rp_id_hash_only_for_configured_rps() {
        // One origin under two RPs (the shared RP and a legacy one): selection
        // is by rpIdHash, and each entry keeps its own origin list.
        let p = AssertionPolicy::builder()
            .rp(
                "inblock.io",
                &[
                    "https://siwx-oidc.inblock.io",
                    "https://aquafire.inblock.io",
                ],
            )
            .unwrap()
            .rp("siwx-oidc.inblock.io", &["https://siwx-oidc.inblock.io"])
            .unwrap()
            .build()
            .unwrap();
        let shared = p.entry_for_rp_id_hash(&hash("inblock.io")).unwrap();
        assert_eq!(shared.rp_id, "inblock.io");
        assert!(shared.allows_origin("https://aquafire.inblock.io"));
        let legacy = p
            .entry_for_rp_id_hash(&hash("siwx-oidc.inblock.io"))
            .unwrap();
        assert_eq!(legacy.rp_id, "siwx-oidc.inblock.io");
        assert!(legacy.allows_origin("https://siwx-oidc.inblock.io"));
        assert!(!legacy.allows_origin("https://aquafire.inblock.io"));
        assert_eq!(p.entries().len(), 2);

        // Anything else matches nothing, including a differently cased RP ID
        // (the hash is over the normalised RP ID only) and a parent domain.
        for other in ["evil.io", "INBLOCK.IO", "io", "aquafire.inblock.io"] {
            assert!(p.entry_for_rp_id_hash(&hash(other)).is_none(), "{other}");
        }
        assert!(p.entry_for_rp_id_hash(&[0u8; 32]).is_none());

        // A policy with no RP would match nothing, an RP with no origin could
        // never verify, and one RP twice would make selection ambiguous.
        assert_eq!(
            AssertionPolicy::builder().build().err(),
            Some(PolicyError::NoRp)
        );
        assert!(matches!(
            AssertionPolicy::builder().rp("inblock.io", &[]).err(),
            Some(PolicyError::NoOrigins { .. })
        ));
        assert!(matches!(
            AssertionPolicy::builder()
                .rp("inblock.io", &["https://a.inblock.io"])
                .unwrap()
                .rp("INBLOCK.io", &["https://b.inblock.io"])
                .err(),
            Some(PolicyError::DuplicateRpId { .. })
        ));
    }

    #[test]
    fn policy_require_uv_defaults_true() {
        let p = AssertionPolicy::builder()
            .rp("inblock.io", &["https://a.inblock.io"])
            .unwrap()
            .build()
            .unwrap();
        assert!(p.require_uv());
        let p = AssertionPolicy::builder()
            .require_uv(false)
            .rp("inblock.io", &["https://a.inblock.io"])
            .unwrap()
            .build()
            .unwrap();
        assert!(!p.require_uv());
    }
}
