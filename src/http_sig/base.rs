//! Signature base construction, RFC 9421 section 2.5.
//!
//! The signature base is the exact byte string that gets signed. Its ABNF
//! (section 2.5) is:
//!
//! ```text
//! signature-base       = *( signature-base-line LF ) signature-params-line
//! signature-base-line  = component-identifier ":" SP
//!                        ( derived-component-value / *field-content )
//! signature-params-line = DQUOTE "@signature-params" DQUOTE ":" SP inner-list
//! ```
//!
//! Two consequences that are easy to get wrong and are therefore pinned by
//! exact-string tests below: every covered-component line is followed by a
//! newline, and the trailing `@signature-params` line is **not**.

use super::{HttpSigError, RequestParts};

/// `@authority`, the only mandatory covered component in this profile.
pub(crate) const COMPONENT_AUTHORITY: &str = "@authority";

/// `signature-agent`, covered whenever the request carries the header.
pub(crate) const COMPONENT_SIGNATURE_AGENT: &str = "signature-agent";

/// The fixed trailing component name (RFC 9421 section 2.3).
pub(crate) const COMPONENT_SIGNATURE_PARAMS: &str = "@signature-params";

/// The covered components this profile allows, in canonical order.
pub(crate) const ALLOWED_COMPONENTS: [&str; 2] = [COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT];

/// Signature parameter names, in the canonical order this profile emits and
/// requires. RFC 9421 lets an implementation pick any order but forbids
/// changing it once picked, so it is fixed here.
pub(crate) const PARAM_ORDER: [&str; 6] = ["created", "expires", "keyid", "alg", "nonce", "tag"];

/// The signature metadata shared by signing and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignatureParams {
    /// Covered component names, in signing order. Entries come from
    /// [`ALLOWED_COMPONENTS`].
    pub covered: Vec<&'static str>,
    /// `created`, UNIX seconds.
    pub created: i64,
    /// `expires`, UNIX seconds.
    pub expires: i64,
    /// `keyid`: a DID under the internal profile, a JWK thumbprint under
    /// web-bot-auth.
    pub keyid: String,
    /// `alg`, an RFC 9421 algorithm name.
    pub alg: String,
    /// `nonce`, base64url without padding.
    pub nonce: String,
    /// `tag`, the application identifier.
    pub tag: String,
}

/// The covered components for a request: `@authority` always, plus
/// `signature-agent` when the request carries that header.
pub(crate) fn covered_components(parts: &RequestParts<'_>) -> Vec<&'static str> {
    let mut covered = vec![COMPONENT_AUTHORITY];
    if parts.signature_agent.is_some() {
        covered.push(COMPONENT_SIGNATURE_AGENT);
    }
    covered
}

/// Derive `@authority` from a target URI (RFC 9421 section 2.2.3).
///
/// Normalised per RFC 9110 section 4.2.3: the host is lowercased and the
/// scheme's default port is omitted. Userinfo is stripped, since it is not
/// part of the authority an HTTP server sees and http(s) URIs deprecate it.
pub(crate) fn authority_from_uri(target_uri: &str) -> Result<String, HttpSigError> {
    let (scheme, rest) = target_uri
        .split_once("://")
        .ok_or_else(|| HttpSigError::InvalidTargetUri(target_uri.to_string()))?;

    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80u16,
        "https" => 443u16,
        _ => return Err(HttpSigError::UnsupportedScheme(scheme)),
    };

    // The authority runs to the first path, query, or fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host_port)) => host_port,
        None => authority,
    };
    if authority.is_empty() {
        return Err(HttpSigError::InvalidTargetUri(target_uri.to_string()));
    }

    // IPv6 literals are bracketed, and those brackets contain colons, so the
    // host/port split has to happen after the closing bracket.
    let (host, port) =
        match authority.rfind(']') {
            Some(close) if authority.starts_with('[') => {
                let host = &authority[..=close];
                match &authority[close + 1..] {
                    "" => (host, None),
                    tail => (
                        host,
                        Some(tail.strip_prefix(':').ok_or_else(|| {
                            HttpSigError::InvalidTargetUri(target_uri.to_string())
                        })?),
                    ),
                }
            }
            Some(_) => return Err(HttpSigError::InvalidTargetUri(target_uri.to_string())),
            None => match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };

    let host = host.to_ascii_lowercase();
    if host.is_empty() || host == "[]" {
        return Err(HttpSigError::InvalidTargetUri(target_uri.to_string()));
    }

    match port {
        None => Ok(host),
        Some(port) => {
            let port: u16 = port
                .parse()
                .map_err(|_| HttpSigError::InvalidTargetUri(target_uri.to_string()))?;
            if port == default_port {
                Ok(host)
            } else {
                Ok(format!("{host}:{port}"))
            }
        }
    }
}

/// The canonicalized value of one covered component for this request.
///
/// Field values are canonicalized per RFC 9421 section 2.1: leading and
/// trailing whitespace is stripped, and a value carrying a bare CR or LF is
/// rejected rather than folded, since that would let a header value inject
/// extra signature base lines.
pub(crate) fn component_value(
    name: &str,
    parts: &RequestParts<'_>,
) -> Result<String, HttpSigError> {
    match name {
        COMPONENT_AUTHORITY => authority_from_uri(parts.target_uri),
        COMPONENT_SIGNATURE_AGENT => {
            let raw = parts
                .signature_agent
                .ok_or_else(|| HttpSigError::MissingComponent(name.to_string()))?;
            let value = raw.trim();
            if value.is_empty() {
                return Err(HttpSigError::MissingComponent(name.to_string()));
            }
            if value.contains(['\r', '\n']) {
                return Err(HttpSigError::InvalidComponentValue {
                    name: name.to_string(),
                    reason: "value contains a line break".to_string(),
                });
            }
            Ok(value.to_string())
        }
        other => Err(HttpSigError::UnsupportedComponent(other.to_string())),
    }
}

fn sf_key(name: &str) -> Result<&sfv::KeyRef, HttpSigError> {
    Ok(sfv::KeyRef::from_str(name)?)
}

fn sf_string(value: &str) -> Result<&sfv::StringRef, HttpSigError> {
    Ok(sfv::StringRef::from_str(value)?)
}

fn sf_integer(value: i64) -> Result<sfv::Integer, HttpSigError> {
    sfv::Integer::try_from(value)
        .map_err(|e| HttpSigError::StructuredField(format!("{value} is not a valid integer: {e}")))
}

/// Write the parameterized inner list shared by the `@signature-params` line
/// and the `Signature-Input` header value.
fn write_params_inner_list(
    mut inner: sfv::InnerListSerializer<'_>,
    params: &SignatureParams,
) -> Result<(), HttpSigError> {
    for name in &params.covered {
        let _ = inner.bare_item(sf_string(name)?);
    }
    let _ = inner
        .finish()
        .parameter(sf_key("created")?, sf_integer(params.created)?)
        .parameter(sf_key("expires")?, sf_integer(params.expires)?)
        .parameter(sf_key("keyid")?, sf_string(&params.keyid)?)
        .parameter(sf_key("alg")?, sf_string(&params.alg)?)
        .parameter(sf_key("nonce")?, sf_string(&params.nonce)?)
        .parameter(sf_key("tag")?, sf_string(&params.tag)?)
        .finish();
    Ok(())
}

/// The `@signature-params` component value: a parameterized inner list.
pub(crate) fn serialize_signature_params(params: &SignatureParams) -> Result<String, HttpSigError> {
    let mut ser = sfv::ListSerializer::new();
    write_params_inner_list(ser.inner_list(), params)?;
    ser.finish()
        .ok_or_else(|| HttpSigError::StructuredField("empty signature parameters".to_string()))
}

/// The `Signature-Input` header value: a one-member dictionary whose value is
/// the same parameterized inner list, keyed by the signature label.
pub(crate) fn signature_input_header(
    label: &str,
    params: &SignatureParams,
) -> Result<String, HttpSigError> {
    let mut ser = sfv::DictSerializer::new();
    write_params_inner_list(ser.inner_list(sf_key(label)?), params)?;
    ser.finish()
        .ok_or_else(|| HttpSigError::StructuredField("empty Signature-Input".to_string()))
}

/// The `Signature` header value: a one-member dictionary whose value is the
/// raw signature as an RFC 8941 byte sequence.
pub(crate) fn signature_header(label: &str, signature: &[u8]) -> Result<String, HttpSigError> {
    let mut ser = sfv::DictSerializer::new();
    let _ = ser.bare_item(sf_key(label)?, signature);
    ser.finish()
        .ok_or_else(|| HttpSigError::StructuredField("empty Signature".to_string()))
}

/// Build the signature base for a request (RFC 9421 section 2.5).
pub(crate) fn build_signature_base(
    parts: &RequestParts<'_>,
    params: &SignatureParams,
) -> Result<String, HttpSigError> {
    let mut out = String::new();
    let mut seen: Vec<&str> = Vec::with_capacity(params.covered.len());

    for name in &params.covered {
        if !ALLOWED_COMPONENTS.contains(name) {
            return Err(HttpSigError::UnsupportedComponent((*name).to_string()));
        }
        if seen.contains(name) {
            return Err(HttpSigError::DuplicateComponent((*name).to_string()));
        }
        seen.push(name);

        // Component names in this profile come from ALLOWED_COMPONENTS, which
        // holds no quote or backslash, so the sf-string serialization of a
        // name is exactly the name wrapped in double quotes.
        out.push('"');
        out.push_str(name);
        out.push_str("\": ");
        out.push_str(&component_value(name, parts)?);
        out.push('\n');
    }

    if !seen.contains(&COMPONENT_AUTHORITY) {
        return Err(HttpSigError::MissingComponent(
            COMPONENT_AUTHORITY.to_string(),
        ));
    }

    out.push('"');
    out.push_str(COMPONENT_SIGNATURE_PARAMS);
    out.push_str("\": ");
    out.push_str(&serialize_signature_params(params)?);

    if !out.is_ascii() {
        return Err(HttpSigError::NonAsciiBase);
    }
    Ok(out)
}

/// Reject a request that carries a `Signature-Agent` header the signature does
/// not cover.
///
/// Without this check an attacker could strip `signature-agent` from the
/// covered set and still have the header ride along unsigned, which is a
/// silent downgrade rather than a failure.
pub(crate) fn check_signature_agent_coverage(
    parts: &RequestParts<'_>,
    covered: &[&'static str],
) -> Result<(), HttpSigError> {
    let present = parts.signature_agent.is_some();
    let is_covered = covered.contains(&COMPONENT_SIGNATURE_AGENT);
    match (present, is_covered) {
        (true, false) => Err(HttpSigError::MalformedSignatureInput(
            "request carries a Signature-Agent header that the signature does not cover"
                .to_string(),
        )),
        (false, true) => Err(HttpSigError::MissingComponent(
            COMPONENT_SIGNATURE_AGENT.to_string(),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(covered: Vec<&'static str>) -> SignatureParams {
        SignatureParams {
            covered,
            created: 1_618_884_473,
            expires: 1_618_884_773,
            keyid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            alg: "ed25519".to_string(),
            nonce: "e4ZQMcuRoxHtRnCPFdCMlBunbNbYSWTiZOGyzP7DGwc".to_string(),
            tag: "aqua-auth".to_string(),
        }
    }

    // ── exact signature base strings ────────────────────────────────────

    #[test]
    fn base_with_authority_only_is_exact() {
        let parts = RequestParts::new("GET", "https://node.example.com/v1/trees?limit=10");
        let base = build_signature_base(&parts, &params(vec![COMPONENT_AUTHORITY])).unwrap();

        assert_eq!(
            base,
            concat!(
                "\"@authority\": node.example.com\n",
                "\"@signature-params\": (\"@authority\")",
                ";created=1618884473",
                ";expires=1618884773",
                ";keyid=\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"",
                ";alg=\"ed25519\"",
                ";nonce=\"e4ZQMcuRoxHtRnCPFdCMlBunbNbYSWTiZOGyzP7DGwc\"",
                ";tag=\"aqua-auth\"",
            )
        );
    }

    #[test]
    fn base_with_signature_agent_is_exact() {
        let parts = RequestParts::new("POST", "https://node.example.com/v1/trees")
            .with_signature_agent("\"https://directory.example.com\"");
        let base = build_signature_base(
            &parts,
            &params(vec![COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT]),
        )
        .unwrap();

        assert_eq!(
            base,
            concat!(
                "\"@authority\": node.example.com\n",
                "\"signature-agent\": \"https://directory.example.com\"\n",
                "\"@signature-params\": (\"@authority\" \"signature-agent\")",
                ";created=1618884473",
                ";expires=1618884773",
                ";keyid=\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"",
                ";alg=\"ed25519\"",
                ";nonce=\"e4ZQMcuRoxHtRnCPFdCMlBunbNbYSWTiZOGyzP7DGwc\"",
                ";tag=\"aqua-auth\"",
            )
        );
    }

    #[test]
    fn base_has_no_trailing_newline() {
        let parts = RequestParts::new("GET", "https://example.com/");
        let base = build_signature_base(&parts, &params(vec![COMPONENT_AUTHORITY])).unwrap();
        assert!(!base.ends_with('\n'));
        // One newline per covered component, none after @signature-params.
        assert_eq!(base.matches('\n').count(), 1);
    }

    #[test]
    fn base_line_count_matches_covered_components() {
        let parts = RequestParts::new("GET", "https://example.com/")
            .with_signature_agent("\"https://d.example\"");
        let base = build_signature_base(
            &parts,
            &params(vec![COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT]),
        )
        .unwrap();
        assert_eq!(base.lines().count(), 3);
    }

    // ── @authority derivation ───────────────────────────────────────────

    #[test]
    fn authority_from_plain_https_uri() {
        assert_eq!(
            authority_from_uri("https://example.com/foo?bar=1#frag").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn authority_elides_default_https_port() {
        assert_eq!(
            authority_from_uri("https://example.com:443/foo").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn authority_elides_default_http_port() {
        assert_eq!(
            authority_from_uri("http://example.com:80/").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn authority_keeps_explicit_non_default_port() {
        assert_eq!(
            authority_from_uri("https://example.com:8443/foo").unwrap(),
            "example.com:8443"
        );
    }

    #[test]
    fn authority_port_defaults_are_per_scheme() {
        // 443 is not the default for http, so it must survive.
        assert_eq!(
            authority_from_uri("http://example.com:443/").unwrap(),
            "example.com:443"
        );
        // ... and 80 is not the default for https.
        assert_eq!(
            authority_from_uri("https://example.com:80/").unwrap(),
            "example.com:80"
        );
    }

    #[test]
    fn authority_lowercases_the_host() {
        assert_eq!(
            authority_from_uri("HTTPS://Node.EXAMPLE.CoM/Path").unwrap(),
            "node.example.com"
        );
    }

    #[test]
    fn authority_keeps_ipv6_brackets() {
        assert_eq!(
            authority_from_uri("https://[2001:db8::1]/foo").unwrap(),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn authority_ipv6_with_non_default_port() {
        assert_eq!(
            authority_from_uri("https://[2001:db8::1]:8443/foo").unwrap(),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn authority_ipv6_elides_default_port() {
        assert_eq!(
            authority_from_uri("https://[2001:DB8::1]:443/").unwrap(),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn authority_strips_userinfo() {
        assert_eq!(
            authority_from_uri("https://user:pass@example.com:8443/x").unwrap(),
            "example.com:8443"
        );
    }

    #[test]
    fn authority_with_no_path_still_parses() {
        assert_eq!(
            authority_from_uri("https://example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn authority_rejects_missing_scheme() {
        assert!(matches!(
            authority_from_uri("example.com/foo"),
            Err(HttpSigError::InvalidTargetUri(_))
        ));
    }

    #[test]
    fn authority_rejects_non_http_scheme() {
        assert!(matches!(
            authority_from_uri("ftp://example.com/"),
            Err(HttpSigError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn authority_rejects_empty_host() {
        assert!(matches!(
            authority_from_uri("https:///foo"),
            Err(HttpSigError::InvalidTargetUri(_))
        ));
    }

    #[test]
    fn authority_rejects_non_numeric_port() {
        assert!(matches!(
            authority_from_uri("https://example.com:notaport/"),
            Err(HttpSigError::InvalidTargetUri(_))
        ));
    }

    #[test]
    fn authority_rejects_unbracketed_ipv6() {
        assert!(matches!(
            authority_from_uri("https://2001:db8::1]/foo"),
            Err(HttpSigError::InvalidTargetUri(_))
        ));
    }

    // ── covered component selection and values ──────────────────────────

    #[test]
    fn covered_components_track_the_signature_agent_header() {
        let bare = RequestParts::new("GET", "https://example.com/");
        assert_eq!(covered_components(&bare), vec![COMPONENT_AUTHORITY]);

        let with_agent = bare.with_signature_agent("\"https://d.example\"");
        assert_eq!(
            covered_components(&with_agent),
            vec![COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT]
        );
    }

    #[test]
    fn signature_agent_value_is_trimmed() {
        let parts = RequestParts::new("GET", "https://example.com/")
            .with_signature_agent("  \"https://d.example\"  ");
        assert_eq!(
            component_value(COMPONENT_SIGNATURE_AGENT, &parts).unwrap(),
            "\"https://d.example\""
        );
    }

    #[test]
    fn signature_agent_value_rejects_line_breaks() {
        let parts = RequestParts::new("GET", "https://example.com/")
            .with_signature_agent("\"https://d.example\"\n\"@authority\": evil.example");
        assert!(matches!(
            component_value(COMPONENT_SIGNATURE_AGENT, &parts),
            Err(HttpSigError::InvalidComponentValue { .. })
        ));
    }

    #[test]
    fn missing_signature_agent_is_an_error_when_covered() {
        let parts = RequestParts::new("GET", "https://example.com/");
        assert!(matches!(
            component_value(COMPONENT_SIGNATURE_AGENT, &parts),
            Err(HttpSigError::MissingComponent(_))
        ));
    }

    #[test]
    fn unknown_component_is_rejected() {
        let parts = RequestParts::new("GET", "https://example.com/");
        assert!(matches!(
            component_value("@method", &parts),
            Err(HttpSigError::UnsupportedComponent(_))
        ));
    }

    #[test]
    fn base_rejects_duplicate_components() {
        let parts = RequestParts::new("GET", "https://example.com/");
        let err = build_signature_base(
            &parts,
            &params(vec![COMPONENT_AUTHORITY, COMPONENT_AUTHORITY]),
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::DuplicateComponent(_)));
    }

    #[test]
    fn base_requires_the_authority_component() {
        let parts = RequestParts::new("GET", "https://example.com/")
            .with_signature_agent("\"https://d.example\"");
        let err =
            build_signature_base(&parts, &params(vec![COMPONENT_SIGNATURE_AGENT])).unwrap_err();
        assert!(matches!(err, HttpSigError::MissingComponent(_)));
    }

    // ── header serialization ────────────────────────────────────────────

    #[test]
    fn signature_input_header_is_the_params_list_under_a_label() {
        let p = params(vec![COMPONENT_AUTHORITY]);
        let header = signature_input_header("sig1", &p).unwrap();
        let value = serialize_signature_params(&p).unwrap();
        assert_eq!(header, format!("sig1={value}"));
    }

    #[test]
    fn signature_header_wraps_bytes_as_a_byte_sequence() {
        // RFC 8941 byte sequences are standard base64 with padding, inside colons.
        assert_eq!(signature_header("sig1", &[0u8; 3]).unwrap(), "sig1=:AAAA:");
    }

    #[test]
    fn keyid_with_a_quote_is_escaped_not_injected() {
        let mut p = params(vec![COMPONENT_AUTHORITY]);
        p.keyid = "did:key:\"evil".to_string();
        let value = serialize_signature_params(&p).unwrap();
        assert!(value.contains("keyid=\"did:key:\\\"evil\""));
    }

    // ── Signature-Agent coverage consistency ────────────────────────────

    #[test]
    fn coverage_check_accepts_matching_shapes() {
        let bare = RequestParts::new("GET", "https://example.com/");
        assert!(check_signature_agent_coverage(&bare, &[COMPONENT_AUTHORITY]).is_ok());

        let with_agent = bare.with_signature_agent("\"https://d.example\"");
        assert!(check_signature_agent_coverage(
            &with_agent,
            &[COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT]
        )
        .is_ok());
    }

    #[test]
    fn coverage_check_rejects_an_uncovered_header() {
        let parts = RequestParts::new("GET", "https://example.com/")
            .with_signature_agent("\"https://d.example\"");
        assert!(matches!(
            check_signature_agent_coverage(&parts, &[COMPONENT_AUTHORITY]),
            Err(HttpSigError::MalformedSignatureInput(_))
        ));
    }

    #[test]
    fn coverage_check_rejects_a_covered_but_absent_header() {
        let parts = RequestParts::new("GET", "https://example.com/");
        assert!(matches!(
            check_signature_agent_coverage(
                &parts,
                &[COMPONENT_AUTHORITY, COMPONENT_SIGNATURE_AGENT]
            ),
            Err(HttpSigError::MissingComponent(_))
        ));
    }

    #[test]
    fn param_order_is_the_documented_one() {
        assert_eq!(
            PARAM_ORDER,
            ["created", "expires", "keyid", "alg", "nonce", "tag"]
        );
    }
}
