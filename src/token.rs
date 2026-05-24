use crate::config::{ApiToken, JwtKey, ValidatorConfig};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthContext {
    pub token_type: String,
    pub key_id: String,
    pub subject: String,
    pub issuer: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

pub fn extract_bearer(header: &str) -> Option<String> {
    let trimmed = header.trim();
    if trimmed.len() <= 7 {
        return None;
    }
    let (scheme, token) = trimmed.split_at(6);
    if scheme.eq_ignore_ascii_case("bearer") && token.starts_with(' ') {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

pub fn validate_jwt(
    token: &str,
    config: &ValidatorConfig,
    now_secs: u64,
) -> Result<AuthContext, String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(|| "malformed-jwt".to_string())?;
    let payload_b64 = parts.next().ok_or_else(|| "malformed-jwt".to_string())?;
    let signature_b64 = parts.next().ok_or_else(|| "malformed-jwt".to_string())?;
    if parts.next().is_some() {
        return Err("malformed-jwt".to_string());
    }

    let header_bytes = decode_segment(header_b64)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| "invalid-jwt-header".to_string())?;
    if header.alg != "HS256" {
        return Err("unsupported-alg".to_string());
    }

    let key = select_jwt_key(config, header.kid.as_deref())?;
    if key.alg != header.alg {
        return Err("key-alg-mismatch".to_string());
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = decode_segment(signature_b64)?;
    verify_hs256(key.secret.as_bytes(), signing_input.as_bytes(), &signature)?;

    let payload_bytes = decode_segment(payload_b64)?;
    let claims: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "invalid-jwt-claims".to_string())?;
    validate_claims(&claims, config, now_secs)?;

    Ok(AuthContext {
        token_type: "jwt".to_string(),
        key_id: key.id.clone(),
        subject: claim_string(&claims, "sub").unwrap_or_default(),
        issuer: claim_string(&claims, "iss").unwrap_or_default(),
        scopes: claim_scopes(&claims),
    })
}

pub fn validate_api_token(token: &str, config: &ValidatorConfig) -> Result<AuthContext, String> {
    let token = token.trim();
    for candidate in &config.api_tokens {
        if constant_time_eq(token.as_bytes(), candidate.token.as_bytes()) {
            return Ok(api_context(candidate));
        }
    }
    Err("invalid-api-token".to_string())
}

fn api_context(token: &ApiToken) -> AuthContext {
    AuthContext {
        token_type: "api-token".to_string(),
        key_id: token.id.clone(),
        subject: token.subject.clone(),
        issuer: String::new(),
        scopes: token.scopes.clone(),
    }
}

fn select_jwt_key<'a>(
    config: &'a ValidatorConfig,
    kid: Option<&str>,
) -> Result<&'a JwtKey, String> {
    if let Some(kid) = kid {
        return config
            .keys
            .iter()
            .find(|key| key.id == kid)
            .ok_or_else(|| "unknown-kid".to_string());
    }

    if config.require_kid {
        return Err("missing-kid".to_string());
    }

    match config.keys.as_slice() {
        [key] => Ok(key),
        [] => Err("no-jwt-keys-configured".to_string()),
        _ => Err("missing-kid".to_string()),
    }
}

fn validate_claims(claims: &Value, config: &ValidatorConfig, now_secs: u64) -> Result<(), String> {
    if let Some(exp) = claim_u64(claims, "exp") {
        if now_secs > exp.saturating_add(config.leeway_seconds) {
            return Err("token-expired".to_string());
        }
    }

    if let Some(nbf) = claim_u64(claims, "nbf") {
        if now_secs.saturating_add(config.leeway_seconds) < nbf {
            return Err("token-not-yet-valid".to_string());
        }
    }

    if let Some(iat) = claim_u64(claims, "iat") {
        if now_secs.saturating_add(config.leeway_seconds) < iat {
            return Err("token-issued-in-future".to_string());
        }
    }

    if let Some(expected) = config.issuer.as_deref() {
        if claim_string(claims, "iss").as_deref() != Some(expected) {
            return Err("issuer-mismatch".to_string());
        }
    }

    if let Some(expected) = config.audience.as_deref() {
        if !audience_matches(claims, expected) {
            return Err("audience-mismatch".to_string());
        }
    }

    for (name, expected) in &config.required_claims {
        if claim_value_as_string(claims.get(name)).as_deref() != Some(expected.as_str()) {
            return Err(format!("required-claim-mismatch:{name}"));
        }
    }

    let scopes = claim_scopes(claims);
    for required in &config.required_scopes {
        if !scopes.iter().any(|scope| scope == required) {
            return Err(format!("missing-scope:{required}"));
        }
    }

    Ok(())
}

fn verify_hs256(secret: &[u8], signing_input: &[u8], signature: &[u8]) -> Result<(), String> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input);
    mac.verify_slice(signature)
        .map_err(|_| "invalid-jwt-signature".to_string())
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| "invalid-base64url".to_string())
}

fn claim_string(claims: &Value, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_string)
}

fn claim_u64(claims: &Value, name: &str) -> Option<u64> {
    claims.get(name).and_then(Value::as_u64)
}

fn audience_matches(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn claim_scopes(claims: &Value) -> Vec<String> {
    let mut scopes = Vec::new();
    if let Some(scope) = claims.get("scope").and_then(Value::as_str) {
        scopes.extend(scope.split_whitespace().map(str::to_string));
    }
    if let Some(Value::Array(values)) = claims.get("scp") {
        scopes.extend(values.iter().filter_map(Value::as_str).map(str::to_string));
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn claim_value_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for i in 0..max_len {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        diff |= (l ^ r) as usize;
    }
    diff == 0
}

#[cfg(test)]
pub fn sign_hs256(header_json: &str, claims_json: &str, secret: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    let signing_input = format!("{header}.{claims}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiToken, JwtKey};

    fn config() -> ValidatorConfig {
        ValidatorConfig {
            keys: vec![JwtKey {
                id: "test-key".to_string(),
                secret: "topsecret".to_string(),
                alg: "HS256".to_string(),
            }],
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("edge".to_string()),
            required_scopes: vec!["read".to_string()],
            ..ValidatorConfig::default()
        }
    }

    #[test]
    fn extracts_bearer_case_insensitively() {
        assert_eq!(extract_bearer("Bearer abc.def").as_deref(), Some("abc.def"));
        assert_eq!(extract_bearer("bearer token").as_deref(), Some("token"));
        assert!(extract_bearer("Basic token").is_none());
    }

    #[test]
    fn validates_hs256_jwt() {
        let token = sign_hs256(
            r#"{"alg":"HS256","kid":"test-key","typ":"JWT"}"#,
            r#"{"iss":"https://issuer.example","aud":"edge","sub":"user-123","exp":4102444800,"nbf":1700000000,"scope":"read write","tier":"gold"}"#,
            b"topsecret",
        );
        let context = validate_jwt(&token, &config(), 1779660000).unwrap();
        assert_eq!(context.subject, "user-123");
        assert_eq!(context.key_id, "test-key");
        assert_eq!(context.scopes, vec!["read", "write"]);
    }

    #[test]
    fn rejects_bad_signature() {
        let token = sign_hs256(
            r#"{"alg":"HS256","kid":"test-key"}"#,
            r#"{"iss":"https://issuer.example","aud":"edge","sub":"user-123","exp":4102444800,"scope":"read"}"#,
            b"wrong",
        );
        assert_eq!(
            validate_jwt(&token, &config(), 1779660000).unwrap_err(),
            "invalid-jwt-signature"
        );
    }

    #[test]
    fn rejects_missing_scope() {
        let token = sign_hs256(
            r#"{"alg":"HS256","kid":"test-key"}"#,
            r#"{"iss":"https://issuer.example","aud":"edge","sub":"user-123","exp":4102444800,"scope":"write"}"#,
            b"topsecret",
        );
        assert_eq!(
            validate_jwt(&token, &config(), 1779660000).unwrap_err(),
            "missing-scope:read"
        );
    }

    #[test]
    fn validates_opaque_api_token() {
        let config = ValidatorConfig {
            api_tokens: vec![ApiToken {
                id: "internal".to_string(),
                token: "opaque-secret".to_string(),
                subject: "service-a".to_string(),
                scopes: vec!["read".to_string()],
            }],
            ..ValidatorConfig::default()
        };
        let context = validate_api_token("opaque-secret", &config).unwrap();
        assert_eq!(context.token_type, "api-token");
        assert_eq!(context.subject, "service-a");
        assert_eq!(
            validate_api_token("opaque-secret!", &config).unwrap_err(),
            "invalid-api-token"
        );
    }
}
