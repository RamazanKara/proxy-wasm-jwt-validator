use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct JwtKey {
    pub id: String,
    pub secret: String,
    #[serde(default = "default_alg")]
    pub alg: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Jwks {
    #[serde(default)]
    pub keys: Vec<JwkKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ApiToken {
    pub id: String,
    pub token: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ValidatorConfig {
    #[serde(default)]
    pub keys: Vec<JwtKey>,
    #[serde(default)]
    pub jwks: Jwks,
    #[serde(default)]
    pub api_tokens: Vec<ApiToken>,
    #[serde(default = "default_authorization_header")]
    pub authorization_header: String,
    #[serde(default = "default_api_key_header")]
    pub api_key_header: String,
    #[serde(default = "default_status_header")]
    pub status_header: String,
    #[serde(default = "default_subject_header")]
    pub subject_header: String,
    #[serde(default = "default_issuer_header")]
    pub issuer_header: String,
    #[serde(default = "default_scopes_header")]
    pub scopes_header: String,
    #[serde(default = "default_token_type_header")]
    pub token_type_header: String,
    #[serde(default = "default_key_id_header")]
    pub key_id_header: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
    #[serde(default = "default_leeway_seconds")]
    pub leeway_seconds: u64,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub require_kid: bool,
    #[serde(default = "default_true")]
    pub emit_headers: bool,
    #[serde(default = "default_true")]
    pub strip_token_headers: bool,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            jwks: Jwks::default(),
            api_tokens: Vec::new(),
            authorization_header: default_authorization_header(),
            api_key_header: default_api_key_header(),
            status_header: default_status_header(),
            subject_header: default_subject_header(),
            issuer_header: default_issuer_header(),
            scopes_header: default_scopes_header(),
            token_type_header: default_token_type_header(),
            key_id_header: default_key_id_header(),
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            required_claims: BTreeMap::new(),
            leeway_seconds: default_leeway_seconds(),
            mode: default_mode(),
            require_kid: false,
            emit_headers: true,
            strip_token_headers: true,
        }
    }
}

impl ValidatorConfig {
    pub fn is_report_mode(&self) -> bool {
        self.mode.eq_ignore_ascii_case("report")
    }
}

pub fn parse_config(data: &[u8]) -> Result<ValidatorConfig, String> {
    if data.is_empty() {
        return Ok(ValidatorConfig::default());
    }

    let config: ValidatorConfig =
        serde_json_wasm::from_slice(data).map_err(|err| format!("invalid-config: {err}"))?;

    if config.mode != "enforce" && config.mode != "report" {
        return Err("invalid-config: mode must be enforce or report".to_string());
    }

    for key in &config.keys {
        if key.alg != "HS256" {
            return Err(
                "invalid-config: keys support HS256 only; use jwks.keys for RS256".to_string(),
            );
        }
        if key.id.is_empty() || key.secret.is_empty() {
            return Err("invalid-config: HS256 keys require non-empty id and secret".to_string());
        }
    }

    for key in &config.jwks.keys {
        if key.kty != "RSA" {
            return Err("invalid-config: jwks.keys only supports RSA keys".to_string());
        }
        if let Some(alg) = key.alg.as_deref() {
            if alg != "RS256" {
                return Err("invalid-config: jwks.keys only supports RS256".to_string());
            }
        }
        if let Some(key_use) = key.key_use.as_deref() {
            if key_use != "sig" {
                return Err("invalid-config: jwks.keys use must be sig".to_string());
            }
        }
        if key.kid.as_deref().unwrap_or("").is_empty() || key.n.is_empty() || key.e.is_empty() {
            return Err("invalid-config: RS256 JWKs require kid, n, and e".to_string());
        }
    }

    Ok(config)
}

fn default_alg() -> String {
    "HS256".to_string()
}

fn default_authorization_header() -> String {
    "authorization".to_string()
}

fn default_api_key_header() -> String {
    "x-api-token".to_string()
}

fn default_status_header() -> String {
    "x-auth-status".to_string()
}

fn default_subject_header() -> String {
    "x-auth-subject".to_string()
}

fn default_issuer_header() -> String {
    "x-auth-issuer".to_string()
}

fn default_scopes_header() -> String {
    "x-auth-scopes".to_string()
}

fn default_token_type_header() -> String {
    "x-auth-token-type".to_string()
}

fn default_key_id_header() -> String {
    "x-auth-key-id".to_string()
}

fn default_leeway_seconds() -> u64 {
    60
}

fn default_mode() -> String {
    "enforce".to_string()
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_enforcing() {
        let config = ValidatorConfig::default();
        assert_eq!(config.mode, "enforce");
        assert_eq!(config.authorization_header, "authorization");
        assert_eq!(config.api_key_header, "x-api-token");
        assert_eq!(config.leeway_seconds, 60);
        assert!(config.emit_headers);
        assert!(config.strip_token_headers);
    }

    #[test]
    fn parses_full_config() {
        let json = br#"{
            "keys":[{"id":"primary","secret":"topsecret"}],
            "jwks":{"keys":[{"kty":"RSA","kid":"rsa","alg":"RS256","use":"sig","n":"abc","e":"AQAB"}]},
            "api_tokens":[{"id":"svc","token":"opaque","subject":"service-a","scopes":["read"]}],
            "issuer":"https://issuer.example",
            "audience":"edge",
            "required_scopes":["read"],
            "required_claims":{"tier":"gold"},
            "mode":"report",
            "require_kid":true
        }"#;
        let config = parse_config(json).unwrap();
        assert!(config.is_report_mode());
        assert!(config.require_kid);
        assert_eq!(config.keys[0].alg, "HS256");
        assert_eq!(config.jwks.keys[0].kid.as_deref(), Some("rsa"));
        assert_eq!(config.api_tokens[0].subject, "service-a");
        assert_eq!(config.required_claims.get("tier").unwrap(), "gold");
    }

    #[test]
    fn rejects_unsupported_alg() {
        let err =
            parse_config(br#"{"keys":[{"id":"rsa","secret":"x","alg":"RS256"}]}"#).unwrap_err();
        assert!(err.contains("HS256"));
    }

    #[test]
    fn rejects_unsupported_jwk_alg() {
        let err = parse_config(
            br#"{"jwks":{"keys":[{"kty":"RSA","kid":"rsa","alg":"RS384","n":"abc","e":"AQAB"}]}}"#,
        )
        .unwrap_err();
        assert!(err.contains("RS256"));
    }
}
