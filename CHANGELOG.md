# Changelog

All notable changes to proxy-wasm-jwt-validator will be documented here.

## Unreleased

### Added
- RS256 JWT validation with embedded JWKS public keys.
- Unit and vmod-wasm integration coverage for RS256 bearer tokens.

## [0.1.0] - 2026-05-25

### Added
- Initial local HS256 JWT validator and opaque API token validator.
- JSON policy for keys, issuer, audience, leeway, required claims/scopes, and mode.
- Native unit tests and vmod-wasm VTC integration test.
