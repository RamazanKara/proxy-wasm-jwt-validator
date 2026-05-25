# proxy-wasm-jwt-validator

Proxy-Wasm request filter that validates JWT bearer tokens and opaque API
tokens locally at the edge.

It is designed for [vmod-wasm](https://github.com/RamazanKara/vmod-wasm), but
the module uses standard Proxy-Wasm request header operations where possible.

## What It Does

- Validates `Authorization: Bearer <jwt>` HS256 JWTs.
- Validates RS256 JWTs with an embedded JWKS.
- Validates opaque API tokens from `X-API-Token`.
- Checks `kid`, HMAC/RSA signature, `exp`, `nbf`, `iat`, issuer, audience,
  required scopes, and required exact claims.
- Emits trusted auth context as request headers for VCL/backend use.
- Strips raw token headers before backend fetch by default.
- Supports `enforce` and `report` mode.

JWKS keys are configured inline. The module does not fetch remote JWKS URLs from
inside Varnish workers.

## Varnish / vmod-wasm

```vcl
import wasm;

sub vcl_init {
    wasm.load("auth", "/etc/varnish/wasm/proxy_wasm_jwt_validator.wasm");
    wasm.set_epoch_deadline(100);
    wasm.set_memory_limit(8388608);
}

sub vcl_recv {
    set req.http.X-Wasm-Action =
        wasm.proxy_wasm_on_request_configured("auth", "",
            {"{"keys":[{"id":"test-key","secret":"topsecret" }],"jwks":{"keys":[{"kty":"RSA","kid":"rsa-key","alg":"RS256","use":"sig","n":"<base64url-modulus>","e":"AQAB" }]},"issuer":"https://issuer.example","audience":"edge","required_scopes":["read"],"mode":"enforce" }"});

    if (req.http.X-Wasm-Action != "0") {
        return (synth(401, "Unauthorized"));
    }
}
```

On success, the module emits:

- `X-Auth-Status: verified`
- `X-Auth-Token-Type: jwt|api-token`
- `X-Auth-Key-Id: <kid or api token id>`
- `X-Auth-Subject: <sub or configured API token subject>`
- `X-Auth-Issuer: <iss>` for JWTs
- `X-Auth-Scopes: <space-separated scopes>`

By default it removes `Authorization` and `X-API-Token` before backend fetch.

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `keys` | array | `[]` | HS256 JWT keys with `id`, `secret`, and optional `alg`. |
| `jwks` | object | `{"keys":[]}` | Embedded JWKS for RS256 keys. Each key needs `kty:"RSA"`, `kid`, `n`, `e`, and optional `alg:"RS256"` / `use:"sig"`. |
| `api_tokens` | array | `[]` | Opaque tokens with `id`, `token`, `subject`, and `scopes`. |
| `authorization_header` | string | `authorization` | Header containing a bearer JWT. |
| `api_key_header` | string | `x-api-token` | Header containing an opaque API token. |
| `issuer` | string/null | `null` | Required `iss`. |
| `audience` | string/null | `null` | Required `aud`, string or array. |
| `required_scopes` | array | `[]` | Required scopes from `scope` or `scp`. |
| `required_claims` | object | `{}` | Exact string/number/bool claim matches. |
| `leeway_seconds` | integer | `60` | Clock leeway for `exp`, `nbf`, and `iat`. |
| `mode` | string | `enforce` | `enforce` blocks failures; `report` annotates and allows. |
| `require_kid` | bool | `false` | Require JWT `kid`. |
| `emit_headers` | bool | `true` | Emit auth context headers. |
| `strip_token_headers` | bool | `true` | Remove raw credentials before backend fetch. |

### RS256 / JWKS

Configure public RSA keys under `jwks.keys`. The JWT header `alg` must be
`RS256`; `kid` selects the matching JWK. If `require_kid` is false and exactly
one RS256 key is configured, a JWT without `kid` can use that key.

Remote JWKS discovery and refresh are intentionally out of scope for this
module. Rotate keys by deploying updated plugin configuration with overlapping
old and new keys during the rollout window.

## Build

```bash
cargo build --release --target wasm32-unknown-unknown
```

Artifact:

```text
target/wasm32-unknown-unknown/release/proxy_wasm_jwt_validator.wasm
```

## Test

```bash
cargo fmt --all --check
cargo test --all
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown
```

Integration test against a sibling `vmod-wasm` checkout:

```bash
VMOD_WASM_REPO=../vmod-wasm ./scripts/test-vmod-wasm.sh
```
