# Security Policy

Please report vulnerabilities privately by opening a GitHub security advisory or
emailing the repository maintainer.

Recommended production posture:

- Use strong HS256 secrets and rotate them with `kid`.
- Prefer RS256 with embedded JWKS for shared environments where Varnish should
  not hold signing secrets.
- Use 2048-bit or stronger RSA keys for RS256 and rotate by publishing both old
  and new public keys during rollout.
- The RustCrypto RSA advisory `RUSTSEC-2023-0071` is audit-ignored because this
  module uses only public-key signature verification, not private-key RSA
  operations.
- Prefer short-lived JWTs and validate `iss`, `aud`, `exp`, and `nbf`.
- Keep `mode` set to `enforce` for protected routes.
- Strip `Authorization` and API token headers before backend fetch unless the
  backend explicitly needs them.
- Treat this module as edge validation; VCL should still decide whether a route
  is cacheable, pass-only, or public.
