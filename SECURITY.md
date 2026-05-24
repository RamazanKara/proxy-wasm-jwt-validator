# Security Policy

Please report vulnerabilities privately by opening a GitHub security advisory or
emailing the repository maintainer.

Recommended production posture:

- Use strong HS256 secrets and rotate them with `kid`.
- Prefer short-lived JWTs and validate `iss`, `aud`, `exp`, and `nbf`.
- Keep `mode` set to `enforce` for protected routes.
- Strip `Authorization` and API token headers before backend fetch unless the
  backend explicitly needs them.
- Treat this module as edge validation; VCL should still decide whether a route
  is cacheable, pass-only, or public.
