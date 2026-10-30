# DOLOS ZAP medium findings review (October 30, 2026)

## Evidence and scope
The prior ZAP report raised medium alerts for **Absence of Anti-CSRF Tokens** on GET `/login` and GET `/trap/login`, and **CSP: style-src unsafe-inline** on several pages. See `evidence/ci-final/PR3/ZAP-DAST-report/zap.json` on the local machine; do not commit private scan artifacts by default.

## Analyst login: mitigated
Pre-authentication login now uses a 10-minute nonce cookie and an HMAC-SHA256 form token. The POST `/login` endpoint rejects missing, invalid, or expired tokens with HTTP 403. Authenticated state-changing endpoints retain their existing per-session CSRF check.

## Content Security Policy: mitigated
The inline DOLOS stylesheet is explicitly authorized by its SHA-256 hash, replacing `style-src 'unsafe-inline'`. The logout form's inline style attribute was replaced with a CSS class. Framing remains prohibited by `frame-ancestors 'none'` and `X-Frame-Options: DENY`.

## Decoy `/trap/login`: intentional exception
The honeypot intentionally accepts unauthenticated requests and does not issue an authenticated session or change analyst account settings. Requiring a CSRF token would prevent collection of unsolicited attempts. **Residual risk:** attackers can generate synthetic events, including cross-origin requests. Deployment should maintain request rate limits, storage limits, and monitoring appropriate to the exposure. This local lab binds its service to loopback.

## Verification
Run `make test` and `make security`. The added tests verify valid analyst logins, rejected forged logins, and the updated CSP. The HTTP probe suite reports **9/9** in the patched code. Re-run GitHub Actions/ZAP after this patch; actual new scanner results must be recorded and reviewed rather than assumed. For this single-process lab implementation, the HMAC key is generated on server startup; a multi-process deployment must share a durable, securely managed key.
