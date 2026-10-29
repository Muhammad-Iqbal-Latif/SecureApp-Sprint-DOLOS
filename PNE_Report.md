# DOLOS: Protection Needs Elicitation and CIA Mapping

**Version:** 1.0 proposal baseline | **Classification:** controlled local test assets only

## 1. Stakeholders and elicitation method
- Analyst: must investigate only assigned incidents, protect investigation activity and maintain integrity of event findings.
- Administrator: must view global monitoring, control owned/authorized decoys, prevent unapproved configuration changes.
- Security operator: must keep decoy ingestion reliable, investigate pipeline failures, retain tamper-resistant evidence.
- External unauthenticated client (adversarial perspective): may submit untrusted input to decoy endpoints; cannot access real analyst data or private controls.
- Instructor/reviewer: needs reproducible, authorized attacks against synthetic data, explicit regression tests and complete traceability.

## 2. Asset inventory
| ID | Asset | Type | Sensitivity | Relevant CIA |
|---|---|---|---|---|
| A01 | Analyst account and password hashes | Data | High | C,I |
| A02 | Server-side session token hashes and CSRF tokens | Data | High | C,I |
| A03 | Synthetic event/indicator log | Data | Medium | C,I,A |
| A04 | Decoy enabled-state configuration | Data | High | I,A |
| A05 | Admin and analyst authorization decisions | Process | Critical | C,I |
| A06 | Local SQLite database | Component | High | C,I,A |
| A07 | Event investigation/search handler | Process | High | I,A |
| A08 | Native metadata parser (teaching lab only) | Component | Medium | I,A |
| A09 | GitHub Actions checks and retained evidence | Process | High | I,A |
| A10 | Docker runtime, secrets and local volume | Component | High | C,I,A |

## 3. Protection needs (PNE), measurable requirements, validation
| PNE | Need and stakeholder | CIA | Measurable security requirement | Test / evidence | Threat |
|---|---|---|---|---|---|
| PNE-01 | Analysts must not see other users' incidents | C,I | Every incident read includes the authenticated owner ID; admin role explicitly exceptioned | test_unauthorized_idor_rejected, 403/404 screenshot | T-IDOR |
| PNE-02 | Secure decoy configuration updates | I,A | Each authenticated POST requires an unpredictable valid session CSRF token | test_csrf_rejects_without_token | T-CSRF |
| PNE-03 | Untrusted event indicators cannot execute commands | I,A | No user-controlled value enters a shell; parameterized SQL search only | test_injection_string_is_only_data, AST gate | T-CMD |
| PNE-04 | Parser must not corrupt process memory | I,A | Reject event tags >=16 bytes; ASan clean on fixed implementation | ASan before/after, native/secure.c | T-BOF |
| PNE-05 | Sensitive pages must not be framed | I,C | CSP frame-ancestors 'none' AND X-Frame-Options DENY | test_health_and_security_headers and browser framing | T-FRAME |
| PNE-06 | Passwords and sessions must be protected | C,I | Salted PBKDF2 hashes; opaque random session tokens hashed in SQLite; HttpOnly cookie | test auth, inspect schema and headers | T-AUTH |
| PNE-07 | Detect decoy access with minimal personal data | C,I,A | Record only supplied username (<=96 chars), never supplied passwords | test_trap_records_only_identifier | T-LOG |
| PNE-08 | Enforce trusted code in deployment | I,A | CI rejects high/critical Bandit, ZAP and Trivy issues and synthetic gate test | Actions logs and gate screenshots | T-PIPE |
| PNE-09 | Resist basic browser injection | C,I | HTML-escape event values and set nosniff/CSP | test_xss_is_escaped | T-XSS |
| PNE-10 | Preserve access continuity locally | A | Health check responds 200 and container health check is configured | test_health_and_security_headers, docker inspect | T-DOS |

## 4. CIA goals and tradeoffs
- Confidentiality: owner-scoped incident retrieval; no decoy password retention; salted stored password hashes; sensitive session cookies HttpOnly.
- Integrity: CSRF synchronizer; check admin/owner before update; no shell interpolation; approved PRs and blocked critical scans.
- Availability: local health endpoint, bounded request sizes, Docker memory/pid limits; rate limiting and resilient ingestion are residual risks.

## 5. Known limits
Elicitation is based on expected stakeholder roles, not recorded interviews; replace these assumptions with actual stakeholder feedback if obtained. A local reference WSGI server and no TLS or central authentication means this prototype is not production-ready for internet exposure.
