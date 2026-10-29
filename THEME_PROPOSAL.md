# DOLOS - Custom Theme Proposal (Instructor Approval Required)

**Course:** CYC386 Secure Software Design and Development, Fall 2026
**Working name:** DOLOS (Deception Operations and Log Observation System)
**Theme:** Local-first deception engineering, honeypot event observation and secure analyst workflow
**Team:** [TEAM MEMBER NAMES / GITHUB USERNAMES]
**Status:** PROPOSED - NOT YET APPROVED

DOLOS is a controlled, defensive cybersecurity platform that hosts a decoy login endpoint, records synthetic intrusion indicators, displays events to authenticated analysts, and lets authorized owners control decoy states. An admin can inspect global activity. The system never stores submitted decoy passwords and never touches university or third-party infrastructure. Architecture: Python 3.11+ standard-library HTTP/WSGI layer; SQLite parameterized data layer; PBKDF2-hashed analyst passwords; random opaque session tokens; role and object ownership checks; local-only intentionally vulnerable comparison server; isolated native C metadata parser lab. Docker deploys only secure code, listens on loopback at the host, and runs as an unprivileged user.

**Five mandatory vulnerabilities and fixes:** (1) C buffer overflow in synthetic event-tag parser -> bounded copy, ASan and compiler mitigation. (2) Shell injection in an event-indicator investigation command -> parameterized SQLite search with zero shell interpretation. (3) IDOR in cross-analyst event lookup -> per-object ownership check and 404 on unauthorized IDs. (4) CSRF in decoy toggle -> per-session unguessable synchronizer tokens and SameSite cookies. (5) Clickjacking in analyst/admin interface -> CSP `frame-ancestors 'none'` and X-Frame-Options DENY. The flawed examples are confined to loopback training mode; they are never exposed by the secured application or Docker image.

We will map all protection needs to CIA, create context and Level-1 DFDs, conduct STRIDE analysis, write two attack trees, justify CVSS v3.1 scores, maintain Jira traceability, and demonstrate fail-closed GitHub Actions security gates (Python tests, Bandit/SAST, ZAP/DAST, ASan, Trivy and Docker security). We request approval of the niche theme for its combination of deception operations and secure analyst workflows. Uniqueness must be confirmed by the instructor.
