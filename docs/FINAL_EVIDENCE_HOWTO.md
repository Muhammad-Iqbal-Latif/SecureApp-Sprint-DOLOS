# DOLOS final vulnerability verification

Run from the project root:

```bash
bash scripts/collect_remaining_evidence.sh
```

This runs the actual Python WSGI application on an ephemeral localhost HTTP port with a separate temporary SQLite database, tests secure handling of IDOR, command-injection probes, CSRF, clickjacking and XSS, and also runs the isolated intentionally vulnerable training service on `127.0.0.1:5001` for BEFORE proof. It also runs the native ASan test,  security severity gate and the Python unit suite. No real user passwords or database contents are touched.

Evidence is written to `evidence/final/` and existing `evidence/0*-*.txt`. Capture screenshots from your own successful output. The `401` in decoy demonstrations and sanitizer exit `134` are expected. The critical-finding policy gate must fail, while the clean one must pass. They must not be confused with actual scanner findings, which must be taken from GitHub Actions artifacts.

## Exact evidence pointers

| Jira | BEFORE | AFTER secure behavior |
|---|---|---|
| DLS-14 Command injection | `evidence/04-command-before.txt` | `evidence/final/03-secure-http-probes.txt`: shell marker not executed |
| DLS-15 IDOR | `evidence/03-idor-before.txt` | `evidence/final/03-secure-http-probes.txt`: 404 cross-user, 200 own |
| DLS-16 CSRF | `evidence/05-csrf-before.txt` | `evidence/final/03-secure-http-probes.txt`: 403 without token, 303 with valid token |
| DLS-17 Clickjacking | `evidence/06-framing-before.txt` and `/lab/frame-demo` browser screenshot | `evidence/final/03-secure-http-probes.txt`: `X-Frame-Options: DENY` and CSP |
| DLS-18 Additional XSS | vulnerable `<script>` stored as controlled test | `evidence/final/03-secure-http-probes.txt`: HTML escaping verified |

These tests demonstrate unsafe *training endpoints* versus safe *current implementation*; they do not prove DOLOS production previously contained these flaws. The pipeline has actual fail-on-high evidence through the previously failed Trivy run and the later passing run.

## Remaining manual requirements

- Ensure genuine teammate approval, merge latest PR, and record Jira issue links and individual contributions.
- Download Bandit, ZAP, ASan artifacts from passing GitHub Actions; inspect DAST alert count and severity.
- Launch Docker with `docker compose up -d --build` after stopping the local Python server on port 5000, verify health, runtime user and read-only root filesystem.
- Attach real screenshots and link PRs into Jira; request instructor approval for the custom DOLOS theme.
- Fill final report (18–30 pages), narrate demo video (6–10 minutes), submit via MS Teams and provide Jira access/export.
