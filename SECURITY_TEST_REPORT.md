# DOLOS Security Testing Report (living record)

**Baseline status:** Local Python standard-library integration tests and custom security gate are designed to run without pip packages; CI Bandit, ZAP and Trivy require a GitHub runner or local installations. **Do not claim a scan passed without its output.**

| Stage | Tool | Command | Expected policy | Evidence status |
|---|---|---|---|---|
| Dynamic native | GCC AddressSanitizer | `bash scripts/verify_native.sh` | unsafe example should crash; safe example should reject | Capture locally; attached evidence after run |
| Integration | unittest | `make test` | all 12 tests pass, including native integration | Reproduce on Fedora |
| Static scanner baseline | Bandit | `bandit -r labs -f json -o evidence/bandit-before.json` | report intentionally vulnerable code; known unsafe training fixtures | Pending tool run |
| Static scanner secured | Bandit | `bandit -r dolos run.py -lll -i -f json -o evidence/bandit-after.json` | zero open HIGH findings | Pending tool run |
| AST security gate | custom Python scanner | `python scripts/sast_gate.py` | nonzero on `shell=True`, eval, pickle | Reproduce on Fedora |
| Synthetic severity policy | JSON gate | `python scripts/security_gate.py --input scripts/findings-critical-demo.json` | **exit 1 is PASS of this test** | Reproduce on Fedora |
| Clean policy | JSON gate | `python scripts/security_gate.py --input scripts/findings-clean.json` | exit 0 | Reproduce on Fedora |
| Web DAST | OWASP ZAP baseline | GitHub `dast` job | fail on missing report or HIGH alerts | Pending Actions run |
| Container CVEs | Trivy | GitHub `container` job | nonzero if any HIGH/CRITICAL fixable vulnerabilities | Pending Actions run |

## Before and after testing sequence
1. Start lab-only vulnerable app and capture IDOR, shell injection, CSRF and framing results (`bash scripts/lab_demo.sh`).
2. Run `bash scripts/verify_native.sh` and capture failed ASan on unsafe parser plus successful overflow rejection on safe parser.
3. Run secured app + test suite; capture owner-scope (404), CSRF rejection (403), XFO/CSP headers, XSS encoding.
4. Run Bandit on both (document expected lab alerts and secure code scan output separately).
5. Deploy secure app locally; run OWASP ZAP only against your local application.
6. Show workflow red for deliberate blocked high/critical finding, green for fixes, and preserved scan artifacts.

## Fill after actual scans
- Fedora version: [TO FILL]
- Python version: [TO FILL]
- GCC/ASan: [TO FILL]
- SAST date: [TO FILL]
- Bandit findings before / after: [TO FILL]
- ZAP target, date, alert summary: [TO FILL]
- Trivy image digest, date, findings: [TO FILL]
- CI red/green run URLs: [TO FILL]
- Security tickets and remediation PR URLs: [TO FILL]
- Exceptions accepted with owner and expiration: [TO FILL]

Do not remove genuine findings or hide failing checks simply to show a green pipeline. Investigate and remediate or document a justified exception, subject to instructor approval.
