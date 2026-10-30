# DOLOS: Security implementation and reproducible before/after evidence

**Lab constraints:** All intentionally unsafe demonstrations use synthetic data and 127.0.0.1 only. Lab server code is deliberately insecure; do not deploy it. Secure code is in `dolos/`, never in the vulnerable lab.

## 1. Buffer Overflow - CWE-120 (T-BOF, PNE-04)
- Vulnerable code: `native/vulnerable.c`: `char buffer[16]; strcpy(buffer, tag);` copies without a size check.
- Demonstration: `bash scripts/verify_native.sh` compiles with `-fsanitize=address` and passes a 40-byte tag to both binaries.
- Expected before evidence: AddressSanitizer `stack-buffer-overflow`, nonzero crash. `evidence/01-overflow-before.txt`.
- Secure code: `native/secure.c` checks `strlen(tag) >= sizeof buffer`, rejects invalid input, uses `snprintf` and `-fstack-protector-strong -D_FORTIFY_SOURCE=2`. Oversized input returns exit 1, no overflow. `evidence/02-overflow-after.txt`.
- Note: ASan validates memory safety of this input/path; it does not prove every possible C memory error has been eliminated.
- **Live integration:** `dolos/native.py` loads the compiled `libdolos_native.so` and `dolos/db.py:create_event()` calls the bounded C validator before inserting every event. Application startup fails closed if the library is missing. `test_native_parser_accepts_event_type` and `test_native_parser_rejects_overlong_and_nul_tags` prove allowed types are recorded and unsafe tags never reach SQLite. `make test` compiles the library; the Docker multi-stage build includes it without shipping the vulnerable example.
- **Evidence limitation:** the original unsafe C example is isolated teaching code; it was not previously invoked by the live Python app. Do not claim a historical production exploit of DOLOS.

## 2. Command Injection - CWE-78 (T-CMD, PNE-03)
- Vulnerable code: `labs/vulnerable.py`, `/lab/search`: user-controlled string concatenated into `printf ... | grep ` and executed with `subprocess.run(...,shell=True)`.
- Before: run `python -m labs.vulnerable` then `bash scripts/lab_demo.sh`. Probe `needle=invalid; printf LAB_INJECTED` proves shell interpretation from a local, harmless echo marker. Screenshot `evidence/04-command-before.txt`.
- Secure code: `dolos/app.py`, `investigate()`: parameterized SQLite `LIKE` and escaping `%`/`_`/`\\`; does not call an OS shell. The same string is treated only as a literal search term.
- Verify: `test_injection_string_is_only_data` and `scripts/sast_gate.py`. No `LAB_INJECTED` output.

## 3. IDOR - CWE-639 (T-IDOR, PNE-01)
- Vulnerable code: `/lab/event/2` returns Bob's incident even when Alice has the demo cookie.
- Before: `bash scripts/lab_demo.sh`, see `evidence/03-idor-before.txt` showing Owner: bob.
- Secure code: `event_detail()` uses `SELECT * FROM events WHERE id=? AND owner_id=?` for non-admins. Admin has explicitly authorized broader access. Unauthorized/missing IDs both return 404.
- Verify: `test_unauthorized_idor_rejected` and `test_admin_can_read_all`.

## 4. CSRF - CWE-352 (T-CSRF, PNE-02)
- Vulnerable code: `/lab/toggle` changes state on POST without a token. Before: `evidence/05-csrf-before.txt`.
- Secure code: `session_user()` retrieves a random per-session CSRF token, HTML forms include it, and `handle()` blocks POST without it, while session cookies use `HttpOnly` and `SameSite=Lax`.
- Verify: `test_csrf_rejects_without_token` (403 and unchanged DB) and `test_valid_csrf_changes_only_owned_decoy` (valid token + owner requirement).
- Caveat: SameSite is defense in depth, not a substitute for synchronizer tokens.

## 5. Clickjacking - CWE-1021 (T-FRAME, PNE-05)
- Vulnerable code: `/lab/admin` returns an HTML administrative form without anti-frame headers. Open `http://127.0.0.1:5001/lab/frame-demo`; page frames the admin form.
- Secure code: every response sets `Content-Security-Policy: ...; frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- Verify: `test_health_and_security_headers`; compare `curl -sD - -o /dev/null http://127.0.0.1:5001/lab/admin` versus secure `/admin` (requires login; even 401 contains anti-frame headers). For browser screenshot, place secured page in an iframe and show browser blocking it.

## 6. Extra vulnerability fixes
- Reflected/stored XSS from event indicators: `html.escape` used in dashboard/event templates; `test_xss_is_escaped`.
- SQL injection: bound query parameters in login, events, decoys and investigation.
- Session fixation: server creates new high-entropy token at login. Only token hash resides in SQLite.
- Private keys/secrets: no hardcoded seeded passwords; demo seeding generates random per-machine credentials.
- No full production claim: deployment review and residual risk statement in threat model.

## 7. Evidence mapping
| Vulnerability | Before artifact | After artifact |
|---|---|---|
| Buffer overflow | `01-overflow-before.txt`, screenshot of sanitizer | `02-overflow-after.txt`, screenshot of rejection |
| Command injection | `04-command-before.txt` | Pytest/unittest output + secure search screenshot |
| IDOR | `03-idor-before.txt` | unauthorized secure event 404 + regression test |
| CSRF | `05-csrf-before.txt` | secure POST 403 and unchanged decoy state |
| Clickjacking | `06-framing-before.txt`, browser iframe | CSP/XFO headers + browser blocked iframe |

**Always link the screenshots and code/PR URLs in the final report.**
