# DOLOS | Deception Operations and Log Observation System

**CYC386 - Secure Software Design and Development | Fall 2026 | COMSATS University Islamabad**

DOLOS is a controlled defensive cybersecurity app: simulated honeypot login, incident ingestion, authenticated analyst dashboard, owner-scoped investigations and decoy controls. A second localhost-only training server demonstrates four deliberately insecure web patterns; a C teaching component demonstrates a fifth. **Never deploy the lab-only vulnerable server.**

**Instructor status:** custom project theme requires approval and confirmation of uniqueness. **Academic note:** AI-assisted code permitted under exam instructions, but team must understand and justify all security decisions and cite any third-party references.

## Fedora Quick Start (first terminal)
```bash
sudo dnf install -y git gh python3 gcc make curl jq
mkdir -p ~/SSDD && cd ~/SSDD
unzip ~/Downloads/SecureApp-Sprint-DOLOS.zip
cd SecureApp-Sprint-DOLOS
python3 --version
make test
make security
make seed
cat instance/DEMO_CREDENTIALS_LOCAL_ONLY.txt
python3 run.py
```
Open http://127.0.0.1:5000 and sign in with generated local demo credentials for **alice**, **bob** or **admin**. The file is ignored by Git; do not share screenshots showing its contents. User accounts are **only for local demo**. **Do not use a public URL, tunnel or port forwarding.**

## Generate a synthetic honeypot event (second terminal)
```bash
curl -i -X POST -d 'username=local-probe' -d 'password=DO_NOT_STORE' http://127.0.0.1:5000/trap/login
curl -i http://127.0.0.1:5000/health
```
Expected decoy HTTP 401 (intended rejection) and health HTTP 200. Refresh the dashboard: Alice can see the event if her decoy is active. The decoy never stores the submitted password.

## Local vulnerable-before demo (third terminal)
```bash
python3 -m labs.vulnerable
```
In a fourth terminal, from repository root:
```bash
bash scripts/lab_demo.sh
bash scripts/verify_native.sh
python3 -m unittest discover -s tests -v
```
`lab_demo.sh` creates before-evidence for command injection, IDOR, CSRF and clickjacking. `verify_native.sh` produces ASan before and safe rejection after. The training server **only binds 127.0.0.1:5001**.

## Prove the security gate fails on critical findings
```bash
python3 scripts/security_gate.py --input scripts/findings-critical-demo.json
# EXPECT EXIT 1 (a correct blocking result)
echo $?
python3 scripts/security_gate.py --input scripts/findings-clean.json
# EXPECT EXIT 0
```
This is a **synthetic-policy demonstration**, not a real SAST finding; also run actual Bandit/ZAP/Trivy scans and present their outputs.

## Static analysis on Fedora
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
mkdir -p evidence
bandit -r labs -f json -o evidence/bandit-before.json || true
bandit -r dolos run.py -lll -i -f json -o evidence/bandit-after.json
python scripts/sast_gate.py
```
If Bandit findings remain in the secure deployment code, investigate rather than suppress the pipeline.

## Optional bonus: Docker on Fedora
```bash
sudo systemctl enable --now docker
docker compose up --build -d
docker compose ps
docker inspect "$(docker compose ps -q dolos)" --format '{{.Config.User}}'
curl -i http://127.0.0.1:5000/health
docker compose down
```
Stop the local Python server before Docker, since both need port 5000. `compose.yaml` binds the host port to loopback only, drops Linux capabilities, uses a non-root image user, a read-only filesystem and a separate SQLite volume. To populate demo accounts in the Docker volume only in a local demo:
```bash
docker compose exec -e DOLOS_ALLOW_DEMO_SEED=1 dolos python -m dolos.seed
```
Demo credentials are stored inside the container volume, not in Git. Never deploy those demo credentials or expose the HTTP reference server publicly.

## Git/GitHub/Jira workflow (do not invent evidence)
The ZIP includes completed reference code, but the exam also grades **actual teamwork and incrementally reviewed security work**. Do not create a fake commit history or claim a PR was approved if it was not. To preserve genuine incremental evidence, first commit only planning artifacts, then make real reviewed branches for implementation/testing. See `docs/GIT_STAGING_GUIDE.md` for the exact order.

```bash
git init -b main
git add .gitignore README.md THEME_PROPOSAL.md PNE_Report.md SECURITY.md CONTRIBUTING.md LICENSE THREAT_MODEL.pdf docs/THREAT_MODEL.md docs/SPRINT_PLAN.md docs/JIRA_BACKLOG.md
git commit -m 'docs: establish approved DOLOS sprint scope and security needs'
gh auth login
gh repo create SecureApp-Sprint-DOLOS --public --source=. --remote=origin --push
# Create your Jira project and configure protected main on GitHub.
git switch -c feature/DOLOS-11-native-overflow
# Add only the files for this work item. These were present in your unpacked ZIP but not yet tracked.
git add native/vulnerable.c native/secure.c scripts/verify_native.sh
bash scripts/verify_native.sh
git commit -m 'fix: demonstrate and bound native event parser input'
git push -u origin feature/DOLOS-11-native-overflow
gh pr create --base main --head feature/DOLOS-11-native-overflow --title 'Fix DOLOS-11: native event tag bounds' --body 'PNE-04; T-BOF; ASan before/after; manual peer review required'
```

A real teammate must inspect/approve the PR before merge, then continue with the next issue. If working alone, request an approved alternative from the instructor: do not fabricate peer approvals. Set required security checks after the workflow has first been run.

## Required deliverables
- `PNE_Report.md` - assets, stakeholders, explicit CIA map and tests.
- `THREAT_MODEL.pdf` and `docs/THREAT_MODEL.md` - DFDs, STRIDE, two attack trees, CVSS v3.1 risk register and residual risks.
- `SECURITY_IMPLEMENTATION.md` - before/after for 5 required vulnerabilities.
- `SECURITY_TEST_REPORT.md` - actual tool configurations, results and pending evidence.
- `.github/workflows/ci-cd.yml` - push and PR test gates, SAST, ZAP and Trivy.
- `docs/RUBRIC_MATRIX.md`, `docs/JIRA_BACKLOG.md`, `docs/EVIDENCE_CHECKLIST.md` - traceability.
- `docs/FINAL_REPORT_TEMPLATE.md` - outline only, **NOT a final completed 18-30-page report**.
- `docs/DEMO_SCRIPT.md` - planned 6-10 minute technical walkthrough, must actually record.

## Honest deployment limitations
This is a local-first teaching/prototype application, not a security-reviewed internet-facing honeypot. Python WSGI reference server, SQLite, no TLS/production reverse proxy, no rate limiting, no retention enforcement or immutable audit trail. The container hardening and scanners improve defenses but do not prove full security. Consult `SECURITY.md` and the threat model for residual risk.
