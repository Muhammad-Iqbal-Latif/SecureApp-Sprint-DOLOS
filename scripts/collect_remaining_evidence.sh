#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p evidence/final

printf '\n[1/6] Compile validator, run all unit/integration tests\n'
make test 2>&1 | tee evidence/final/01-unit-and-integration-tests.txt

printf '\n[2/6] Run internal security gates\n'
make security 2>&1 | tee evidence/final/02-internal-security-gates.txt

printf '\n[3/6] Run real secure HTTP regression probes on temporary SQLite database\n'
python3 -m scripts.http_security_probes 2>&1 | tee evidence/final/03-secure-http-probes.txt

printf '\n[4/6] Verify fail-closed severity gate\n'
set +e
python3 scripts/security_gate.py --input scripts/findings-critical-demo.json > evidence/final/04-gate-critical-blocked.txt 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
    echo "ERROR: Critical finding did NOT block the security gate" >&2
    exit 1
fi
printf 'Expected failure, exit code %d\n' "$status" | tee -a evidence/final/04-gate-critical-blocked.txt
python3 scripts/security_gate.py --input scripts/findings-clean.json | tee evidence/final/04-gate-clean.txt

printf '\n[5/6] Run native AddressSanitizer before/after tests\n'
bash scripts/verify_native.sh 2>&1 | tee evidence/final/05-native-ASAN-summary.txt

printf '\n[6/6] Run four intentionally vulnerable localhost-only proofs\n'
started_lab=0
lab_pid=''
cleanup() {
    if [[ "$started_lab" -eq 1 && -n "$lab_pid" ]]; then
        kill "$lab_pid" 2>/dev/null || true
        wait "$lab_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
if curl -fsS --max-time 2 http://127.0.0.1:5001/ > /tmp/dolos-5001-response.$$ 2>/dev/null; then
    if ! grep -q 'DOLOS vulnerable training environment' /tmp/dolos-5001-response.$$; then
        rm -f /tmp/dolos-5001-response.$$
        echo 'ERROR: Port 5001 belongs to another service; not sending lab probes.' >&2
        exit 1
    fi
    echo 'Using existing local DOLOS vulnerable lab server on port 5001.'
else
    python3 -m labs.vulnerable > evidence/final/06-vulnerable-lab-server.txt 2>&1 &
    lab_pid=$!
    started_lab=1
    ready=0
    for attempt in $(seq 1 30); do
        if curl -fsS --max-time 2 http://127.0.0.1:5001/ >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.2
    done
    if [[ "$ready" -ne 1 ]]; then
        echo 'ERROR: Cannot start local vulnerable test service' >&2
        exit 1
    fi
fi
rm -f /tmp/dolos-5001-response.$$
bash scripts/lab_demo.sh 2>&1 | tee evidence/final/06-four-vulnerable-localhost-proofs.txt

# Check these markers so a changed lab cannot silently produce false-positive evidence.
grep -q 'LAB_INJECTED' evidence/04-command-before.txt
grep -q 'Owner: bob' evidence/03-idor-before.txt
grep -q 'Decoy enabled:' evidence/05-csrf-before.txt
if grep -qiE '^X-Frame-Options:|^Content-Security-Policy:' evidence/06-framing-before.txt; then
    echo 'ERROR: intentionally unsafe framing example unexpectedly has anti-frame headers' >&2
    exit 1
fi

echo
printf 'SUCCESS: All local evidence collected into evidence/ and evidence/final/.\n'
printf 'DO NOT COMMIT database, credentials, cookies, or generated evidence without reviewing them.\n'
