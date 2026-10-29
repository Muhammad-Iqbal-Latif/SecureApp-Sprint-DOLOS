#!/usr/bin/env bash
set -uo pipefail
mkdir -p evidence
cc -g -O1 -fsanitize=address -fno-omit-frame-pointer -o native/vulnerable native/vulnerable.c
cc -g -O1 -fsanitize=address -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o native/secure native/secure.c
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./native/vulnerable "$(printf 'A%.0s' {1..40})" > evidence/01-overflow-before.txt 2>&1
before=$?
./native/secure "$(printf 'A%.0s' {1..40})" > evidence/02-overflow-after.txt 2>&1
after=$?
set -e
printf 'Vulnerable exit: %s (nonzero expected)\nSecure exit: %s (1=rejected oversized input)\n' "$before" "$after"
head -n 14 evidence/01-overflow-before.txt
cat evidence/02-overflow-after.txt
if [[ "$before" -eq 0 || "$after" -ne 1 ]]; then echo 'Unexpected result';exit 1;fi
