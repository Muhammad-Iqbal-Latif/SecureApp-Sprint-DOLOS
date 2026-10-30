#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence
printf '1. Unsafe IDOR: Alice reads Bob incident #2\n'
curl --silent --cookie-jar evidence/lab-cookie.txt 'http://127.0.0.1:5001/lab/login?user=alice' >/dev/null
curl --silent --cookie evidence/lab-cookie.txt 'http://127.0.0.1:5001/lab/event/2' | tee evidence/03-idor-before.txt
printf '\n2. Unsafe command injection: marker appears as command output\n'
curl --silent --get --data-urlencode 'needle=invalid; printf LAB_INJECTED' 'http://127.0.0.1:5001/lab/search' | tee evidence/04-command-before.txt
printf '\n3. Unsafe CSRF: state change works with no token\n'
curl --silent -X POST 'http://127.0.0.1:5001/lab/toggle' | tee evidence/05-csrf-before.txt
printf '\n4. Unsafe clickjacking: no anti-frame headers\n'
curl --silent -D evidence/06-framing-before.txt -o /dev/null 'http://127.0.0.1:5001/lab/admin'
cat evidence/06-framing-before.txt
printf '\nNow run secure integration tests and capture after evidence:\npython -m unittest discover -s tests -v\n'
