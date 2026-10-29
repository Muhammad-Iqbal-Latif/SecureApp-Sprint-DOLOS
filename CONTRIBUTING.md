# Contributing

1. Create a Jira issue linking the PNE ID and STRIDE threat ID.
2. Create a `feature/<issue>-name` or `fix/<issue>-name` branch; never push to protected `main`.
3. Add a focused fix, regression test, and screenshot/log evidence.
4. Run `make test && make security && bash scripts/verify_native.sh`.
5. Push the branch, open a GitHub PR, request at least one genuine peer review and passing CI checks.
6. After approval merge to main; attach PR URL and screenshot to Jira.

Commit style: `feat: ...`, `fix: ...`, `test: ...`, `docs: ...`, `ci: ...`. Each contributor needs visible original commits and PR participation.
