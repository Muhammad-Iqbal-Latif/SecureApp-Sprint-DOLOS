# Responsible security testing

DOLOS is a controlled educational application. Only test instances you own or are explicitly authorized to assess. The intentionally vulnerable example (`labs/vulnerable.py`) binds to 127.0.0.1:5001; NEVER expose it through Docker, a tunnel or a public interface. Never test university or external infrastructure.

The production-like `dolos/` implementation is different from the vulnerable lab. No credentials, private event logs, browser cookies, or real attacker payloads should be committed to the repository. `instance/` is gitignored.

For vulnerabilities discovered in secure code, open a private security advisory or contact the maintainer rather than publishing exploitable details in an issue.

Remaining limitations: WSGI reference server is for lab demonstration only, no TLS termination or public exposure, no rate limiting, no event-retention policy, SQLite is not multi-instance, and no externally verified honeypot isolation. Production deployment requires a hardened application server and infrastructure review.
