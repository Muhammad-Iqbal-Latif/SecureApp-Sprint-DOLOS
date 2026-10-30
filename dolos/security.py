"""Password hashing, session tokens and HTML escaping for DOLOS."""
import hashlib
import hmac
import html
import secrets

ITERATIONS = 350_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}'


def verify_password(password: str, stored: str) -> bool:
    try:
        label, iters, salt, expected = stored.split('$')
        if label != 'pbkdf2_sha256' or not 100_000 <= int(iters) <= 1_000_000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)
