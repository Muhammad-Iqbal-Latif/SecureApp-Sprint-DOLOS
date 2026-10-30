#!/usr/bin/env python3
"""True localhost HTTP security regression probes against the secured DOLOS app.

Uses a disposable SQLite database and an ephemeral localhost TCP port. Does NOT
change the user's actual DOLOS database, accounts, or running application.
"""
import http.client
import io
import re
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlencode
from wsgiref.simple_server import make_server, WSGIRequestHandler

from dolos import db
from dolos.app import DolosApp


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


class Session:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def login(self, username, password):
        status, _, body = self.request('GET', '/login')
        assert status == 200
        token = re.search(r'name="csrf" value="([^"]+)"', body)
        assert token, 'Missing pre-login CSRF token'
        return self.request('POST', '/login',
            {'username': username, 'password': password, 'csrf': token.group(1)})

    def request(self, method, path, data=None):
        headers = {}
        payload = None
        if data is not None:
            payload = urlencode(data).encode('utf-8')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.cookie:
            headers['Cookie'] = self.cookie
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            body = response.read().decode('utf-8', errors='replace')
            response_headers = dict(response.getheaders())
            if 'Set-Cookie' in response_headers:
                self.cookie = response_headers['Set-Cookie'].split(';', 1)[0]
            return response.status, response_headers, body
        finally:
            conn.close()


def verify():
    with tempfile.TemporaryDirectory(prefix='dolos-security-') as temp:
        path = str(Path(temp) / 'temp.sqlite3')
        app = DolosApp(database=path)
        with db.connect(path) as con:
            alice_id = db.create_user(con, 'alice', 'AlicePassword-test-2026')
            bob_id = db.create_user(con, 'bob', 'BobPassword-test-2026')
            db.create_user(con, 'admin', 'AdminPassword-test-2026', 'admin')
            alice_decoy = db.create_decoy(con, alice_id, 'alpha')
            bob_decoy = db.create_decoy(con, bob_id, 'bravo')
            own_event = db.create_event(con, alice_id, alice_decoy, 'trap', 'alice-indicator')
            bob_event = db.create_event(con, bob_id, bob_decoy, 'trap', 'bob-private')
            db.create_event(con, alice_id, alice_decoy, 'trap', '<script>alert(1)</script>')

        server = make_server('127.0.0.1', 0, app, handler_class=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_port
            alice = Session(port)
            status, headers, _ = alice.login('alice', 'AlicePassword-test-2026')
            assert status == 303, f'Alice login status {status}'
            anonymous = Session(port)
            bad_status, _, _ = anonymous.request('POST', '/login',
                {'username': 'alice', 'password': 'AlicePassword-test-2026'})
            assert bad_status == 403, 'Forged login was not rejected'
            print('[PASS] Login CSRF: forged login without token rejected (HTTP 403)')
            assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Lax' in headers['Set-Cookie']
            with db.connect(path) as con:
                csrf = con.execute('SELECT csrf FROM sessions WHERE user_id=?',
                    (alice_id,)).fetchone()['csrf']

            # IDOR before/after proof uses real HTTP against secure WSGI server.
            status, _, body = alice.request('GET', f'/events/{bob_event}')
            assert status == 404 and 'bob-private' not in body
            print('[PASS] IDOR: Alice cannot read Bob event (HTTP 404)')
            status, _, body = alice.request('GET', f'/events/{own_event}')
            assert status == 200 and 'alice-indicator' in body
            print('[PASS] Authorization: Alice can read her own event (HTTP 200)')

            # Command injection in secure path is literal SQL search input, no shell.
            status, _, body = alice.request('POST', '/investigate',
                {'csrf': csrf, 'needle': 'not-found; printf LAB_INJECTED'})
            assert status == 200 and 'LAB_INJECTED' not in body
            print('[PASS] Command injection: shell marker not executed (HTTP 200)')

            with db.connect(path) as con:
                initial = con.execute('SELECT enabled FROM decoys WHERE id=?',
                    (alice_decoy,)).fetchone()['enabled']
            status, _, _ = alice.request('POST', f'/decoys/{alice_decoy}/toggle')
            with db.connect(path) as con:
                unchanged = con.execute('SELECT enabled FROM decoys WHERE id=?',
                    (alice_decoy,)).fetchone()['enabled']
            assert status == 403 and unchanged == initial
            print('[PASS] CSRF: missing token rejected; state unchanged (HTTP 403)')
            status, _, _ = alice.request('POST', f'/decoys/{alice_decoy}/toggle', {'csrf': csrf})
            with db.connect(path) as con:
                changed = con.execute('SELECT enabled FROM decoys WHERE id=?',
                    (alice_decoy,)).fetchone()['enabled']
            assert status == 303 and changed != initial
            print('[PASS] CSRF: valid token changes owned decoy (HTTP 303)')

            # Clickjacking protections must be on actual page, even an access-denied response.
            status, headers, _ = alice.request('GET', '/admin')
            assert status == 403
            assert headers.get('X-Frame-Options') == 'DENY'
            assert "frame-ancestors 'none'" in headers.get('Content-Security-Policy', '')
            print('[PASS] Clickjacking: security headers on forbidden admin response (HTTP 403)')
            administrator = Session(port)
            status, _, _ = administrator.login('admin', 'AdminPassword-test-2026')
            assert status == 303
            status, headers, _ = administrator.request('GET', '/admin')
            assert status == 200 and headers.get('X-Frame-Options') == 'DENY'
            assert "frame-ancestors 'none'" in headers.get('Content-Security-Policy', '')
            print('[PASS] Clickjacking: admin page forbids framing (HTTP 200)')

            status, _, body = alice.request('GET', '/')
            assert status == 200 and '<script>alert(1)</script>' not in body
            assert '&lt;script&gt;' in body
            print('[PASS] Extra XSS control: incident value HTML-escaped')
            print('DOLOS secure HTTP regression probes: 9/9 PASSED')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    verify()
