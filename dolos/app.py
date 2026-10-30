"""DOLOS local-first, defensive honeypot simulator and incident dashboard."""
import json
import hashlib
import hmac
import os
import re
import secrets
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server, WSGIRequestHandler
from . import db as model
from .native import validate_event_tag
from .security import verify_password, new_token, token_hash, esc
from .ui import layout, CSS_SHA256

MAX_BODY = 4096
MAX_FIELD = 96


def flatten(value):
    return value[0] if value else ''


class DolosApp:
    def __init__(self, database=None, secure_cookie=None):
        validate_event_tag('decoy-login')  # Fail closed at startup if C guard is unavailable.
        self._prelogin_key = secrets.token_bytes(32)  # For this single-process local service.
        self.path = str(database or os.getenv('DOLOS_DB', 'instance/dolos.sqlite3'))
        self.secure_cookie = (os.getenv('DOLOS_COOKIE_SECURE', '0') == '1') if secure_cookie is None else secure_cookie
        with model.connect(self.path) as con:
            model.init(con)

    def __call__(self, environ, start_response):
        try:
            status, headers, body = self.handle(environ)
        except Exception:  # no stack trace/secret leakage to clients
            status, headers, body = 500, [], b'Internal server error'
        if not any(k.lower() == 'content-type' for k, _ in headers):
            headers.append(('Content-Type', 'text/html; charset=utf-8'))
        headers += [
            ('Content-Length', str(len(body))),
            ('X-Content-Type-Options', 'nosniff'),
            ('X-Frame-Options', 'DENY'),
            ('Content-Security-Policy', f"default-src 'none'; style-src 'sha256-{CSS_SHA256}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
            ('Referrer-Policy', 'no-referrer'),
            ('Cache-Control', 'no-store'),
        ]
        start_response(f'{status} {HTTPStatus(status).phrase}', headers)
        return [body]

    def handle(self, env):
        route = env.get('PATH_INFO', '/')
        method = env.get('REQUEST_METHOD', 'GET').upper()
        data = {}
        if method in ('POST', 'PUT'):
            try:
                length = int(env.get('CONTENT_LENGTH', 0) or '0')
            except ValueError:
                return self.reply(400, 'Invalid request')
            if not 0 <= length <= MAX_BODY:
                return self.reply(413, 'Request too large')
            raw = env['wsgi.input'].read(length)
            try:
                data = {k: flatten(v) for k, v in parse_qs(raw.decode('utf-8'), keep_blank_values=True).items()}
            except UnicodeDecodeError:
                return self.reply(400, 'Invalid encoding')
        with model.connect(self.path) as con:
            user = self.session_user(con, env)
            if route == '/health' and method == 'GET':
                return self.json_reply(200, {'status':'ok', 'project':'DOLOS', 'profile':'secure'})
            if route == '/trap/login' and method == 'POST':
                return self.trap(con, env, data)
            if route == '/trap/login' and method == 'GET':
                return self.page('Decoy service', '<h1>Legacy service</h1><form method="post"><label>Username <input name="username" maxlength="96"></label><button>Connect</button></form>')
            if route == '/login' and method == 'GET':
                return self.login_page()
            if route == '/login' and method == 'POST':
                if not self.valid_prelogin_csrf(env, data):
                    return self.reply(403, 'CSRF validation failed')
                return self.login(con, data)
            if route == '/' and method == 'GET':
                if not user:
                    return self.page('Overview','<h1>Security through deception.</h1><p>Local-first honeypot observation, incident records, and secure analyst workflows.</p><div class="panel"><a href="/login">Analyst login</a> · <a href="/trap/login">Decoy endpoint</a></div>')
                return self.dashboard(con, user)
            if not user:
                return self.reply(401, 'Authentication required')
            if method == 'POST' and not secrets.compare_digest(str(data.get('csrf', '')), user['csrf']):
                return self.reply(403, 'CSRF validation failed')
            if route == '/logout' and method == 'POST':
                con.execute('DELETE FROM sessions WHERE token_hash=?', (user['session_hash'],))
                con.commit()
                return self.redirect('/login', clear=True)
            m = re.fullmatch(r'/events/(\d+)', route)
            if m and method == 'GET':
                return self.event_detail(con, user, int(m.group(1)))
            m = re.fullmatch(r'/decoys/(\d+)/toggle', route)
            if m and method == 'POST':
                return self.toggle_decoy(con, user, int(m.group(1)))
            if route == '/investigate' and method == 'POST':
                return self.investigate(con, user, data)
            if route == '/admin' and method == 'GET':
                if user['role'] != 'admin':
                    return self.reply(403, 'Admin access required')
                return self.page('Administration','<h1>Security administration</h1><p class="panel">Administrative approval and policy management space. CSP disallows framing.</p>', user)
            return self.reply(404, 'Not found')

    def session_user(self, con, env):
        cookie = SimpleCookie()
        try:
            cookie.load(env.get('HTTP_COOKIE', ''))
        except Exception:
            return None
        if 'dolos_session' not in cookie:
            return None
        raw = cookie['dolos_session'].value
        if len(raw) > 128:
            return None
        digest = token_hash(raw)
        row = con.execute('''SELECT u.id,u.username,u.role,s.csrf
            FROM sessions s JOIN users u ON s.user_id=u.id
            WHERE s.token_hash=? AND s.expires>?''', (digest, int(time.time()))).fetchone()
        if not row:
            return None
        result = dict(row)
        result['session_hash'] = digest
        return result

    def trap(self, con, env, data):
        # A decoy, never a real authentication service; passwords are never stored.
        username = str(data.get('username', ''))[:MAX_FIELD]
        decoy = con.execute('SELECT id,owner_id FROM decoys WHERE enabled=1 ORDER BY id LIMIT 1').fetchone()
        if decoy:
            model.create_event(con, decoy['owner_id'], decoy['id'], 'decoy-login', username,
                               env.get('REMOTE_ADDR', 'unknown')[:48])
        return self.reply(401, 'Decoy service: authentication unavailable')

    def login_page(self):
        # Short-lived, signed pre-auth token prevents forged analyst logins.
        expiry = int(time.time()) + 600
        nonce = secrets.token_urlsafe(24)
        cookie_value = f'{expiry}.{nonce}'
        tag = hmac.new(self._prelogin_key, cookie_value.encode('ascii'), hashlib.sha256).hexdigest()
        body = ('<h1>Analyst sign in</h1><div class="panel"><form method="post">'
                f'<input type="hidden" name="csrf" value="{tag}">'
                '<label>Username <input name="username" required></label>'
                '<label>Password <input type="password" name="password" required></label>'
                '<button>Sign in</button></form></div>')
        status, headers, response = self.page('Sign in', body)
        secure = 'Secure; ' if self.secure_cookie else ''
        headers.append(('Set-Cookie',
            f'dolos_prelogin={cookie_value}; Path=/login; {secure}HttpOnly; SameSite=Strict; Max-Age=600'))
        return status, headers, response

    def valid_prelogin_csrf(self, env, data):
        cookies = SimpleCookie()
        try:
            cookies.load(env.get('HTTP_COOKIE', ''))
            if 'dolos_prelogin' not in cookies:
                return False
            value = cookies['dolos_prelogin'].value
            if len(value) > 100:
                return False
            timestamp, sep, nonce = value.partition('.')
            if not sep or len(nonce) < 20 or not timestamp.isdigit():
                return False
            now = int(time.time())
            expiry = int(timestamp)
            if not now <= expiry <= now + 600:
                return False
            expected = hmac.new(self._prelogin_key, value.encode('ascii'), hashlib.sha256).hexdigest()
            submitted = str(data.get('csrf', ''))
            return len(submitted) == len(expected) and hmac.compare_digest(submitted, expected)
        except (ValueError, UnicodeEncodeError):
            return False

    def login(self, con, data):
        username = str(data.get('username', ''))[:MAX_FIELD]
        password = str(data.get('password', ''))
        row = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if row is None or not verify_password(password, row['password_hash']):
            return self.reply(401, 'Invalid credentials')
        token, csrf = new_token(), new_token()
        con.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires) VALUES(?,?,?,?)',
                    (token_hash(token), row['id'], csrf, int(time.time())+8*60*60))
        con.commit()
        flags = 'Secure; ' if self.secure_cookie else ''
        return self.redirect('/', cookie=f'dolos_session={token}; Path=/; {flags}HttpOnly; SameSite=Lax; Max-Age=28800')

    def dashboard(self, con, user):
        if user['role'] == 'admin':
            decoys = con.execute('SELECT * FROM decoys ORDER BY id').fetchall()
            events = con.execute('SELECT * FROM events ORDER BY id DESC LIMIT 30').fetchall()
        else:
            decoys = con.execute('SELECT * FROM decoys WHERE owner_id=? ORDER BY id', (user['id'],)).fetchall()
            events = con.execute('SELECT * FROM events WHERE owner_id=? ORDER BY id DESC LIMIT 30', (user['id'],)).fetchall()
        drows = ''.join(f'<tr><td>{d["id"]}</td><td>{esc(d["name"])}</td><td>{"Online" if d["enabled"] else "Paused"}</td><td><form action="/decoys/{d["id"]}/toggle" method="post"><input type="hidden" name="csrf" value="{esc(user["csrf"])}"><button>Toggle</button></form></td></tr>' for d in decoys)
        erows = ''.join(f'<tr><td><a href="/events/{e["id"]}">#{e["id"]}</a></td><td>{esc(e["kind"])}</td><td>{esc(e["value"])}</td><td>{esc(e["created_at"])}</td></tr>' for e in events)
        form = f'<form action="/investigate" method="post"><input type="hidden" name="csrf" value="{esc(user["csrf"])}"><input name="needle" maxlength="96" placeholder="Search event indicator"><button>Search</button></form>'
        body = f'<h1>Deception operations dashboard</h1><div class="grid"><div class="panel"><h2>{len(decoys)} decoys</h2><small>Visible to your role</small></div><div class="panel"><h2>{len(events)} recent events</h2><small>Authorized incident feed</small></div></div><div class="panel"><h2>Decoy controls</h2><table><tr><th>ID</th><th>Name</th><th>State</th><th>Control</th></tr>{drows}</table></div><div class="panel"><h2>Recent incidents</h2><table><tr><th>Event</th><th>Type</th><th>Indicator</th><th>UTC recorded</th></tr>{erows}</table></div><div class="panel"><h2>Investigate indicator</h2><p class="muted">Parameterized local database search; never invokes a shell.</p>{form}</div>'
        if user['role']=='admin':
            body += '<p><a href="/admin">Administration</a></p>'
        return self.page('Dashboard',body,user)

    def event_detail(self, con, user, event_id):
        if user['role']=='admin':
            event = con.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
        else:
            event = con.execute('SELECT * FROM events WHERE id=? AND owner_id=?', (event_id,user['id'])).fetchone()
        if not event:
            # 404 also hides whether another user's record exists.
            return self.reply(404, 'Event not found')
        body = f'<h1>Incident #{event["id"]}</h1><div class="panel"><p>Type: {esc(event["kind"])}</p><p>Indicator: {esc(event["value"])}</p><p>Peer: {esc(event["peer"])}</p><p>Recorded: {esc(event["created_at"])}</p></div><a href="/">Back to dashboard</a>'
        return self.page('Incident detail',body,user)

    def toggle_decoy(self, con, user, decoy_id):
        if user['role']=='admin':
            cur=con.execute('UPDATE decoys SET enabled=1-enabled WHERE id=?',(decoy_id,))
        else:
            cur=con.execute('UPDATE decoys SET enabled=1-enabled WHERE id=? AND owner_id=?',(decoy_id,user['id']))
        con.commit()
        return self.redirect('/') if cur.rowcount else self.reply(404,'Decoy not found')

    def investigate(self, con, user, data):
        needle = str(data.get('needle',''))[:MAX_FIELD]
        # No shell, no regex backtracking, no path traversal. The query is parameterized.
        needle = needle.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        if user['role']=='admin':
            rows=con.execute("SELECT * FROM events WHERE value LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 30",('%'+needle+'%',)).fetchall()
        else:
            rows=con.execute("SELECT * FROM events WHERE owner_id=? AND value LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 30",(user['id'],'%'+needle+'%')).fetchall()
        listing=''.join(f'<li><a href="/events/{row["id"]}">Event #{row["id"]}</a> - {esc(row["value"])}</li>' for row in rows)
        return self.page('Investigation','<h1>Indicator search</h1><div class="panel"><ul>'+listing+'</ul></div><a href="/">Back</a>',user)

    @staticmethod
    def reply(status, msg):
        return status, [], esc(msg).encode('utf-8')

    @staticmethod
    def json_reply(status, data):
        return status, [('Content-Type','application/json; charset=utf-8')],json.dumps(data).encode('utf-8')

    def page(self, title, content, user=None):
        return 200, [],layout(title,content,user).encode('utf-8')

    @staticmethod
    def redirect(to, cookie=None, clear=False):
        headers=[('Location',to)]
        if clear:
            headers.append(('Set-Cookie','dolos_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'))
        if cookie:
            headers.append(('Set-Cookie',cookie))
        return 303,headers,b''


def serve(host='127.0.0.1',port=5000):
    print(f'DOLOS secure server: http://{host}:{port}', flush=True)
    with make_server(host,port,DolosApp(),handler_class=WSGIRequestHandler) as server:
        server.serve_forever()
