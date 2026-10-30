"""INTENTIONALLY VULNERABLE. Bound to 127.0.0.1:5001. Never deploy.

CWE-78 Command Injection, CWE-639 IDOR, CWE-352 CSRF, CWE-1021 Clickjacking.
All records and tokens are fabricated. No real accounts or infrastructure.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
import html
import subprocess  # nosec B404; isolated intentionally insecure lab only

EVENTS = {1: {'owner':'alice','indicator':'lab-scan-alpha'},
          2: {'owner':'bob','indicator':'lab-scan-bravo'}}
CONFIG = {'enabled': True}


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        p = parsed.path
        query = parse_qs(parsed.query)
        if p == '/':
            return self.send_page(200, '<h1>DOLOS vulnerable training environment</h1><p>LOCAL LAB ONLY | Port 5001</p><a href="/lab/login?user=alice">Login as Alice</a> | <a href="/lab/login?user=bob">Login as Bob</a>')
        if p == '/lab/login':
            name=query.get('user',['alice'])[0]
            if name not in ('alice','bob'):
                return self.send_page(400,'Invalid lab identity')
            # Intentionally weak mock-login, never a production feature.
            return self.send_page(200, f'Mock logged in as {name}',cookie=f'labuser={name}; Path=/')
        if p.startswith('/lab/event/'):
            try: event = EVENTS[int(p.split('/')[-1])]
            except (ValueError,KeyError): return self.send_page(404,'No event')
            # CWE-639: no owner check, lab-only insecure example.
            return self.send_page(200,f'<h1>Incident</h1>Owner: {event["owner"]} | Indicator: {event["indicator"]}')
        if p == '/lab/admin':
            # CWE-1021: missing X-Frame-Options / CSP frame-ancestors.
            return self.send_page(200,'<h1>Admin action panel</h1><form action="/lab/toggle" method="post"><button>Toggle decoy</button></form>')
        if p == '/lab/search':
            needle=query.get('needle',[''])[0][:100]
            # CWE-78: shell interprets user-controlled string. Harmless lab file only.
            command="printf 'fake-event-1\\nfake-event-2\\n' | grep " + needle
            result=subprocess.run(command,shell=True,text=True,capture_output=True,timeout=2)  # nosec B602
            return self.send_page(200,'<pre>'+html.escape((result.stdout+result.stderr)[:500])+'</pre>')
        if p == '/lab/state':
            return self.send_page(200, 'Decoy enabled: '+str(CONFIG['enabled']))
        if p == '/lab/frame-demo':
            return self.send_page(200,'<h1>Attempted iframe</h1><iframe width="700" height="300" src="/lab/admin"></iframe>')
        return self.send_page(404,'Not found')

    def do_POST(self):
        if urlsplit(self.path).path == '/lab/toggle':
            # CWE-352: changes state without anti-CSRF token or Origin check.
            CONFIG['enabled']=not CONFIG['enabled']
            return self.send_page(200,'Decoy enabled: '+str(CONFIG['enabled']))
        return self.send_page(404,'Not found')

    def send_page(self,status,text,cookie=None):
        body=('<!doctype html><html><head><title>DOLOS vulnerable lab</title></head><body>'+text+'</body></html>').encode()
        self.send_response(status)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers()
        self.wfile.write(body)


if __name__=='__main__':
    print('WARNING: Intentionally vulnerable local demo. NEVER expose outside localhost.',flush=True)
    HTTPServer(('127.0.0.1',5001), DemoHandler).serve_forever()
