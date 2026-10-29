"""WSGI integration tests: auth, IDOR, CSRF, clickjacking, injection and decoys."""
import io
import os
import tempfile
import unittest
from urllib.parse import urlencode
from dolos.app import DolosApp
from dolos import db


class Client:
    def __init__(self,app):
        self.app=app
        self.cookie=''

    def req(self,method,path,data=None):
        data=urlencode(data or {}).encode('utf-8')
        environ={'PATH_INFO':path,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(data)),
                 'wsgi.input':io.BytesIO(data),'REMOTE_ADDR':'127.0.0.1','HTTP_COOKIE':self.cookie}
        result={}
        def start(status,headers):
            result['status']=int(status.split()[0]);result['headers']=dict(headers)
        response=b''.join(self.app(environ,start))
        if 'Set-Cookie' in result['headers']:
            self.cookie=result['headers']['Set-Cookie'].split(';',1)[0]
        return result['status'],result['headers'],response.decode()


class DolosTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.tmp.name,'test.sqlite3')
        self.app=DolosApp(database=self.path)
        with db.connect(self.path) as con:
            self.alice=db.create_user(con,'alice','AlicePassword-test-2026')
            self.bob=db.create_user(con,'bob','BobPassword-test-2026')
            self.admin=db.create_user(con,'admin','AdminPassword-test-2026','admin')
            self.decoy1=db.create_decoy(con,self.alice,'alpha')
            self.decoy2=db.create_decoy(con,self.bob,'bravo')
            self.event1=db.create_event(con,self.alice,self.decoy1,'trap','alpha-event')
            self.event2=db.create_event(con,self.bob,self.decoy2,'trap','bravo-event')
        self.client=Client(self.app)

    def tearDown(self):
        self.tmp.cleanup()

    def login(self,who,password):
        code,headers,body=self.client.req('POST','/login',{'username':who,'password':password})
        self.assertEqual(code,303)
        self.assertIn('HttpOnly',headers['Set-Cookie'])
        self.assertIn('SameSite=Lax',headers['Set-Cookie'])
        with db.connect(self.path) as con:
            return con.execute('SELECT csrf FROM sessions ORDER BY rowid DESC LIMIT 1').fetchone()['csrf']

    def test_health_and_security_headers(self):
        code,headers,body=self.client.req('GET','/health')
        self.assertEqual(code,200)
        self.assertIn('"status": "ok"',body)
        self.assertEqual(headers['X-Frame-Options'],'DENY')
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])

    def test_auth_required(self):
        self.assertEqual(self.client.req('GET','/events/1')[0],401)

    def test_unauthorized_idor_rejected(self):
        self.login('alice','AlicePassword-test-2026')
        code,_,body=self.client.req('GET',f'/events/{self.event2}')
        self.assertEqual(code,404)
        self.assertNotIn('bravo-event',body)
        self.assertEqual(self.client.req('GET',f'/events/{self.event1}')[0],200)

    def test_admin_can_read_all(self):
        self.login('admin','AdminPassword-test-2026')
        self.assertEqual(self.client.req('GET',f'/events/{self.event2}')[0],200)

    def test_csrf_rejects_without_token(self):
        self.login('alice','AlicePassword-test-2026')
        self.assertEqual(self.client.req('POST',f'/decoys/{self.decoy1}/toggle')[0],403)
        with db.connect(self.path) as con:
            self.assertEqual(con.execute('SELECT enabled FROM decoys WHERE id=?',(self.decoy1,)).fetchone()[0],1)

    def test_valid_csrf_changes_only_owned_decoy(self):
        csrf=self.login('alice','AlicePassword-test-2026')
        self.assertEqual(self.client.req('POST',f'/decoys/{self.decoy1}/toggle',{'csrf':csrf})[0],303)
        self.assertEqual(self.client.req('POST',f'/decoys/{self.decoy2}/toggle',{'csrf':csrf})[0],404)
        with db.connect(self.path) as con:
            self.assertEqual(con.execute('SELECT enabled FROM decoys WHERE id=?',(self.decoy2,)).fetchone()[0],1)

    def test_injection_string_is_only_data(self):
        csrf=self.login('alice','AlicePassword-test-2026')
        code,_,body=self.client.req('POST','/investigate',{'csrf':csrf,'needle':'; echo LAB_INJECTED'})
        self.assertEqual(code,200)
        self.assertNotIn('LAB_INJECTED',body)

    def test_xss_is_escaped(self):
        with db.connect(self.path) as con:
            db.create_event(con,self.alice,self.decoy1,'trap','<script>alert(1)</script>')
        self.login('alice','AlicePassword-test-2026')
        _,_,body=self.client.req('GET','/')
        self.assertNotIn('<script>alert(1)</script>',body)
        self.assertIn('&lt;script&gt;',body)

    def test_trap_records_only_identifier(self):
        code,_,_=self.client.req('POST','/trap/login',{'username':'demo','password':'DO-NOT-STORE'})
        self.assertEqual(code,401)
        with db.connect(self.path) as con:
            row=con.execute('SELECT value FROM events ORDER BY id DESC LIMIT 1').fetchone()
            self.assertEqual(row['value'],'demo')
            self.assertNotIn('DO-NOT-STORE',row['value'])

    def test_native_parser_accepts_event_type(self):
        with db.connect(self.path) as con:
            event_id = db.create_event(con, self.alice, self.decoy1,
                                       'decoy-login', 'known-safe')
            self.assertIsNotNone(con.execute(
                'SELECT id FROM events WHERE id=?', (event_id,)).fetchone())

    def test_native_parser_rejects_overlong_and_nul_tags(self):
        with db.connect(self.path) as con:
            before = con.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            for tag in ('x' * 16, 'trap\x00bypass', '../bad', ''):
                with self.subTest(tag=repr(tag)):
                    with self.assertRaises(ValueError):
                        db.create_event(con, self.alice, self.decoy1,
                                        tag, 'should-not-be-inserted')
            after = con.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            self.assertEqual(before, after)

    def test_admin_protection(self):
        self.login('alice','AlicePassword-test-2026')
        self.assertEqual(self.client.req('GET','/admin')[0],403)


if __name__=='__main__':unittest.main()
