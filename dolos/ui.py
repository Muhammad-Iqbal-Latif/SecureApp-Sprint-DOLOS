"""Simple HTML rendering; escape every attacker-controlled field."""
from .security import esc
CSS = '''
:root{color-scheme:dark}body{margin:0;background:#0b111b;color:#e8eef6;font:16px system-ui,sans-serif}
header{padding:24px 6%;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #253143}
.brand{letter-spacing:.16em;font-size:24px;font-weight:800;color:#ef6575}
main{max-width:1080px;margin:45px auto;padding:0 20px}a{color:#a8d6f5}h1{font-size:2rem}
small,.muted{color:#9aa9bd}.kicker{color:#ef6575;font-weight:700;text-transform:uppercase;letter-spacing:.18em}
.panel{background:#131f2f;border:1px solid #2a3b4c;border-radius:13px;padding:25px;margin:20px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}
input,button{font:inherit;border-radius:7px;padding:11px;margin:6px 0}input{background:#0b111b;color:white;border:1px solid #50657c}
button{background:#eb566c;border:0;color:#fff;cursor:pointer;font-weight:bold}button:hover{background:#f77384}
.error{color:#ff9ea9}.ok{color:#94e2b8}table{width:100%;border-collapse:collapse}td,th{padding:12px;border-bottom:1px solid #2a3b4c;text-align:left}
code{background:#263245;padding:4px 8px;border-radius:5px;overflow-wrap:anywhere}
'''

def layout(title, content, user=None):
    nav = f'<span>{esc(user["username"])} ({esc(user["role"])}) <form style="display:inline" action="/logout" method="post"><input type="hidden" name="csrf" value="{esc(user["csrf"])}"><button>Log out</button></form></span>' if user else '<a href="/login">Sign in</a>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} | DOLOS</title><style>{CSS}</style></head><body><header><span class="brand">DOLOS</span>{nav}</header><main><div class="kicker">Deception Operations and Log Observation System</div>{content}</main></body></html>'''
