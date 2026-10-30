"""Local demo bootstrap, creates generated passwords never committed to Git."""
import os
from pathlib import Path
import secrets
from . import db


def main():
    if os.getenv('DOLOS_ALLOW_DEMO_SEED') != '1':
        raise SystemExit('Demo seeding disabled. Set DOLOS_ALLOW_DEMO_SEED=1 for local tests only.')
    with db.connect() as con:
        db.init(con)
        if con.execute('SELECT count(*) FROM users').fetchone()[0]:
            raise SystemExit('Users already exist. Refusing to regenerate credentials.')
        credentials = {}
        for name, role in [('alice','analyst'), ('bob','analyst'), ('admin','admin')]:
            password = secrets.token_urlsafe(15)
            owner=db.create_user(con,name,password,role)
            db.create_decoy(con,owner,f'{name}-legacy-login')
            credentials[name]=password
    out=Path('instance/DEMO_CREDENTIALS_LOCAL_ONLY.txt')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text('LOCAL DEMO ONLY. DO NOT COMMIT OR DEPLOY.\n'+''.join(f'{k}: {v}\n' for k,v in credentials.items()))
    out.chmod(0o600)
    print('Demo users: alice, bob, admin')
    print(f'Generated credentials saved locally to {out}. NEVER upload this file.')

if __name__=='__main__':
    main()
