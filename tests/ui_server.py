"""Temporary browser DB; intentional first-login fixtures, never production resources."""
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from extensions import db
from models import User
from skvm import create_app

with tempfile.TemporaryDirectory(prefix='skvm-browser-') as directory:
    root=Path(directory)
    app=create_app({'TEST_MODE':True,'DATA_DIR':root/'data','SQLALCHEMY_DATABASE_URI':f'sqlite:///{root/"skvm.db"}',
                    'SECRET_KEY':secrets.token_hex(48),'START_WORKER':False,'SESSION_COOKIE_SECURE':False})
    credentials={'admin':None,'managed':{},'profile':{},'bootstrap':{}}
    with app.app_context():
        for kind,project in [('admin',None),('managed','desktop'),('managed','android'),('profile','desktop'),('profile','android'),('bootstrap','desktop'),('bootstrap','android')]:
            label=kind+('-'+project if project else '')
            password='admin123' if kind=='bootstrap' else secrets.token_urlsafe(24)
            email='admin' if kind=='bootstrap' and project=='desktop' else label+'@example.test'
            user=User(name='Isolated '+label,email=email,role='admin' if kind in ('admin','bootstrap') else 'user',
                      must_change_password=kind=='bootstrap')
            user.set_password(password);db.session.add(user);db.session.flush()
            account={'id':user.id,'email':user.email,'password':password,'role':user.role}
            if project:credentials[kind][project]=account
            else:credentials[kind]=account
        db.session.commit()
    state=Path(os.getenv('SKVM_UI_CREDENTIALS',ROOT/'test-results'/'.ui-credentials.json'))
    state.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as handle:json.dump(credentials,handle)
    app.run(host='0.0.0.0',port=5558,debug=False,use_reloader=False,threaded=True)
