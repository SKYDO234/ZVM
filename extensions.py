from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()
login = LoginManager()
login.login_view = 'auth.login'
csrf = CSRFProtect()


@event.listens_for(Engine, 'connect')
def sqlite_settings(connection, _):
    if connection.__class__.__module__.startswith('sqlite3'):
        cur = connection.cursor()
        cur.execute('PRAGMA foreign_keys=ON')
        cur.execute('PRAGMA journal_mode=WAL')
        cur.execute('PRAGMA busy_timeout=30000')
        cur.close()
