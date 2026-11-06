"""One-time, explicitly documented bootstrap account; never a password back door."""
from flask import current_app, jsonify, redirect, request, url_for
from flask_login import current_user
from sqlalchemy import inspect, text
from extensions import db
from models import Setting, User
from services.security import audit

BOOTSTRAP_LOGIN = 'admin'
BOOTSTRAP_PASSWORD = 'admin123'
BOOTSTRAP_MARKER = 'bootstrap_admin_initialized'


def migrate_user_schema():
    """Add the rotation flag to existing SQLite DBs without replacing any rows."""
    columns = {column['name'] for column in inspect(db.engine).get_columns('user')}
    if 'must_change_password' not in columns:
        with db.engine.begin() as connection:
            connection.execute(text('ALTER TABLE "user" ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0'))


def bootstrap_admin():
    """Caller holds schema-initialization lock. Existing installs are never reset."""
    if current_app.config['NODE_AGENT']:
        return 'disabled on agents'
    marker = db.session.get(Setting, BOOTSTRAP_MARKER)
    if marker:
        return 'already initialized; existing credentials preserved'
    if db.session.scalar(db.select(User.id).limit(1)) is not None:
        db.session.add(Setting(key=BOOTSTRAP_MARKER, value={'state': 'existing_accounts_preserved'}))
        db.session.commit()
        return 'existing accounts preserved; default account not added'
    # "admin" is a reserved login identifier, not a fabricated deliverable email.
    user = User(email=BOOTSTRAP_LOGIN, name='Administrator', role='admin', must_change_password=True)
    user.set_password(BOOTSTRAP_PASSWORD)
    db.session.add(user)
    db.session.flush()
    db.session.add(Setting(key=BOOTSTRAP_MARKER, value={'state': 'created', 'user_id': user.id}))
    audit('admin.bootstrap', 'One-time bootstrap administrator created; password replacement required before panel access.', user.id)
    db.session.commit()
    return 'created; sign in as admin and replace the initial password before using the panel'


def require_password_change():
    """No admin page, API or guest mutation is usable with the initial password."""
    if not current_user.is_authenticated or not current_user.must_change_password:
        return None
    if request.endpoint in ('auth.profile', 'auth.logout', 'static'):
        return None
    if request.path.startswith('/api/'):
        return jsonify(error='Replace the initial administrator password before using the panel.',
                       code='password_change_required', redirect=url_for('auth.profile')), 403
    return redirect(url_for('auth.profile'))
