import hashlib
import re
from datetime import timedelta
from urllib.parse import urlsplit
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from engines import EngineError
from extensions import db
from models import AuthAttempt, User
from models.user import utcnow
from services.security import audit, settings, validate_password

bp = Blueprint('auth', __name__)
DUMMY_HASH = generate_password_hash('not-a-real-login-password')


def valid_email(value):
    email = value.strip().lower()
    if len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise EngineError('Enter a valid email address.')
    return email


def rate_limit(email, registration=False):
    now = utcnow()
    window = now - timedelta(minutes=15 if not registration else 60)
    purpose = 'registration' if registration else 'login'
    fingerprints = [hashlib.sha256(f'{current_app.secret_key}:{purpose}:{x}'.encode()).hexdigest()
                    for x in (f'ip:{request.remote_addr}', f'email:{email}')]
    for fingerprint in fingerprints:
        count = db.session.scalar(db.select(db.func.count()).select_from(AuthAttempt).where(
            AuthAttempt.fingerprint == fingerprint, AuthAttempt.created_at > window))
        if count >= (6 if registration else 15):
            raise EngineError('Too many attempts. Please try again later.')
    for fingerprint in fingerprints:
        db.session.add(AuthAttempt(fingerprint=fingerprint))
    db.session.execute(db.delete(AuthAttempt).where(AuthAttempt.created_at < now - timedelta(days=1)))
    db.session.commit()


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if not settings()['registration_enabled']:
        return render_template('error.html', code=403, message='Registration is disabled. Ask your operator for an account.'), 403
    if request.method == 'POST':
        try:
            email = valid_email(request.form.get('email', ''))
            rate_limit(email, registration=True)
            name = request.form.get('name', '').strip()
            if not 2 <= len(name) <= 80:
                raise EngineError('Your name must be 2–80 characters.')
            password = validate_password(request.form.get('password', ''))
            if password != request.form.get('confirm_password'):
                raise EngineError('Passwords do not match.')
            user = User(email=email, name=name, role='user')
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
            audit('account.created', 'Welcome to SKVM. Your workspace is ready.', user.id)
            db.session.commit()
            session.clear()
            login_user(user)
            session.permanent = True
            flash('Account created. Welcome to your workspace.', 'success')
            return redirect(url_for('dashboard.index'))
        except IntegrityError:
            db.session.rollback()
            flash('Unable to register this email. Try signing in or contact your operator.', 'error')
        except EngineError as exc:
            flash(str(exc), 'error')
    return render_template('register.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        try:
            identifier = request.form.get('email', '').strip().lower()
            email = identifier if identifier == 'admin' else valid_email(identifier)
            rate_limit(email)
            user = db.session.scalar(db.select(User).where(User.email == email))
            password = request.form.get('password', '')[:129]
            correct = user.check_password(password) if user else check_password_hash(DUMMY_HASH, password)
            if not user or not correct or not user.enabled:
                audit('auth.failed', 'Unsuccessful sign-in attempt.', user.id if user else None)
                db.session.commit()
                raise EngineError('Invalid email or password, or account disabled.')
            session.clear()
            login_user(user)
            session.permanent = True
            audit('auth.login', 'Signed in to your workspace.', user.id)
            db.session.commit()
            if user.must_change_password:
                flash('Welcome. Change the initial administrator password in Profile and keep the forwarded port Private.', 'warning')
            next_url = request.args.get('next', '')
            try:
                target = urlsplit(next_url)
            except ValueError:
                next_url, target = '', urlsplit('')
            if target.scheme or target.netloc or not next_url.startswith('/') or next_url.startswith('//') or '\\' in next_url:
                next_url = url_for('dashboard.index')
            return redirect(next_url)
        except EngineError as exc:
            flash(str(exc), 'error')
    return render_template('login.html')


@bp.post('/logout')
@login_required
def logout():
    from services.webssh_access import revoke_browser_sessions
    revoke_browser_sessions()
    audit('auth.logout', 'Signed out.', current_user.id)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('dashboard.starter'))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            if not current_user.check_password(request.form.get('current_password', '')):
                raise EngineError('Current password is incorrect.')
            name = request.form.get('name', '').strip()
            if not 2 <= len(name) <= 80:
                raise EngineError('Name must be 2–80 characters.')
            current_user.name = name
            if request.form.get('new_password'):
                current_user.set_password(validate_password(request.form['new_password']))
                current_user.must_change_password = False
                current_user.session_version += 1
                login_user(current_user._get_current_object())
            audit('profile.updated', 'Profile updated. Password changes revoke other sessions.')
            db.session.commit()
            flash('Profile saved.', 'success')
            return redirect(url_for('auth.profile'))
        except EngineError as exc:
            db.session.rollback()
            flash(str(exc), 'error')
    from services.validation import user_limits
    return render_template('profile.html', limits=user_limits(current_user))


@bp.post('/sessions/revoke')
@login_required
def revoke_sessions():
    if not current_user.check_password(request.form.get('password', '')):
        flash('Enter your password to revoke sessions.', 'error')
    else:
        current_user.session_version += 1
        audit('sessions.revoked', 'All other sessions revoked.')
        db.session.commit()
        login_user(current_user._get_current_object())
        flash('All other sessions have been revoked.', 'success')
    return redirect(url_for('auth.profile'))
