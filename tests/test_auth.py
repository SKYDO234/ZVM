from extensions import db
from models import User
from tests.conftest import csrf_token, signin, post


def test_authentication_required(client):
    assert client.get('/dashboard').status_code == 302
    assert client.get('/api/metrics').status_code == 401
    assert client.get('/admin').status_code == 302


def test_registration_hashes_password_and_never_grants_admin(client):
    password = 'Unique-password-123!'
    response = client.post('/register', data={'csrf_token': csrf_token(client, '/register'), 'name': 'Test Person',
                                           'email': 'new@example.test', 'password': password, 'confirm_password': password})
    assert response.status_code == 302
    user = db.session.scalar(db.select(User).where(User.email == 'new@example.test'))
    assert user and user.check_password(password)
    assert password not in user.password_hash and user.password_hash.startswith('scrypt:')
    assert user.role == 'user'
    assert client.get('/dashboard').status_code == 200
    assert client.get('/admin').status_code == 403


def test_csrf_is_required(client, users):
    assert client.post('/login', data={'email': users[0].email, 'password': 'Test-only-password-123!'}).status_code == 400
    signin(client)
    assert client.post('/logout').status_code == 400


def test_login_logout_and_safe_redirect(client, users):
    token = csrf_token(client)
    response = client.post('/login?next=//evil.example', data={'csrf_token': token, 'email': users[0].email, 'password': 'Test-only-password-123!'})
    assert response.location.endswith('/user')
    assert post(client, '/logout').status_code == 302
    assert client.get('/api/metrics').status_code == 401


def test_admin_authorization_and_rendering(client, users):
    signin(client)
    assert client.get('/admin').status_code == 403
    assert post(client, '/admin/plans', {'name':'Escalate'}).status_code == 403
    post(client, '/logout')
    signin(client, 'operator@example.test')
    response = client.get('/admin')
    assert response.status_code == 200 and b'Operating system image catalog' in response.data


def test_all_pages_are_connected(client, users):
    signin(client)
    for path in ['/user', '/dashboard', '/vps', '/profile', '/settings', '/docs']:
        response = client.get(path)
        assert response.status_code == 200, path
    assert client.get('/vps/create').status_code == 403
    assert client.get('/vps/console').status_code == 404


def test_password_change_invalidates_other_sessions(app, client, users):
    other = app.test_client()
    signin(client); signin(other)
    response = post(client, '/profile', {'name':'Alice Updated', 'current_password':'Test-only-password-123!', 'new_password':'Changed-password-123!'})
    assert response.status_code == 302
    assert client.get('/dashboard').status_code == 200
    assert other.get('/api/metrics').status_code == 401


def test_disabled_user_session_is_revoked(client, users):
    signin(client)
    users[0].enabled = False
    db.session.commit()
    assert client.get('/api/metrics').status_code == 401


def test_registration_limits_are_independent_of_login_attempts(app,client):
    from routes.auth import rate_limit
    from engines import EngineError
    import pytest
    with app.test_request_context('/login'):
        for _ in range(10):rate_limit('login-limit@example.test')
        for _ in range(6):rate_limit('register-limit@example.test',registration=True)
        with pytest.raises(EngineError,match='Too many'):
            rate_limit('register-limit@example.test',registration=True)
        for _ in range(5):rate_limit('login-limit@example.test')
        with pytest.raises(EngineError,match='Too many'):
            rate_limit('login-limit@example.test')
