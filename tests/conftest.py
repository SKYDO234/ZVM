"""Temporary app/DB fixtures only. Integration modules declare real disposable resources."""
import re
import pytest
from skvm import create_app
from extensions import db
from models import User


@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'SECRET_KEY': 'test-only-session-key-not-used-by-live-app',
                      'DATA_DIR': tmp_path / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "test.db"}',
                      'START_WORKER': False, 'TEST_MODE': False, 'SESSION_COOKIE_SECURE': False})
    # A long-lived fixture app context is convenient for DB assertions; clear request-local
    # caches just as real, independent HTTP application contexts do.
    @app.after_request
    def clear_request_caches(response):
        from flask import g
        g.pop('csrf_token', None)
        g.pop('_login_user', None)
        return response
    with app.app_context():
        yield app
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def users(app):
    result = []
    for name, role in [('Alice', 'user'), ('Bob', 'user'), ('Operator', 'admin')]:
        user = User(name=name, email=f'{name.lower()}@example.test', role=role)
        user.set_password('Test-only-password-123!')
        db.session.add(user)
        result.append(user)
    db.session.commit()
    return result


def csrf_token(client, path='/login'):
    result = client.get(path)
    return re.search(rb'name="csrf-token" content="([^"]+)"', result.data)[1].decode()


def signin(client, email='alice@example.test'):
    return client.post('/login', data={'email': email, 'password': 'Test-only-password-123!', 'csrf_token': csrf_token(client)})


def post(client, path, data=None, token_path='/dashboard'):
    return client.post(path, data={'csrf_token': csrf_token(client, token_path), **(data or {})})
