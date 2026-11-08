"""One-time initial login, non-blocking navigation and secure password replacement."""
import pytest
from sqlalchemy import inspect, text
from extensions import db
from models import Audit, Job, Plan, Setting, User, VPS
from services.bootstrap import BOOTSTRAP_MARKER, bootstrap_admin, migrate_user_schema
from skvm import create_app
from tests.conftest import csrf_token, post
from tests.test_html import parsed


def initial_login(client, password='admin123'):
    return client.post('/login', data={'email': 'admin', 'password': password, 'csrf_token': csrf_token(client)})


def test_bootstrap_hashes_password_keeps_reminder_and_seeds_only_once(app):
    assert db.session.scalar(db.select(db.func.count(User.id))) == 0
    assert bootstrap_admin().startswith('created')
    user = db.session.scalar(db.select(User).where(User.email == 'admin'))
    assert user.is_admin and user.must_change_password
    assert user.check_password('admin123')
    assert user.password_hash.startswith('scrypt:') and 'admin123' not in user.password_hash
    original_hash, original_id = user.password_hash, user.id
    assert db.session.get(Setting, BOOTSTRAP_MARKER).value['state'] == 'created'
    assert bootstrap_admin().startswith('already initialized')
    assert user.password_hash == original_hash and user.id == original_id
    assert db.session.scalar(db.select(db.func.count(User.id))) == 1
    assert db.session.scalar(db.select(db.func.count(VPS.id))) == 0
    entry = db.session.scalar(db.select(Audit).where(Audit.action == 'admin.bootstrap'))
    assert entry and 'admin123' not in entry.message


def test_existing_accounts_are_not_changed_or_promoted(app, users):
    originals = [(user.id, user.email, user.password_hash, user.role, user.session_version) for user in users]
    assert bootstrap_admin().startswith('existing accounts preserved')
    assert db.session.scalar(db.select(User).where(User.email == 'admin')) is None
    assert [(user.id, user.email, user.password_hash, user.role, user.session_version) for user in users] == originals
    assert all(not user.must_change_password for user in users)
    assert db.session.get(Setting, BOOTSTRAP_MARKER).value['state'] == 'existing_accounts_preserved'


def test_marker_prevents_recreating_a_deleted_initial_account(app):
    bootstrap_admin()
    user = db.session.scalar(db.select(User).where(User.email == 'admin'))
    for event in db.session.scalars(db.select(Audit).where(Audit.user_id == user.id)):
        event.user_id = None
    db.session.delete(user)
    db.session.commit()
    assert bootstrap_admin().startswith('already initialized')
    assert db.session.scalar(db.select(db.func.count(User.id))) == 0


def test_existing_sqlite_schema_is_migrated_additively(app, users):
    original = [(u.id, u.email, u.password_hash, u.role, u.session_version) for u in users]
    db.session.remove()
    # Reproduce the previous release's schema, not a mock migration result.
    db.session.execute(text('ALTER TABLE "user" DROP COLUMN must_change_password'))
    db.session.commit()
    assert 'must_change_password' not in {c['name'] for c in inspect(db.engine).get_columns('user')}
    migrate_user_schema()
    migrate_user_schema()
    loaded = list(db.session.scalars(db.select(User).order_by(User.id)))
    assert [(u.id, u.email, u.password_hash, u.role, u.session_version) for u in loaded] == original
    assert all(u.must_change_password is False for u in loaded)
    assert bootstrap_admin().startswith('existing accounts preserved')


def test_app_factory_bootstraps_explicitly_and_idempotently(tmp_path):
    options = {'TESTING': True, 'SECRET_KEY': 'test-only-bootstrap-key', 'START_WORKER': False,
               'DATA_DIR': tmp_path / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "bootstrap.db"}',
               'BOOTSTRAP_ADMIN': True}
    for _ in range(2):
        app = create_app(options)
        with app.app_context():
            assert db.session.scalar(db.select(db.func.count(User.id))) == 1
            assert db.session.scalar(db.select(User)).check_password('admin123')
            db.session.remove()
            db.engine.dispose()


@pytest.mark.parametrize('mode', ['TESTING', 'TEST_MODE'])
def test_dotenv_bootstrap_flag_does_not_contaminate_isolated_tests(tmp_path, monkeypatch, mode):
    monkeypatch.setenv('SKVM_BOOTSTRAP_ADMIN', '1')
    app = create_app({mode: True, 'SECRET_KEY': 'test-only-empty-key', 'START_WORKER': False,
                      'DATA_DIR': tmp_path / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "empty.db"}'})
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(User.id))) == 0
        db.session.remove()
        db.engine.dispose()


def test_node_agents_never_receive_a_default_account(tmp_path):
    app = create_app({'NODE_AGENT': True, 'NODE_TOKEN': 'A' * 48, 'BOOTSTRAP_ADMIN': True, 'START_WORKER': False,
                      'DATA_DIR': tmp_path / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "agent.db"}'})
    with app.app_context():
        assert bootstrap_admin() == 'disabled on agents'
        assert db.session.scalar(db.select(db.func.count(User.id))) == 0
        assert db.session.get(Setting, BOOTSTRAP_MARKER) is None
        db.session.remove()
        db.engine.dispose()


def test_initial_login_opens_dashboard_and_shows_nonblocking_reminder(app, client):
    bootstrap_admin()
    root = parsed(client.get('/login'))
    field = next(node for node in root.iter('input') if node.get('name') == 'email')
    assert field.get('type') == 'text' and field.get('autocomplete') == 'username'
    response = initial_login(client)
    assert response.status_code == 302 and response.location.endswith('/dashboard')
    dashboard = parsed(client.get('/dashboard'))
    assert any('data-initial-password-reminder' in node.attrib for node in dashboard.iter('div'))
    profile = parsed(client.get('/profile'))
    new_password = next(node for node in profile.iter('input') if node.get('name') == 'new_password')
    assert new_password.get('required') is None
    assert any(form.get('action') == '/sessions/revoke' for form in profile.iter('form'))


@pytest.mark.parametrize('path', ['/dashboard', '/admin', '/settings', '/vps', '/vps/create', '/user', '/profile', '/docs'])
def test_initial_password_can_navigate_all_panel_routes(app, client, path):
    bootstrap_admin()
    initial_login(client)
    response = client.get(path)
    assert response.status_code == 200
    assert b'data-initial-password-reminder' in response.data


@pytest.mark.parametrize('target,expected', [('/settings', '/settings'), ('/vps', '/vps'),
                                            ('//evil.example', '/dashboard'), ('https://evil.example', '/dashboard')])
def test_initial_admin_respects_only_safe_post_login_destinations(app, client, target, expected):
    bootstrap_admin()
    response = client.post('/login', query_string={'next': target}, data={
        'email': 'admin', 'password': 'admin123', 'csrf_token': csrf_token(client)})
    assert response.status_code == 302 and response.location == expected


def test_initial_password_can_use_api_and_forms_without_fabricating_guests(app, client):
    bootstrap_admin()
    initial_login(client)
    response = client.get('/api/metrics')
    assert response.status_code == 200 and response.json['totals']['count'] == 0
    response = client.get('/api/activity')
    assert response.status_code == 200 and isinstance(response.json, list)
    # Invalid creation reaches real validation instead of bouncing to Profile.
    response = post(client, '/vps/create', {'name': 'invalid-without-engine'}, token_path='/vps/create')
    assert response.status_code == 200 and b'Create' in response.data
    assert db.session.scalar(db.select(db.func.count(VPS.id))) == 0
    assert db.session.scalar(db.select(db.func.count(Job.id))) == 0
    response = post(client, '/admin/plans', {'name': 'Initial admin plan', 'max_instances': '2',
                    'ram_mb': '1024', 'vcpus': '1', 'disk_gb': '16'}, token_path='/admin')
    assert response.status_code == 302 and response.location.endswith('/admin/plans')
    assert db.session.scalar(db.select(Plan).where(Plan.name == 'Initial admin plan')) is not None
    assert client.get('/static/js/app.js').status_code == 200
    assert post(client, '/logout', token_path='/profile').status_code == 302
    assert client.get('/api/metrics').status_code == 401


def test_initial_password_does_not_bypass_csrf(app, client):
    bootstrap_admin()
    initial_login(client)
    assert client.post('/admin/plans', data={'name': 'Must not be saved'}).status_code == 400
    assert db.session.scalar(db.select(Plan).where(Plan.name == 'Must not be saved')) is None


def test_initial_password_flag_does_not_grant_an_ordinary_user_admin_access(app, client, users):
    from tests.conftest import signin
    users[0].must_change_password = True
    db.session.commit()
    signin(client)
    assert client.get('/dashboard').status_code == 200
    assert client.get('/admin').status_code == 403
    assert post(client, '/admin/plans', {'name': 'Escalation'}, token_path='/profile').status_code == 403


def test_profile_can_be_saved_without_changing_password_and_keeps_reminder(app, client):
    bootstrap_admin()
    initial_login(client)
    response = post(client, '/profile', {'name': 'Panel Owner', 'current_password': 'admin123', 'new_password': ''}, token_path='/profile')
    assert response.status_code == 302
    user = db.session.scalar(db.select(User).where(User.email == 'admin'))
    assert user.name == 'Panel Owner' and user.must_change_password and user.check_password('admin123')
    assert b'data-initial-password-reminder' in client.get('/dashboard').data


@pytest.mark.parametrize('current,new', [('admin123', 'Too-short'), ('wrong-password', 'Private-password-2026!')])
def test_password_replacement_requires_current_password_and_strong_replacement(app, client, current, new):
    bootstrap_admin()
    initial_login(client)
    response = post(client, '/profile', {'name': 'Changed', 'current_password': current, 'new_password': new}, token_path='/profile')
    assert response.status_code == 200
    user = db.session.scalar(db.select(User).where(User.email == 'admin'))
    assert user.must_change_password and user.name == 'Administrator' and user.check_password('admin123')
    assert client.get('/api/metrics').status_code == 200


def test_initial_password_can_revoke_other_sessions_without_navigation_lock(app, client):
    bootstrap_admin()
    other = app.test_client()
    initial_login(client)
    initial_login(other)
    response = post(client, '/sessions/revoke', {'password': 'admin123'}, token_path='/profile')
    assert response.status_code == 302
    assert client.get('/dashboard').status_code == 200
    assert other.get('/api/metrics').status_code == 401
    assert db.session.scalar(db.select(User).where(User.email == 'admin')).must_change_password


def test_replacement_removes_reminder_invalidates_old_sessions_and_does_not_reset(app, client):
    bootstrap_admin()
    other = app.test_client()
    initial_login(client)
    initial_login(other)
    assert other.get('/api/metrics').status_code == 200
    password = 'Private-rotated-password-2026!'
    response = post(client, '/profile', {'name': 'Panel Owner', 'current_password': 'admin123', 'new_password': password}, token_path='/profile')
    assert response.status_code == 302
    user = db.session.scalar(db.select(User).where(User.email == 'admin'))
    assert user.is_admin and not user.must_change_password and user.check_password(password)
    assert user.session_version == 2 and not user.check_password('admin123')
    assert client.get('/admin').status_code == 200
    assert b'data-initial-password-reminder' not in client.get('/dashboard').data
    assert client.get('/api/metrics').status_code == 200
    assert other.get('/api/metrics').status_code == 401
    assert bootstrap_admin().startswith('already initialized')
    assert user.check_password(password) and not user.must_change_password
    assert initial_login(other).status_code == 200  # Old known password no longer signs in.
    response = initial_login(other, password)
    assert response.status_code == 302 and response.location.endswith('/dashboard')


@pytest.mark.parametrize('setting,expected', [(None, 1), (False, 0)])
def test_normal_panel_first_start_and_explicit_optout(tmp_path, setting, expected):
    app = create_app({'TESTING': False, 'TEST_MODE': False, 'BOOTSTRAP_ADMIN': setting, 'START_WORKER': False,
                      'DATA_DIR': tmp_path / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "normal.db"}'})
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(User.id))) == expected
        db.session.remove()
        db.engine.dispose()
