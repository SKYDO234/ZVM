#!/usr/bin/env python3
"""SKVM entry point: python skvm.py. No root, systemd, LXC or KVM required."""
import os
import sys
from pathlib import Path

# Makes the documented startup work after install-codespaces.sh creates its venv.
if __name__ == '__main__' and sys.prefix == sys.base_prefix and (Path(__file__).parent / '.venv/bin/python').exists():
    os.execv(str(Path(__file__).parent / '.venv/bin/python'), [str(Path(__file__).parent / '.venv/bin/python'), *sys.argv])
os.umask(0o077)

import argparse
import getpass
import logging
import re
import secrets
from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from config import configuration
from extensions import csrf, db, login
from models import Job, User


def create_app(overrides=None):
    app = Flask(__name__, instance_relative_config=False)
    app.config.update(configuration())
    app.config.update(overrides or {})
    if any(c in str(app.config['DATA_DIR']) for c in (',', '\n', '\r', '\x00')):
        raise RuntimeError('SKVM_DATA_DIR cannot contain QEMU option separators or control characters.')
    for folder in ('vms', 'images', 'logs', 'locks'):
        (Path(app.config['DATA_DIR']) / folder).mkdir(parents=True, exist_ok=True, mode=0o700)
    db.init_app(app)
    login.init_app(app)
    csrf.init_app(app)
    login.session_protection = 'strong'

    @login.user_loader
    def load_user(ident):
        try:
            key, version, tag = ident.split(':')
            user = db.session.get(User, int(key))
            return user if user and user.enabled and user.session_version == int(version) and secrets.compare_digest(user.session_tag(), tag) else None
        except (ValueError, TypeError):
            return None

    @login.unauthorized_handler
    def unauthorized():
        if request.path.startswith('/api/'):
            return jsonify(error='Authentication required.'), 401
        from flask import redirect, url_for
        return redirect(url_for('auth.login', next=request.full_path))

    with app.app_context():
        from services.security import locked
        with locked('schema-initialization'):
            db.create_all()
            from services.image_manager import seed_images
            seed_images()

    if app.config['NODE_AGENT']:
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', app.config.get('NODE_TOKEN') or ''):
            raise RuntimeError('External agents require a random URL-safe ASCII SKVM_NODE_TOKEN of 32–256 characters. No default exists.')
        from routes.node_api import node_api
        app.register_blueprint(node_api)
        csrf.exempt(node_api)  # Bearer-authenticated machine API; never accepts browser cookie authentication.
    else:
        from routes import admin, api, auth, dashboard, vps
        for module in (auth, dashboard, vps, admin, api):
            app.register_blueprint(module.bp)

    @app.context_processor
    def context():
        return {'app_test_mode': app.config['TEST_MODE']}

    @app.template_filter('datetime')
    def format_time(value):
        return value.strftime('%b %d, %Y · %H:%M UTC') if value else 'Not checked'

    @app.errorhandler(CSRFError)
    def csrf_error(exc):
        message = 'Security token missing or expired. Refresh the page and try again.'
        if request.path.startswith(('/api/', '/v1/')):
            return jsonify(error=message), 400
        return render_template('error.html', code=400, message=message), 400

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def http_error(exc):
        code = getattr(exc, 'code', 500)
        messages = {400: 'The request could not be processed.', 401: 'Authentication required.', 403: 'You do not have access to this area.',
                    404: 'This resource does not exist or is not yours.', 413: 'The request is too large.', 500: 'An internal error occurred. Check the server logs.'}
        if request.path.startswith(('/api/', '/v1/')) or app.config['NODE_AGENT']:
            return jsonify(error=messages[code]), code
        return render_template('error.html', code=code, message=messages[code]), code

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self' https://arena.ai https://*.arena.ai https://*.e2b.app https://*.github.dev"
        if not request.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-store'
        if app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    if app.config['START_WORKER'] and not app.config['TEST_MODE']:
        if app.config['NODE_AGENT']:
            from services.node_worker import start_agent_worker
            start_agent_worker(app)
        else:
            from services.provisioning import start_worker
            start_worker(app)
    return app


def cli():
    parser = argparse.ArgumentParser(description='SKVM virtualization control plane')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('init-db')
    admin = sub.add_parser('create-admin')
    admin.add_argument('--email', required=True)
    admin.add_argument('--name', default='Administrator')
    sub.add_parser('check-environment')
    sub.add_parser('verify-images')
    image_cmd = sub.add_parser('configure-image')
    image_cmd.add_argument('--id', required=True)
    image_cmd.add_argument('--url', required=True)
    image_cmd.add_argument('--sha256', default='')
    sub.add_parser('worker')
    resolve = sub.add_parser('resolve-job', help='After manual engine inspection ONLY, release a failed uncertain job reservation.')
    resolve.add_argument('id')
    resolve.add_argument('--confirm-no-resource', action='store_true', required=True)
    args = parser.parse_args()
    app = create_app({'START_WORKER': args.command is None and os.getenv('SKVM_START_WORKER', '1') == '1'})
    with app.app_context():
        if args.command == 'init-db':
            print('SQLite schema and OS catalog initialized. No users or instances were fabricated.')
        elif args.command == 'create-admin':
            from routes.auth import valid_email
            from services.security import validate_password, audit
            from engines import EngineError
            try:
                email = valid_email(args.email)
                if db.session.scalar(db.select(User).where(User.email == email)):
                    raise EngineError('This email already exists. Use a different email; existing accounts are not silently promoted.')
                password = getpass.getpass('Admin password (12+ characters): ')
                validate_password(password)
                if password != getpass.getpass('Confirm password: '):
                    raise EngineError('Passwords do not match.')
                user = User(email=email, name=args.name[:80], role='admin')
                user.set_password(password)
                db.session.add(user)
                db.session.flush()
                audit('admin.created', 'Administrator created through operator CLI.', user.id)
                db.session.commit()
                print(f'Administrator created: {email}. No password is stored in plaintext.')
            except EngineError as exc:
                parser.exit(1, f'{exc}\n')
        elif args.command == 'check-environment':
            import json
            from engines import engine_for
            from services.resource_monitor import host_metrics
            print(json.dumps({'host': host_metrics(), 'qemu': engine_for('qemu').capabilities(), 'docker': engine_for('docker').capabilities()}, indent=2))
        elif args.command == 'configure-image':
            from models import OSImage
            from services.security import settings, validate_url
            from engines import EngineError
            try:
                image = db.session.get(OSImage, args.id)
                if not image:
                    raise EngineError('Unknown OS ID.')
                validate_url(args.url, settings()['image_hosts'])
                if args.sha256 and not re.fullmatch(r'[0-9a-fA-F]{64}', args.sha256):
                    raise EngineError('SHA256 must contain 64 hexadecimal digits.')
                image.qemu_url, image.sha256 = args.url, args.sha256.lower() or None
                image.verification, image.verified_at = 'unverified', None
                db.session.commit()
                print('Image candidate updated. Run verify-images before provisioning.')
            except EngineError as exc:
                parser.exit(1, f'{exc}\n')
        elif args.command == 'verify-images':
            from services.image_manager import ImageManager
            from models import OSImage
            from engines import EngineError
            failed = False
            for image in db.session.scalars(db.select(OSImage)):
                try:
                    ImageManager().verify(image)
                    print(f'{image.name}: verified QCOW2 endpoint')
                except EngineError as exc:
                    failed = True
                    print(f'{image.name}: UNAVAILABLE — {exc}')
            if failed:
                parser.exit(1, 'Some URLs could not be verified. They will not be assumed valid.\n')
        elif args.command == 'worker':
            if app.config['TEST_MODE']:
                parser.exit(1, 'Test mode does not consume or modify the real provisioning queue.\n')
            from services.provisioning import worker_loop
            worker_loop(app)
        elif args.command == 'resolve-job':
            from services.security import audit
            job = db.session.get(Job, args.id)
            if not job or job.status != 'uncertain':
                parser.exit(1, 'Only an uncertain job can be resolved.\n')
            job.status, job.payload, job.message = 'failed', None, 'Operator confirmed manual inspection: no resource remains.'
            audit('job.resolved', f'Operator manually released reservation for job {job.id}.', job.owner_id, job.instance_id)
            db.session.commit()
        else:
            # For production use gunicorn (see README); debug/reloader are intentionally off.
            from werkzeug.serving import run_simple
            run_simple(os.getenv('SKVM_HOST', '0.0.0.0'), int(os.getenv('SKVM_PORT', '5555')), app,
                       use_reloader=False, use_debugger=False, threaded=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    cli()
